"""AP filtering (ANY policy): forwards a message if any AP MAC in it is in
the allowlist, drops it otherwise. Reads raw MACs before hashing runs."""
import logging
import re
from collections import defaultdict
from typing import Optional, Set

from proto import telemetry_bis_pb2

logger = logging.getLogger(__name__)

# Field names carrying AP MAC addresses: wtp-mac (Path 1), ap-mac (Path 3),
# lrad-addr (Path 2), lrad-mac-addr (Path 4), ap-mac-addr (Path 5).
AP_IDENTIFIER_FIELDS = {
    'wtp-mac', 'ap-mac', 'lrad-addr', 'lrad-mac-addr', 'ap-mac-addr',
}

# Real encoding_path -> that path's single expected identifier field, so a
# same-named field on an unrelated path can't be mistaken for an AP
# identifier. Unmapped/future paths fall back to AP_IDENTIFIER_FIELDS.
PATH_IDENTIFIER_FIELDS = {
    "Cisco-IOS-XE-wireless-rrm-oper:rrm-oper-data/ap-auto-rf-dot11-data": {'wtp-mac'},
    "Cisco-IOS-XE-wireless-location-oper:location-oper-data/location-rssi-measurements": {'lrad-addr'},
    "Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data/ap-radio-neighbor": {'ap-mac'},
    "Cisco-IOS-XE-wireless-rogue-oper:rogue-oper-data/rogue-client-data": {'lrad-mac-addr'},
    "Cisco-IOS-XE-wireless-client-oper:client-oper-data/common-oper-data": {'ap-mac-addr'},
}

# Cap on distinct out-of-scope MACs tracked per reporting interval (resets in
# log_summary()), so a busy network's rogue/client MAC churn can't grow it
# unboundedly within one interval. Allowlisted-AP tracking (the actionable,
# lifetime signal) is unaffected - it's bounded by allow_set already.
OUT_OF_SCOPE_SEEN_CAP = 10_000


def _normalize_mac(value: str) -> Optional[str]:
    """Reduce a value to colon-lowercase MAC form if it's MAC-shaped, accepting
    colon, hyphen, dotted, and compact notations - the same formats
    mac_hasher.py already tolerates when hashing. None if not MAC-shaped."""
    hex_digits = re.sub(r'[^0-9A-Fa-f]', '', value).lower()
    if len(hex_digits) != 12:
        return None
    return ':'.join(hex_digits[i:i + 2] for i in range(0, 12, 2))


class APFilter:
    """Filters telemetry messages based on an AP MAC address allowlist."""

    def __init__(self, enabled: bool, allow_list: list):
        self.enabled = enabled
        self.allow_set = {mac.lower() for mac in allow_list}
        self.seen_macs: Set[str] = set()
        self.forwarded_count = 0
        self.dropped_count = 0
        self.path_stats = defaultdict(lambda: {
            'forwarded': 0, 'dropped_unrecognized': 0, 'dropped_out_of_scope': 0,
        })
        self._out_of_scope_count = 0
        self._out_of_scope_capped = False

    def should_forward(self, telemetry_msg: telemetry_bis_pb2.Telemetry) -> bool:
        """True to forward (and later hash) the message, False to drop it."""
        if not self.enabled:
            return True

        path = telemetry_msg.encoding_path or 'unknown'
        ap_macs = self._extract_ap_identifiers(telemetry_msg)
        self._track_seen(ap_macs)

        if not ap_macs:
            self.dropped_count += 1
            self.path_stats[path]['dropped_unrecognized'] += 1
            return False  # no known AP identifier field found - can't verify scope

        if not (ap_macs & self.allow_set):
            self.dropped_count += 1
            self.path_stats[path]['dropped_out_of_scope'] += 1
            return False  # found AP(s), none in scope

        self.forwarded_count += 1
        self.path_stats[path]['forwarded'] += 1
        return True

    def _track_seen(self, ap_macs: Set[str]):
        """Update seen_macs, capping growth of the out-of-scope portion within
        the current reporting interval (log_summary() resets it) -
        allowlisted-AP tracking stays exact and uncapped for the process's
        lifetime."""
        self.seen_macs |= (ap_macs & self.allow_set)

        if self._out_of_scope_capped:
            return

        new_out_of_scope = (ap_macs - self.allow_set) - self.seen_macs
        if not new_out_of_scope:
            return

        self.seen_macs |= new_out_of_scope
        self._out_of_scope_count += len(new_out_of_scope)

        if self._out_of_scope_count >= OUT_OF_SCOPE_SEEN_CAP:
            self._out_of_scope_capped = True
            logger.warning(
                f"Out-of-scope AP tracking capped at {OUT_OF_SCOPE_SEEN_CAP} distinct "
                "MACs; further out-of-scope MACs won't be individually tracked."
            )

    def log_summary(self):
        """Log forward/drop counts (aggregate and per-path, lifetime totals)
        and allowlist AP coverage (lifetime). Out-of-scope AP tracking is
        reset after each call - see _track_seen()."""
        total = self.forwarded_count + self.dropped_count
        rate = (self.forwarded_count / total * 100) if total else 0.0
        logger.info(
            f"AP filtering summary: {self.forwarded_count} forwarded, "
            f"{self.dropped_count} dropped ({rate:.1f}% forward rate)"
        )

        for path in sorted(self.path_stats):
            counts = self.path_stats[path]
            p_total = counts['forwarded'] + counts['dropped_unrecognized'] + counts['dropped_out_of_scope']
            p_rate = (counts['forwarded'] / p_total * 100) if p_total else 0.0
            line = (
                f"  {path}: {counts['forwarded']} forwarded, "
                f"{counts['dropped_unrecognized']} dropped (unrecognized), "
                f"{counts['dropped_out_of_scope']} dropped (out-of-scope) "
                f"({p_rate:.1f}% forward rate)"
            )
            # Unrecognized drops mean no known AP field was found on this path at
            # all - likely a field rename or a never-mapped path.
            if counts['dropped_unrecognized']:
                logger.warning(line)
            else:
                logger.info(line)

        seen_allowed = self.seen_macs & self.allow_set
        unseen_allowed = self.allow_set - self.seen_macs
        out_of_scope_seen = self.seen_macs - self.allow_set

        logger.info(f"Allowlisted APs seen: {len(seen_allowed)}/{len(self.allow_set)}")
        if unseen_allowed:
            logger.warning(f"Allowlisted APs NEVER seen: {sorted(unseen_allowed)}")
        if out_of_scope_seen or self._out_of_scope_capped:
            suffix = "+ (capped)" if self._out_of_scope_capped else ""
            logger.info(f"Out-of-scope APs seen since last summary: {len(out_of_scope_seen)}{suffix}")

        # Out-of-scope tracking is per-interval, not a lifetime total like the
        # counters above - busy deployments can see unbounded distinct
        # out-of-scope MACs over a process's lifetime, so this resets here
        # rather than being capped forever. Allowlisted-AP tracking (kept via
        # the intersection below) is unaffected.
        self.seen_macs &= self.allow_set
        self._out_of_scope_count = 0
        self._out_of_scope_capped = False

    def _extract_ap_identifiers(self, telemetry_msg: telemetry_bis_pb2.Telemetry) -> Set[str]:
        """Recursively collect AP MACs from the TelemetryField tree, scoped to
        the field(s) expected for this message's encoding_path when known."""
        allowed_fields = PATH_IDENTIFIER_FIELDS.get(telemetry_msg.encoding_path, AP_IDENTIFIER_FIELDS)
        ap_macs = set()
        for field in telemetry_msg.data_gpbkv:
            self._extract_from_field(field, ap_macs, allowed_fields)
        return ap_macs

    def _extract_from_field(self, field, ap_macs: Set[str], allowed_fields: Set[str]):
        if field.name in allowed_fields and field.HasField('string_value'):
            normalized = _normalize_mac(field.string_value)
            if normalized:
                ap_macs.add(normalized)

        for child in field.fields:
            self._extract_from_field(child, ap_macs, allowed_fields)
