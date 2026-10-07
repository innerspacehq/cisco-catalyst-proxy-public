"""
MAC Address Hashing - Partial Hashing

OUI (first 3 bytes): Preserved in plaintext (lowercase)
NIC (last 3 bytes): Hashed with HMAC-SHA256

Example: AA:BB:CC:DD:EE:FF -> aa:bb:cc:<64-char-hmac-sha256-hash>
"""
import re
import hmac
import hashlib
import logging

logger = logging.getLogger(__name__)

MAX_FIELD_DEPTH = 100

# MAC address regex - matches common Cisco formats with hex boundaries:
# AA:BB:CC:DD:EE:FF, AA-BB-CC-DD-EE-FF, aabb.ccdd.eeff, and aabbccddeeff.
MAC_REGEX = re.compile(
    r'(?<![0-9a-fA-F])'
    r'(?:'
    r'(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}'
    r'|(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}'
    r'|[0-9a-fA-F]{12}'
    r')'
    r'(?![0-9a-fA-F])'
)


class UnsupportedTelemetryEncoding(ValueError):
    """Raised when telemetry contains payloads the proxy cannot safely inspect."""


def partial_hash_mac(mac: str, secret: bytes) -> str:
    """
    Hash a MAC address: OUI preserved, NIC hashed.

    Args:
        mac: MAC address string in colon, hyphen, dotted, or compact hex format
        secret: HMAC secret key (bytes)

    Returns:
        Partially hashed MAC: "aa:bb:cc:<64-char-hash>"
    """
    # Normalize to 12 lowercase hex digits, then regroup with colons.
    hex_digits = re.sub(r'[^0-9a-fA-F]', '', mac).lower()
    if len(hex_digits) != 12:
        logger.warning(f"Invalid MAC address format: {mac}")
        return mac.lower()
    normalized = ':'.join(hex_digits[i:i + 2] for i in range(0, 12, 2))

    # Split into OUI (first 3 bytes) and NIC (last 3 bytes)
    parts = normalized.split(':')
    if len(parts) != 6:
        logger.warning(f"Invalid MAC address format: {mac}")
        return normalized  # Safe fallback; regex enforces 6 parts so this path is unreachable in practice

    oui = parts[:3]  # First 3 bytes (OUI)
    nic = parts[3:]  # Last 3 bytes (NIC)

    # Hash only the NIC portion
    nic_string = ':'.join(nic)
    nic_hash = hmac.new(secret, nic_string.encode('utf-8'), digestmod=hashlib.sha256).hexdigest()

    # Combine: OUI (plaintext) + NIC (hashed)
    return f"{':'.join(oui)}:{nic_hash}"


def hash_string_value(value: str, secret: bytes) -> str:
    """
    Find and hash all MAC addresses in a string.

    Args:
        value: String that may contain MAC addresses
        secret: HMAC secret key

    Returns:
        String with all MACs hashed
    """
    def replace_mac(match):
        return partial_hash_mac(match.group(0), secret)

    return MAC_REGEX.sub(replace_mac, value)


def _hash_string_with_count(value: str, secret: bytes) -> tuple:
    """
    Hash all MACs in a string and return (hashed_string, mac_count).

    Internal helper used by hash_telemetry_field to track how many MACs
    were actually replaced.
    """
    count = 0

    def replace_mac(match):
        nonlocal count
        count += 1
        return partial_hash_mac(match.group(0), secret)

    return MAC_REGEX.sub(replace_mac, value), count


def hash_telemetry_field(field, secret: bytes, depth: int = 0) -> int:
    """
    Recursively hash all MAC addresses in a TelemetryField.

    Modifies the field in-place.

    Args:
        field: TelemetryField protobuf message
        secret: HMAC secret key

    Returns:
        Number of MAC addresses hashed in this field and all nested fields
    """
    if depth > MAX_FIELD_DEPTH:
        raise UnsupportedTelemetryEncoding(
            f"Telemetry field nesting exceeds maximum depth of {MAX_FIELD_DEPTH}"
        )

    mac_count = 0

    # Check if this field has a string value
    if field.HasField('string_value'):
        original = field.string_value
        hashed, count = _hash_string_with_count(original, secret)
        if original != hashed:
            field.string_value = hashed
            logger.debug(f"Hashed {count} MAC(s) in field '{field.name}'")
        mac_count += count

    # Hash text-like byte fields without attempting to parse arbitrary binary
    # payloads. Compact GPB is handled separately and rejected fail-closed.
    if field.HasField('bytes_value'):
        try:
            original = field.bytes_value.decode('utf-8')
        except UnicodeDecodeError:
            original = None

        if original is not None:
            hashed, count = _hash_string_with_count(original, secret)
            if original != hashed:
                field.bytes_value = hashed.encode('utf-8')
                logger.debug(f"Hashed {count} MAC(s) in byte field '{field.name}'")
            mac_count += count

    # Recursively process nested fields
    for nested_field in field.fields:
        mac_count += hash_telemetry_field(nested_field, secret, depth + 1)

    return mac_count


def hash_telemetry_message(telemetry_pb, secret: bytes) -> int:
    """
    Hash all MAC addresses in a Telemetry protobuf message.

    Modifies the message in-place.

    Args:
        telemetry_pb: Telemetry protobuf message
        secret: HMAC secret key

    Returns:
        Total number of MAC addresses hashed across all fields
    """
    mac_count = 0

    if telemetry_pb.HasField('data_gpb') and telemetry_pb.data_gpb.row:
        raise UnsupportedTelemetryEncoding(
            "Compact GPB telemetry is not supported by this reference proxy. "
            "Configure Cisco MDT subscriptions for self-describing GPBKV encoding."
        )

    for field in telemetry_pb.data_gpbkv:
        mac_count += hash_telemetry_field(field, secret)

    return mac_count


class MACHasher:
    """MAC address hasher: OUI preserved, NIC hashed."""

    def __init__(self, secret: bytes):
        """
        Initialize hasher with HMAC secret.

        Args:
            secret: HMAC secret key (bytes, minimum 32 bytes for 256-bit security)

        Raises:
            ValueError: If secret is less than 32 bytes
        """
        if len(secret) < 32:
            raise ValueError(
                "HMAC secret must be at least 32 bytes (256 bits) for secure hashing"
            )

        self.secret = secret
        logger.info("MACHasher initialized (OUI preserved, NIC hashed)")

    def hash_message(self, telemetry_pb) -> int:
        """
        Hash all MACs in a telemetry message.

        Args:
            telemetry_pb: Telemetry protobuf message

        Returns:
            Number of MAC addresses hashed in this message
        """
        return hash_telemetry_message(telemetry_pb, self.secret)
