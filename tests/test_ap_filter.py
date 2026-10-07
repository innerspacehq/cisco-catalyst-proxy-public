"""Unit tests for AP filtering logic."""

from proxy.ap_filter import APFilter
from proto import telemetry_bis_pb2


class TestAPFilter:
    """Test suite for APFilter class."""

    def test_filtering_disabled_forwards_all(self):
        """When disabled, all messages should be forwarded."""
        filter_obj = APFilter(enabled=False, allow_list=[])
        msg = create_single_ap_message("aa:bb:cc:dd:ee:ff", "wtp-mac")
        assert filter_obj.should_forward(msg) is True

    def test_single_ap_in_allowlist_forwards(self):
        """Single-AP message with AP in allowlist should forward."""
        filter_obj = APFilter(enabled=True, allow_list=["aa:bb:cc:dd:ee:ff"])
        msg = create_single_ap_message("aa:bb:cc:dd:ee:ff", "wtp-mac")
        assert filter_obj.should_forward(msg) is True

    def test_single_ap_not_in_allowlist_drops(self):
        """Single-AP message with AP not in allowlist should drop."""
        filter_obj = APFilter(enabled=True, allow_list=["aa:bb:cc:dd:ee:ff"])
        msg = create_single_ap_message("11:22:33:44:55:66", "wtp-mac")
        assert filter_obj.should_forward(msg) is False

    def test_multi_ap_any_match_forwards(self):
        """Multi-AP message: ANY AP in allowlist should forward (Path 2, 4)."""
        filter_obj = APFilter(enabled=True, allow_list=["aa:bb:cc:dd:ee:ff"])
        msg = create_multi_ap_message([
            "11:22:33:44:55:66",  # Out of scope
            "aa:bb:cc:dd:ee:ff",  # IN SCOPE - should trigger forward
            "77:88:99:aa:bb:cc",  # Out of scope
        ], "lrad-addr")
        assert filter_obj.should_forward(msg) is True  # ANY logic

    def test_multi_ap_no_match_drops(self):
        """Multi-AP message: No APs in allowlist should drop."""
        filter_obj = APFilter(enabled=True, allow_list=["aa:bb:cc:dd:ee:ff"])
        msg = create_multi_ap_message([
            "11:22:33:44:55:66",
            "77:88:99:aa:bb:cc",
        ], "lrad-addr")
        assert filter_obj.should_forward(msg) is False

    def test_case_insensitive_mac_matching(self):
        """MAC comparison should be case-insensitive."""
        filter_obj = APFilter(enabled=True, allow_list=["AA:BB:CC:DD:EE:FF"])
        msg = create_single_ap_message("aa:bb:cc:dd:ee:ff", "wtp-mac")
        assert filter_obj.should_forward(msg) is True

    def test_no_ap_identifiers_drops(self):
        """Message with no AP identifiers should be dropped."""
        filter_obj = APFilter(enabled=True, allow_list=["aa:bb:cc:dd:ee:ff"])
        msg = telemetry_bis_pb2.Telemetry()
        msg.encoding_path = "/some-path"
        assert filter_obj.should_forward(msg) is False

    def test_nested_field_extraction(self):
        """Should extract AP MACs from nested fields (Path 4 pattern)."""
        filter_obj = APFilter(enabled=True, allow_list=["aa:bb:cc:dd:ee:ff"])
        msg = create_nested_ap_message([
            "11:22:33:44:55:66",
            "aa:bb:cc:dd:ee:ff",  # Nested in-scope AP
        ], "lrad-mac-addr")
        assert filter_obj.should_forward(msg) is True

    def test_all_ap_identifier_fields(self):
        """Test extraction works for all known AP identifier field names."""
        filter_obj = APFilter(enabled=True, allow_list=["aa:bb:cc:dd:ee:ff"])

        field_names = [
            'wtp-mac',
            'ap-mac',
            'lrad-addr',
            'lrad-mac-addr',
            'ap-mac-addr',
        ]

        for field_name in field_names:
            msg = create_single_ap_message("aa:bb:cc:dd:ee:ff", field_name)
            assert filter_obj.should_forward(msg) is True, \
                f"Failed to extract AP MAC from field: {field_name}"

    def test_non_mac_string_value_ignored(self):
        """A field named like an AP identifier but holding a non-MAC value is ignored."""
        filter_obj = APFilter(enabled=True, allow_list=["aa:bb:cc:dd:ee:ff"])
        msg = create_single_ap_message("not-a-mac-address", "wtp-mac")
        assert filter_obj.should_forward(msg) is False


class TestAPFilterTracking:
    """Test suite for APFilter's seen/forwarded/dropped tracking and log_summary()."""

    def test_seen_macs_accumulates_across_calls(self):
        """seen_macs should include APs from both forwarded and dropped messages."""
        filter_obj = APFilter(enabled=True, allow_list=["aa:bb:cc:dd:ee:ff"])
        filter_obj.should_forward(create_single_ap_message("aa:bb:cc:dd:ee:ff", "wtp-mac"))
        filter_obj.should_forward(create_single_ap_message("11:22:33:44:55:66", "wtp-mac"))
        assert filter_obj.seen_macs == {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}

    def test_forwarded_and_dropped_counts(self):
        """forwarded_count / dropped_count should track each should_forward() outcome."""
        filter_obj = APFilter(enabled=True, allow_list=["aa:bb:cc:dd:ee:ff"])
        filter_obj.should_forward(create_single_ap_message("aa:bb:cc:dd:ee:ff", "wtp-mac"))
        filter_obj.should_forward(create_single_ap_message("11:22:33:44:55:66", "wtp-mac"))
        filter_obj.should_forward(telemetry_bis_pb2.Telemetry())
        assert filter_obj.forwarded_count == 1
        assert filter_obj.dropped_count == 2

    def test_log_summary_reports_never_seen_allowlist_ap(self, caplog):
        """log_summary() should warn about an allowlisted AP that was never observed."""
        filter_obj = APFilter(enabled=True, allow_list=["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"])
        filter_obj.should_forward(create_single_ap_message("aa:bb:cc:dd:ee:ff", "wtp-mac"))

        with caplog.at_level("INFO"):
            filter_obj.log_summary()

        assert "1 forwarded, 0 dropped" in caplog.text
        assert "Allowlisted APs seen: 1/2" in caplog.text
        assert "11:22:33:44:55:66" in caplog.text

    def test_per_path_stats_tracked_independently(self):
        """Messages on different encoding_paths accumulate separate path_stats."""
        filter_obj = APFilter(enabled=True, allow_list=["aa:bb:cc:dd:ee:ff"])
        msg_a = create_single_ap_message("aa:bb:cc:dd:ee:ff", "wtp-mac")
        msg_a.encoding_path = "/path-a"
        msg_b = create_single_ap_message("11:22:33:44:55:66", "wtp-mac")
        msg_b.encoding_path = "/path-b"

        filter_obj.should_forward(msg_a)
        filter_obj.should_forward(msg_b)

        assert filter_obj.path_stats["/path-a"]["forwarded"] == 1
        assert filter_obj.path_stats["/path-b"]["dropped_out_of_scope"] == 1

    def test_unrecognized_vs_out_of_scope_counted_separately(self, caplog):
        """A message with no AP identifier field is 'unrecognized'; a message
        with an out-of-scope AP MAC is 'out-of-scope' - distinct counters and
        log_summary() only warns on the unrecognized path."""
        filter_obj = APFilter(enabled=True, allow_list=["aa:bb:cc:dd:ee:ff"])

        unrecognized_msg = telemetry_bis_pb2.Telemetry()
        unrecognized_msg.encoding_path = "/unrecognized-path"
        filter_obj.should_forward(unrecognized_msg)

        out_of_scope_msg = create_single_ap_message("11:22:33:44:55:66", "wtp-mac")
        out_of_scope_msg.encoding_path = "/out-of-scope-path"
        filter_obj.should_forward(out_of_scope_msg)

        assert filter_obj.path_stats["/unrecognized-path"]["dropped_unrecognized"] == 1
        assert filter_obj.path_stats["/out-of-scope-path"]["dropped_out_of_scope"] == 1

        with caplog.at_level("INFO"):
            filter_obj.log_summary()

        unrecognized_lines = [
            r for r in caplog.records if "/unrecognized-path" in r.message
        ]
        out_of_scope_lines = [
            r for r in caplog.records if "/out-of-scope-path" in r.message
        ]
        assert unrecognized_lines[0].levelname == "WARNING"
        assert out_of_scope_lines[0].levelname == "INFO"

    def test_alternate_mac_formats_extracted(self):
        """Dotted, hyphenated, and compact MAC notations all extract and match,
        same formats mac_hasher.py already tolerates when hashing."""
        filter_obj = APFilter(enabled=True, allow_list=["aa:bb:cc:dd:ee:ff"])

        for raw_value in ["aabb.ccdd.eeff", "aa-bb-cc-dd-ee-ff", "aabbccddeeff"]:
            msg = create_single_ap_message(raw_value, "wtp-mac")
            assert filter_obj.should_forward(msg) is True, \
                f"Failed to extract AP MAC from format: {raw_value}"

    def test_path_scoped_field_matching_prevents_collision(self):
        """Under a mapped encoding_path, only that path's designated field name
        matches - a different AP-identifier field name on the same path does not."""
        filter_obj = APFilter(enabled=True, allow_list=["aa:bb:cc:dd:ee:ff"])

        # ap-mac-addr is Path 5's field, not Path 3's (ap-mac) - should be
        # ignored under Path 3's mapped encoding_path.
        msg = create_single_ap_message(
            "aa:bb:cc:dd:ee:ff", "ap-mac-addr"
        )
        msg.encoding_path = "Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data/ap-radio-neighbor"
        assert filter_obj.should_forward(msg) is False

        # Same field name, unmapped encoding_path - falls back to the full set.
        msg.encoding_path = "/some-unmapped-path"
        assert filter_obj.should_forward(msg) is True

    def test_out_of_scope_tracking_capped(self):
        """Exceeding the out-of-scope cap stops growing seen_macs further and
        doesn't affect allowlisted-AP tracking."""
        from proxy.ap_filter import OUT_OF_SCOPE_SEEN_CAP

        filter_obj = APFilter(enabled=True, allow_list=["aa:bb:cc:dd:ee:ff"])
        filter_obj.should_forward(create_single_ap_message("aa:bb:cc:dd:ee:ff", "wtp-mac"))

        for i in range(OUT_OF_SCOPE_SEEN_CAP + 5):
            mac = f"11:22:33:{(i >> 16) & 0xFF:02x}:{(i >> 8) & 0xFF:02x}:{i & 0xFF:02x}"
            filter_obj.should_forward(create_single_ap_message(mac, "wtp-mac"))

        assert filter_obj._out_of_scope_capped is True
        out_of_scope_seen = filter_obj.seen_macs - filter_obj.allow_set
        assert len(out_of_scope_seen) == OUT_OF_SCOPE_SEEN_CAP
        assert "aa:bb:cc:dd:ee:ff" in filter_obj.seen_macs

    def test_out_of_scope_tracking_resets_on_log_summary(self):
        """log_summary() resets out-of-scope tracking (count, cap, seen_macs
        entries) each time it runs, but leaves allowlisted-AP tracking intact -
        out-of-scope volume is a per-interval signal, not a lifetime one."""
        from proxy.ap_filter import OUT_OF_SCOPE_SEEN_CAP

        filter_obj = APFilter(enabled=True, allow_list=["aa:bb:cc:dd:ee:ff"])
        filter_obj.should_forward(create_single_ap_message("aa:bb:cc:dd:ee:ff", "wtp-mac"))
        for i in range(OUT_OF_SCOPE_SEEN_CAP + 5):
            mac = f"11:22:33:{(i >> 16) & 0xFF:02x}:{(i >> 8) & 0xFF:02x}:{i & 0xFF:02x}"
            filter_obj.should_forward(create_single_ap_message(mac, "wtp-mac"))

        filter_obj.log_summary()

        assert filter_obj._out_of_scope_capped is False
        assert filter_obj._out_of_scope_count == 0
        assert filter_obj.seen_macs == {"aa:bb:cc:dd:ee:ff"}

        # A fresh interval can track new out-of-scope MACs again after reset.
        filter_obj.should_forward(create_single_ap_message("de:ad:be:ef:00:01", "wtp-mac"))
        assert "de:ad:be:ef:00:01" in filter_obj.seen_macs


# Helper functions to create test protobuf messages

def create_single_ap_message(ap_mac: str, field_name: str) -> telemetry_bis_pb2.Telemetry:
    """Create a telemetry message with one AP MAC."""
    telemetry = telemetry_bis_pb2.Telemetry()
    telemetry.encoding_path = "/test-path/single-ap"

    field = telemetry.data_gpbkv.add()
    field.name = field_name
    field.string_value = ap_mac

    return telemetry


def create_multi_ap_message(ap_macs: list, field_name: str) -> telemetry_bis_pb2.Telemetry:
    """Create a telemetry message with multiple AP MACs (Path 2 pattern)."""
    telemetry = telemetry_bis_pb2.Telemetry()
    telemetry.encoding_path = "/test-path/multi-ap"

    for ap_mac in ap_macs:
        field = telemetry.data_gpbkv.add()
        field.name = field_name
        field.string_value = ap_mac

    return telemetry


def create_nested_ap_message(ap_macs: list, field_name: str) -> telemetry_bis_pb2.Telemetry:
    """Create a telemetry message with nested AP MACs (Path 4 pattern)."""
    telemetry = telemetry_bis_pb2.Telemetry()
    telemetry.encoding_path = "/test-path/nested-ap"

    container = telemetry.data_gpbkv.add()
    container.name = "rogue-client-data"

    for ap_mac in ap_macs:
        nested = container.fields.add()
        nested.name = field_name
        nested.string_value = ap_mac

    return telemetry
