"""
Unit tests for MAC address hashing.
"""
import pytest
import hmac
import hashlib

from proxy.mac_hasher import (
    MAX_FIELD_DEPTH,
    UnsupportedTelemetryEncoding,
    hash_telemetry_message,
    partial_hash_mac,
    hash_string_value,
    MAC_REGEX
)
from proto import telemetry_bis_pb2


class TestMACRegex:
    """Test MAC address regex pattern."""
    
    def test_matches_colon_separator(self):
        """Should match MAC with colon separator."""
        mac = "AA:BB:CC:DD:EE:FF"
        assert MAC_REGEX.search(mac) is not None
    
    def test_matches_hyphen_separator(self):
        """Should match MAC with hyphen separator."""
        mac = "AA-BB-CC-DD-EE-FF"
        assert MAC_REGEX.search(mac) is not None

    def test_matches_cisco_dotted_separator(self):
        """Should match Cisco dotted MAC notation."""
        mac = "aabb.ccdd.eeff"
        assert MAC_REGEX.search(mac) is not None

    def test_matches_no_separator(self):
        """Should match compact hex MAC notation."""
        mac = "aabbccddeeff"
        assert MAC_REGEX.search(mac) is not None
    
    def test_matches_lowercase(self):
        """Should match lowercase MAC."""
        mac = "aa:bb:cc:dd:ee:ff"
        assert MAC_REGEX.search(mac) is not None
    
    def test_matches_mixed_case(self):
        """Should match mixed case MAC."""
        mac = "Aa:Bb:Cc:Dd:Ee:Ff"
        assert MAC_REGEX.search(mac) is not None
    
    def test_no_match_invalid(self):
        """Should not match invalid MAC."""
        invalid = "not-a-mac"
        assert MAC_REGEX.search(invalid) is None

    def test_no_match_embedded_in_long_hex_blob(self):
        """Should not match a MAC-shaped substring inside a larger hex value."""
        value = "deadAA:BB:CC:DD:EE:FFbeef"
        assert MAC_REGEX.search(value) is None


class TestPartialHashMAC:
    """Test partial MAC hashing."""
    
    @pytest.fixture
    def secret(self):
        """Test secret key."""
        return b'test_secret_key_12345'
    
    def test_preserves_oui_lowercase(self, secret):
        """OUI should be preserved in lowercase."""
        mac = "AA:BB:CC:DD:EE:FF"
        result = partial_hash_mac(mac, secret)
        
        # First 3 bytes should be lowercase OUI
        assert result.startswith("aa:bb:cc:")
    
    def test_hashes_nic_portion(self, secret):
        """NIC portion should be hashed."""
        mac = "AA:BB:CC:DD:EE:FF"
        result = partial_hash_mac(mac, secret)
        
        # Should have OUI + hash
        parts = result.split(':')
        assert len(parts) == 4  # oui1:oui2:oui3:hash
        
        # Hash should be 64 hex characters (SHA256)
        hash_part = parts[3]
        assert len(hash_part) == 64
        assert all(c in '0123456789abcdef' for c in hash_part)
    
    def test_deterministic(self, secret):
        """Same MAC should produce same hash."""
        mac = "AA:BB:CC:DD:EE:FF"
        result1 = partial_hash_mac(mac, secret)
        result2 = partial_hash_mac(mac, secret)
        
        assert result1 == result2
    
    def test_different_secret_different_hash(self):
        """Different secret should produce different hash."""
        mac = "AA:BB:CC:DD:EE:FF"
        secret1 = b'secret1'
        secret2 = b'secret2'
        
        result1 = partial_hash_mac(mac, secret1)
        result2 = partial_hash_mac(mac, secret2)
        
        # OUI should be same
        assert result1[:8] == result2[:8]  # "aa:bb:cc"
        
        # Hash should be different
        assert result1[9:] != result2[9:]
    
    def test_different_nic_different_hash(self, secret):
        """Different NIC should produce different hash."""
        mac1 = "AA:BB:CC:DD:EE:FF"
        mac2 = "AA:BB:CC:11:22:33"
        
        result1 = partial_hash_mac(mac1, secret)
        result2 = partial_hash_mac(mac2, secret)
        
        # OUI should be same
        assert result1[:8] == result2[:8]
        
        # Hash should be different
        assert result1[9:] != result2[9:]
    
    def test_same_nic_same_hash(self, secret):
        """Same NIC (different OUI) should produce same hash."""
        mac1 = "AA:BB:CC:DD:EE:FF"
        mac2 = "11:22:33:DD:EE:FF"
        
        result1 = partial_hash_mac(mac1, secret)
        result2 = partial_hash_mac(mac2, secret)
        
        # OUI should be different
        assert result1[:8] != result2[:8]
        
        # Hash should be same (same NIC)
        assert result1[9:] == result2[9:]
    
    def test_handles_hyphen_separator(self, secret):
        """Should handle hyphen separator."""
        mac = "AA-BB-CC-DD-EE-FF"
        result = partial_hash_mac(mac, secret)
        
        # Should convert to colon
        assert result.startswith("aa:bb:cc:")

    def test_handles_cisco_dotted_separator(self, secret):
        """Should handle Cisco dotted notation."""
        mac = "aabb.ccdd.eeff"
        result = partial_hash_mac(mac, secret)

        assert result.startswith("aa:bb:cc:")
        assert "dd:ee:ff" not in result

    def test_handles_no_separator(self, secret):
        """Should handle compact hex notation."""
        mac = "aabbccddeeff"
        result = partial_hash_mac(mac, secret)

        assert result.startswith("aa:bb:cc:")
        assert "ddeeff" not in result
    
    def test_normalizes_to_lowercase(self, secret):
        """Should normalize to lowercase."""
        mac = "AA:BB:CC:DD:EE:FF"
        result = partial_hash_mac(mac, secret)
        
        # OUI should be lowercase
        assert result[:8] == "aa:bb:cc"


class TestHashStringValue:
    """Test hashing MACs in string values."""
    
    @pytest.fixture
    def secret(self):
        """Test secret key."""
        return b'test_secret'
    
    def test_hashes_single_mac(self, secret):
        """Should hash a single MAC in string."""
        text = "Client MAC: AA:BB:CC:DD:EE:FF connected"
        result = hash_string_value(text, secret)
        
        # MAC should be hashed
        assert "AA:BB:CC:DD:EE:FF" not in result
        assert "aa:bb:cc:" in result
    
    def test_hashes_multiple_macs(self, secret):
        """Should hash multiple MACs in string."""
        text = "Client AA:BB:CC:DD:EE:FF on AP 1122.3344.5566"
        result = hash_string_value(text, secret)
        
        # Both MACs should be hashed
        assert "AA:BB:CC:DD:EE:FF" not in result
        assert "1122.3344.5566" not in result
        assert "aa:bb:cc:" in result
        assert "11:22:33:" in result
    
    def test_preserves_non_mac_text(self, secret):
        """Should preserve non-MAC text."""
        text = "Client AA:BB:CC:DD:EE:FF on interface eth0"
        result = hash_string_value(text, secret)
        
        # Non-MAC text should be preserved
        assert "Client" in result
        assert "on interface eth0" in result
    
    def test_no_macs_unchanged(self, secret):
        """String with no MACs should be unchanged."""
        text = "No MAC addresses here"
        result = hash_string_value(text, secret)
        
        assert result == text


class TestPartialHashProperties:
    """Test that partial-hashing properties hold."""
    
    @pytest.fixture
    def secret(self):
        """Test secret key."""
        return b'production_secret_key'
    
    def test_oui_visible(self, secret):
        """OUI (manufacturer) should be visible."""
        # Cisco OUI
        mac = "00:1A:A1:DD:EE:FF"
        result = partial_hash_mac(mac, secret)
        
        # Cisco OUI should be preserved
        assert result.startswith("00:1a:a1:")
    
    def test_nic_protected(self, secret):
        """NIC (device-specific) should be protected."""
        mac = "AA:BB:CC:DD:EE:FF"
        result = partial_hash_mac(mac, secret)
        
        # Original NIC should not appear
        assert "dd:ee:ff" not in result
        assert "DD:EE:FF" not in result


class TestTelemetryHashing:
    """Test protobuf telemetry hashing behavior."""

    @pytest.fixture
    def secret(self):
        """Test secret key."""
        return b'production_secret_key'

    def test_hashes_string_and_byte_values(self, secret):
        """Should hash MACs in GPBKV string and UTF-8 byte fields."""
        telemetry = telemetry_bis_pb2.Telemetry()
        string_field = telemetry.data_gpbkv.add()
        string_field.name = "client"
        string_field.string_value = "client=aabb.ccdd.eeff"

        byte_field = telemetry.data_gpbkv.add()
        byte_field.name = "neighbor"
        byte_field.bytes_value = b"neighbor=AA-BB-CC-11-22-33"

        count = hash_telemetry_message(telemetry, secret)

        assert count == 2
        assert "aabb.ccdd.eeff" not in string_field.string_value
        assert b"AA-BB-CC-11-22-33" not in byte_field.bytes_value
        assert string_field.string_value.startswith("client=aa:bb:cc:")
        assert byte_field.bytes_value.startswith(b"neighbor=aa:bb:cc:")

    def test_rejects_compact_gpb(self, secret):
        """Should fail closed for compact GPB payloads that cannot be inspected."""
        telemetry = telemetry_bis_pb2.Telemetry()
        row = telemetry.data_gpb.row.add()
        row.keys = b"raw key bytes"
        row.content = b"raw content with AA:BB:CC:DD:EE:FF"

        with pytest.raises(UnsupportedTelemetryEncoding):
            hash_telemetry_message(telemetry, secret)

    def test_rejects_excessive_field_depth(self, secret):
        """Should fail closed before recursive hashing can exhaust the stack."""
        telemetry = telemetry_bis_pb2.Telemetry()
        field = telemetry.data_gpbkv.add()
        field.name = "root"
        for depth in range(MAX_FIELD_DEPTH + 2):
            field = field.fields.add()
            field.name = f"nested-{depth}"

        with pytest.raises(UnsupportedTelemetryEncoding):
            hash_telemetry_message(telemetry, secret)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
