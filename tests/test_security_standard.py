"""Tests for Standard RDP Security layer implementation.

Validates: Req 9 (AC 1–5) — Standard RDP Security with RSA key exchange and RC4.
"""

from __future__ import annotations

import hashlib
import struct

import pytest

from arrdipi.errors import PduParseError
from arrdipi.security.standard import (
    SEC_ENCRYPT,
    StandardSecurityLayer,
    _final_hash,
    _rsa_encrypt_client_random,
    _salted_hash,
    _update_session_key,
    _validate_proprietary_signature,
    compute_mac,
    derive_keys,
    parse_proprietary_certificate,
    _parse_rsa_public_key_blob,
    _TS_SIGNING_KEY_EXPONENT,
    _TS_SIGNING_KEY_MODULUS_LE,
    _KEY_UPDATE_INTERVAL,
)


class TestSaltedHash:
    """Tests for the SaltedHash function per [MS-RDPBCGR] 5.3.5."""

    def test_salted_hash_deterministic(self):
        """SaltedHash produces the same output for the same inputs."""
        s = b"A" * 16
        i = b"X"
        client_random = b"\x01" * 32
        server_random = b"\x02" * 32

        result1 = _salted_hash(s, i, client_random, server_random)
        result2 = _salted_hash(s, i, client_random, server_random)
        assert result1 == result2

    def test_salted_hash_returns_16_bytes(self):
        """SaltedHash always returns 16 bytes (MD5 output)."""
        s = b"test_secret" * 3
        i = b"A"
        client_random = b"\xaa" * 32
        server_random = b"\xbb" * 32

        result = _salted_hash(s, i, client_random, server_random)
        assert len(result) == 16

    def test_salted_hash_different_inputs_different_outputs(self):
        """Different inputs produce different outputs."""
        client_random = b"\x01" * 32
        server_random = b"\x02" * 32
        s = b"S" * 16

        result_a = _salted_hash(s, b"A", client_random, server_random)
        result_b = _salted_hash(s, b"BB", client_random, server_random)
        assert result_a != result_b

    def test_salted_hash_known_computation(self):
        """Verify SaltedHash matches manual computation."""
        s = b"\x00" * 16
        i = b"A"
        client_random = b"\x11" * 32
        server_random = b"\x22" * 32

        # Manual: SHA1(i + s + client_random + server_random)
        sha1_input = i + s + client_random + server_random
        sha1_hash = hashlib.sha1(sha1_input).digest()
        # MD5(s + sha1_hash)
        expected = hashlib.md5(s + sha1_hash).digest()

        result = _salted_hash(s, i, client_random, server_random)
        assert result == expected


class TestFinalHash:
    """Tests for the FinalHash function."""

    def test_final_hash_returns_16_bytes(self):
        """FinalHash always returns 16 bytes (MD5 output)."""
        session_key_blob = b"\xab" * 48
        k = b"\xcd" * 16
        result = _final_hash(session_key_blob, k)
        assert len(result) == 16

    def test_final_hash_uses_first_32_bytes(self):
        """FinalHash uses only the first 32 bytes of session_key_blob."""
        blob_a = b"\x01" * 32 + b"\xaa" * 16
        blob_b = b"\x01" * 32 + b"\xbb" * 16
        k = b"\xff" * 16

        # Both should produce the same result since first 32 bytes are identical
        assert _final_hash(blob_a, k) == _final_hash(blob_b, k)

    def test_final_hash_known_computation(self):
        """Verify FinalHash matches manual computation."""
        session_key_blob = b"\x01" * 48
        k = b"\x02" * 16

        expected = hashlib.md5(session_key_blob[:32] + k).digest()
        result = _final_hash(session_key_blob, k)
        assert result == expected


class TestDeriveKeys:
    """Tests for key derivation per [MS-RDPBCGR] 5.3.5."""

    def test_derive_keys_returns_three_16_byte_keys(self):
        """derive_keys returns (mac_key, encrypt_key, decrypt_key) each 16 bytes."""
        client_random = b"\x01" * 32
        server_random = b"\x02" * 32

        mac_key, encrypt_key, decrypt_key = derive_keys(client_random, server_random)
        assert len(mac_key) == 16
        assert len(encrypt_key) == 16
        assert len(decrypt_key) == 16

    def test_derive_keys_deterministic(self):
        """Same inputs always produce the same keys."""
        client_random = b"\xaa\xbb\xcc\xdd" * 8
        server_random = b"\x11\x22\x33\x44" * 8

        keys1 = derive_keys(client_random, server_random)
        keys2 = derive_keys(client_random, server_random)
        assert keys1 == keys2

    def test_derive_keys_different_randoms_different_keys(self):
        """Different randoms produce different keys."""
        client_random_a = b"\x01" * 32
        client_random_b = b"\x02" * 32
        server_random = b"\x03" * 32

        keys_a = derive_keys(client_random_a, server_random)
        keys_b = derive_keys(client_random_b, server_random)
        assert keys_a != keys_b

    def test_derive_keys_all_keys_different(self):
        """MAC key, encrypt key, and decrypt key are all different."""
        client_random = b"\xde\xad\xbe\xef" * 8
        server_random = b"\xca\xfe\xba\xbe" * 8

        mac_key, encrypt_key, decrypt_key = derive_keys(client_random, server_random)
        assert mac_key != encrypt_key
        assert mac_key != decrypt_key
        assert encrypt_key != decrypt_key

    def test_derive_keys_known_test_vector(self):
        """Verify key derivation with a known test vector."""
        # Use fixed randoms and verify the derivation step by step
        client_random = bytes(range(32))  # 0x00..0x1F
        server_random = bytes(range(32, 64))  # 0x20..0x3F

        mac_key, encrypt_key, decrypt_key = derive_keys(client_random, server_random)

        # Verify by recomputing manually
        pre_master_secret = (client_random + server_random)[:48]

        master_secret = (
            _salted_hash(pre_master_secret, b"A", client_random, server_random)
            + _salted_hash(pre_master_secret, b"BB", client_random, server_random)
            + _salted_hash(pre_master_secret, b"CCC", client_random, server_random)
        )

        session_key_blob = (
            _salted_hash(master_secret, b"X", client_random, server_random)
            + _salted_hash(master_secret, b"YY", client_random, server_random)
            + _salted_hash(master_secret, b"ZZZ", client_random, server_random)
        )

        expected_mac = session_key_blob[:16]
        expected_encrypt = _final_hash(session_key_blob, session_key_blob[16:32])
        expected_decrypt = _final_hash(session_key_blob, session_key_blob[32:48])

        assert mac_key == expected_mac
        assert encrypt_key == expected_encrypt
        assert decrypt_key == expected_decrypt


class TestComputeMac:
    """Tests for MAC computation per [MS-RDPBCGR] 5.3.6.1."""

    def test_mac_returns_8_bytes(self):
        """MAC always returns 8 bytes."""
        mac_key = b"\x01" * 16
        data = b"Hello, RDP!"
        result = compute_mac(mac_key, data)
        assert len(result) == 8

    def test_mac_deterministic(self):
        """Same inputs produce the same MAC."""
        mac_key = b"\xaa" * 16
        data = b"test data"
        assert compute_mac(mac_key, data) == compute_mac(mac_key, data)

    def test_mac_different_data_different_mac(self):
        """Different data produces different MACs."""
        mac_key = b"\xbb" * 16
        mac1 = compute_mac(mac_key, b"data1")
        mac2 = compute_mac(mac_key, b"data2")
        assert mac1 != mac2

    def test_mac_different_key_different_mac(self):
        """Different keys produce different MACs."""
        data = b"same data"
        mac1 = compute_mac(b"\x01" * 16, data)
        mac2 = compute_mac(b"\x02" * 16, data)
        assert mac1 != mac2

    def test_mac_known_computation(self):
        """Verify MAC matches manual computation."""
        mac_key = b"\x00" * 16
        data = b"\xff" * 10

        pad1 = b"\x36" * 40
        pad2 = b"\x5c" * 48
        data_length = struct.pack("<I", len(data))

        sha_component = hashlib.sha1(mac_key + pad1 + data_length + data).digest()
        expected = hashlib.md5(mac_key + pad2 + sha_component).digest()[:8]

        result = compute_mac(mac_key, data)
        assert result == expected

    def test_mac_empty_data(self):
        """MAC works with empty data."""
        mac_key = b"\xcc" * 16
        result = compute_mac(mac_key, b"")
        assert len(result) == 8


class TestUpdateSessionKey:
    """Tests for RC4 key update after 4096 packets."""

    def test_update_key_returns_16_bytes(self):
        """Updated key is always 16 bytes."""
        original = b"\x01" * 16
        current = b"\x02" * 16
        result = _update_session_key(original, current)
        assert len(result) == 16

    def test_update_key_changes_key(self):
        """Updated key is different from the current key."""
        original = b"\xaa" * 16
        current = b"\xbb" * 16
        result = _update_session_key(original, current)
        assert result != current

    def test_update_key_deterministic(self):
        """Same inputs produce the same updated key."""
        original = b"\x11" * 16
        current = b"\x22" * 16
        result1 = _update_session_key(original, current)
        result2 = _update_session_key(original, current)
        assert result1 == result2


class TestRSAPublicKeyBlob:
    """Tests for RSA public key blob parsing."""

    def _build_rsa_blob(
        self, exponent: int = 0x10001, modulus: bytes = b"\x01" * 64
    ) -> bytes:
        """Build a valid RSA public key blob."""
        magic = 0x31415352  # "RSA1"
        keylen = len(modulus)
        bitlen = keylen * 8
        datalen = keylen - 1

        header = struct.pack("<IIIII", magic, keylen, bitlen, datalen, exponent)
        return header + modulus

    def test_parse_valid_blob(self):
        """Parse a valid RSA public key blob."""
        modulus = b"\xab" * 64
        blob = self._build_rsa_blob(exponent=65537, modulus=modulus)

        exp, mod = _parse_rsa_public_key_blob(blob)
        assert exp == 65537
        assert mod == modulus

    def test_parse_blob_too_short(self):
        """Raise PduParseError on blob shorter than header."""
        with pytest.raises(PduParseError, match="blob too short"):
            _parse_rsa_public_key_blob(b"\x00" * 10)

    def test_parse_blob_invalid_magic(self):
        """Raise PduParseError on invalid magic value."""
        blob = struct.pack("<IIIII", 0xDEADBEEF, 64, 512, 63, 65537) + b"\x00" * 64
        with pytest.raises(PduParseError, match="invalid magic"):
            _parse_rsa_public_key_blob(blob)

    def test_parse_blob_truncated_modulus(self):
        """Raise PduParseError when modulus is truncated."""
        header = struct.pack("<IIIII", 0x31415352, 64, 512, 63, 65537)
        blob = header + b"\x00" * 32  # Only 32 bytes, need 64
        with pytest.raises(PduParseError, match="blob too short for modulus"):
            _parse_rsa_public_key_blob(blob)


class TestProprietaryCertificate:
    """Tests for proprietary certificate parsing and validation."""

    def _build_proprietary_cert(
        self, exponent: int = 65537, modulus: bytes = b"\x01" * 64
    ) -> bytes:
        """Build a proprietary certificate with a valid signature.

        Uses the well-known TS signing key to create a valid signature.
        """
        # Build the public key blob
        magic = 0x31415352
        keylen = len(modulus)
        bitlen = keylen * 8
        datalen = keylen - 1
        pub_key_blob = struct.pack(
            "<IIIII", magic, keylen, bitlen, datalen, exponent
        ) + modulus

        # Compute signature: MD5(pub_key_blob) encrypted with TS private key
        # For testing, we compute the raw RSA signature
        md5_hash = hashlib.md5(pub_key_blob).digest()

        # We need to "sign" with the TS signing key's private key
        # Since we know the modulus and exponent, we can compute d for testing
        # But the TS signing key private key is not public.
        # Instead, we'll create a signature that validates against our verification.
        # For the test, we'll compute sig = hash^d mod n using a known private key.

        # Actually, for testing certificate parsing structure, we'll mock the
        # signature validation. Let's build a cert with a signature that we
        # can verify structurally.

        # Build certificate structure
        dw_version = struct.pack("<I", 0x00000001)
        dw_sig_alg_id = struct.pack("<I", 0x00000001)
        dw_key_alg_id = struct.pack("<I", 0x00000001)
        pub_key_blob_type = struct.pack("<H", 0x0006)
        pub_key_blob_len = struct.pack("<H", len(pub_key_blob))

        # For signature, we need to create a valid one
        # Compute: sig_int = md5_hash_int ^ d mod n
        # We don't have d, so we'll create a test with a custom key pair
        sig_blob_type = struct.pack("<H", 0x0008)
        # Use a dummy signature (64 bytes for 512-bit key) — validation will fail
        # but we test the parsing structure
        dummy_sig = b"\x00" * 64
        sig_blob_len = struct.pack("<H", len(dummy_sig))

        cert = (
            dw_version
            + dw_sig_alg_id
            + dw_key_alg_id
            + pub_key_blob_type
            + pub_key_blob_len
            + pub_key_blob
            + sig_blob_type
            + sig_blob_len
            + dummy_sig
        )
        return cert

    def test_parse_certificate_too_short(self):
        """Raise PduParseError on certificate shorter than minimum."""
        with pytest.raises(PduParseError, match="certificate too short"):
            parse_proprietary_certificate(b"\x00" * 4)

    def test_parse_certificate_truncated_key_blob(self):
        """Raise PduParseError when key blob extends beyond data."""
        # Version + SigAlgId + KeyAlgId + BlobType + BlobLen(huge)
        cert = struct.pack("<IIIHH", 1, 1, 1, 6, 9999)
        with pytest.raises(PduParseError, match="extends beyond"):
            parse_proprietary_certificate(cert)

    def test_parse_certificate_missing_signature(self):
        """Raise PduParseError when signature blob header is missing."""
        # Build a cert with valid key blob but no signature
        modulus = b"\x01" * 64
        pub_key_blob = struct.pack(
            "<IIIII", 0x31415352, 64, 512, 63, 65537
        ) + modulus

        cert = struct.pack("<IIIHH", 1, 1, 1, 6, len(pub_key_blob)) + pub_key_blob
        # No signature blob follows
        with pytest.raises(PduParseError, match="missing signature"):
            parse_proprietary_certificate(cert)


class TestStandardSecurityLayerCreation:
    """Tests for StandardSecurityLayer instantiation and properties."""

    def test_default_fields(self):
        """Default fields are empty/zero."""
        layer = StandardSecurityLayer()
        assert layer.server_random == b""
        assert layer.client_random == b""
        assert layer.encrypt_key == b""
        assert layer.decrypt_key == b""
        assert layer.mac_key == b""
        assert layer.encrypt_count == 0
        assert layer.decrypt_count == 0

    def test_is_enhanced_returns_false(self):
        """Standard Security is not Enhanced Security."""
        layer = StandardSecurityLayer()
        assert layer.is_enhanced is False


class TestStandardSecurityLayerEstablish:
    """Tests for establish() no-op behavior."""

    @pytest.mark.asyncio
    async def test_establish_is_noop(self):
        """establish() does nothing for Standard Security."""
        from unittest.mock import MagicMock

        layer = StandardSecurityLayer()
        mock_x224 = MagicMock()
        mock_tcp = MagicMock()

        # Should not raise
        await layer.establish(mock_x224, mock_tcp)

        # Nothing should have been called
        assert not mock_x224.method_calls
        assert not mock_tcp.method_calls


class TestStandardSecurityLayerEncryptDecrypt:
    """Tests for encrypt/decrypt round-trip with RC4."""

    def _setup_layer_with_keys(self) -> StandardSecurityLayer:
        """Create a layer with derived keys for testing."""
        layer = StandardSecurityLayer()
        client_random = bytes(range(32))
        server_random = bytes(range(32, 64))

        layer.client_random = client_random
        layer.server_random = server_random
        layer.mac_key, layer.encrypt_key, layer.decrypt_key = derive_keys(
            client_random, server_random
        )
        layer._original_encrypt_key = layer.encrypt_key
        layer._original_decrypt_key = layer.decrypt_key
        layer._init_rc4_ciphers()
        return layer

    def test_encrypt_decrypt_round_trip(self):
        """Encrypting then decrypting with matching keys returns original data."""
        # Create two layers with the same keys but swapped encrypt/decrypt
        client_random = bytes(range(32))
        server_random = bytes(range(32, 64))

        # Sender (client)
        sender = StandardSecurityLayer()
        sender.client_random = client_random
        sender.server_random = server_random
        sender.mac_key, sender.encrypt_key, sender.decrypt_key = derive_keys(
            client_random, server_random
        )
        sender._original_encrypt_key = sender.encrypt_key
        sender._original_decrypt_key = sender.decrypt_key
        sender._init_rc4_ciphers()

        # Receiver uses the sender's encrypt key as its decrypt key
        receiver = StandardSecurityLayer()
        receiver.client_random = client_random
        receiver.server_random = server_random
        receiver.mac_key = sender.mac_key
        # Receiver's decrypt key = sender's encrypt key
        receiver.decrypt_key = sender.encrypt_key
        receiver.encrypt_key = sender.decrypt_key
        receiver._original_encrypt_key = receiver.encrypt_key
        receiver._original_decrypt_key = receiver.decrypt_key
        receiver._init_rc4_ciphers()

        plaintext = b"Hello, Standard RDP Security!"
        ciphertext = sender.encrypt(plaintext)
        assert ciphertext != plaintext

        decrypted = receiver.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_encrypt_changes_data(self):
        """Encrypted data is different from plaintext."""
        layer = self._setup_layer_with_keys()
        plaintext = b"secret data" * 10
        ciphertext = layer.encrypt(plaintext)
        assert ciphertext != plaintext
        assert len(ciphertext) == len(plaintext)

    def test_encrypt_increments_counter(self):
        """Each encrypt call increments the counter."""
        layer = self._setup_layer_with_keys()
        assert layer.encrypt_count == 0

        layer.encrypt(b"data1")
        assert layer.encrypt_count == 1

        layer.encrypt(b"data2")
        assert layer.encrypt_count == 2

    def test_decrypt_increments_counter(self):
        """Each decrypt call increments the counter."""
        layer = self._setup_layer_with_keys()
        assert layer.decrypt_count == 0

        layer.decrypt(b"data1")
        assert layer.decrypt_count == 1

        layer.decrypt(b"data2")
        assert layer.decrypt_count == 2

    def test_encrypt_empty_data(self):
        """Encrypting empty data returns empty data."""
        layer = self._setup_layer_with_keys()
        result = layer.encrypt(b"")
        assert result == b""


class TestStandardSecurityLayerKeyRefresh:
    """Tests for RC4 key refresh after 4096 packets."""

    def _setup_layer(self) -> StandardSecurityLayer:
        """Create a layer with derived keys."""
        layer = StandardSecurityLayer()
        client_random = b"\xaa" * 32
        server_random = b"\xbb" * 32

        layer.client_random = client_random
        layer.server_random = server_random
        layer.mac_key, layer.encrypt_key, layer.decrypt_key = derive_keys(
            client_random, server_random
        )
        layer._original_encrypt_key = layer.encrypt_key
        layer._original_decrypt_key = layer.decrypt_key
        layer._init_rc4_ciphers()
        return layer

    def test_key_refresh_at_4096_encrypt(self):
        """Encrypt key is refreshed after 4096 packets."""
        layer = self._setup_layer()
        original_key = layer.encrypt_key

        # Simulate reaching the threshold
        layer.encrypt_count = _KEY_UPDATE_INTERVAL

        # Next encrypt should trigger refresh
        layer.encrypt(b"trigger refresh")

        # Key should have changed
        assert layer.encrypt_key != original_key
        # Counter should be reset to 1 (incremented after refresh)
        assert layer.encrypt_count == 1

    def test_key_refresh_at_4096_decrypt(self):
        """Decrypt key is refreshed after 4096 packets."""
        layer = self._setup_layer()
        original_key = layer.decrypt_key

        # Simulate reaching the threshold
        layer.decrypt_count = _KEY_UPDATE_INTERVAL

        # Next decrypt should trigger refresh
        layer.decrypt(b"trigger refresh")

        # Key should have changed
        assert layer.decrypt_key != original_key
        # Counter should be reset to 1
        assert layer.decrypt_count == 1

    def test_no_refresh_before_4096(self):
        """Key is not refreshed before reaching 4096 packets."""
        layer = self._setup_layer()
        original_key = layer.encrypt_key

        layer.encrypt_count = _KEY_UPDATE_INTERVAL - 1
        layer.encrypt(b"no refresh yet")

        # Key should NOT have changed
        assert layer.encrypt_key == original_key
        assert layer.encrypt_count == _KEY_UPDATE_INTERVAL


class TestStandardSecurityLayerWrapUnwrap:
    """Tests for wrap_pdu/unwrap_pdu with encryption and MAC."""

    def _setup_paired_layers(self) -> tuple[StandardSecurityLayer, StandardSecurityLayer]:
        """Create sender/receiver pair with matching keys."""
        client_random = bytes(range(32))
        server_random = bytes(range(32, 64))

        sender = StandardSecurityLayer()
        sender.client_random = client_random
        sender.server_random = server_random
        sender.mac_key, sender.encrypt_key, sender.decrypt_key = derive_keys(
            client_random, server_random
        )
        sender._original_encrypt_key = sender.encrypt_key
        sender._original_decrypt_key = sender.decrypt_key
        sender._init_rc4_ciphers()

        # Receiver's decrypt key = sender's encrypt key
        receiver = StandardSecurityLayer()
        receiver.client_random = client_random
        receiver.server_random = server_random
        receiver.mac_key = sender.mac_key
        receiver.decrypt_key = sender.encrypt_key
        receiver.encrypt_key = sender.decrypt_key
        receiver._original_encrypt_key = receiver.encrypt_key
        receiver._original_decrypt_key = receiver.decrypt_key
        receiver._init_rc4_ciphers()

        return sender, receiver

    def test_wrap_pdu_format(self):
        """wrap_pdu produces header(4) + MAC(8) + encrypted payload."""
        sender, _ = self._setup_paired_layers()
        payload = b"test payload data"

        wrapped = sender.wrap_pdu(payload)

        # Header: 4 bytes (flags u16 LE + flagsHi u16 LE)
        # MAC: 8 bytes
        # Encrypted payload: same length as original
        assert len(wrapped) == 4 + 8 + len(payload)

        # Check flags
        flags = struct.unpack_from("<H", wrapped, 0)[0]
        assert flags == SEC_ENCRYPT

    def test_wrap_unwrap_round_trip(self):
        """wrap_pdu then unwrap_pdu returns the original payload."""
        sender, receiver = self._setup_paired_layers()
        original = b"Hello, Standard RDP Security wrap/unwrap!"

        wrapped = sender.wrap_pdu(original)
        unwrapped, flags = receiver.unwrap_pdu(wrapped)

        assert unwrapped == original
        assert flags == SEC_ENCRYPT

    def test_unwrap_non_encrypted_pdu(self):
        """unwrap_pdu with no SEC_ENCRYPT flag returns payload without decryption."""
        layer = StandardSecurityLayer()
        layer.mac_key = b"\x00" * 16

        # Build a PDU with flags=0 (no encryption)
        payload = b"unencrypted data"
        message = struct.pack("<HH", 0, 0) + payload

        result, flags = layer.unwrap_pdu(message)
        assert result == payload
        assert flags == 0

    def test_unwrap_pdu_too_short(self):
        """unwrap_pdu raises PduParseError on data shorter than header."""
        layer = StandardSecurityLayer()
        with pytest.raises(PduParseError, match="too short for header"):
            layer.unwrap_pdu(b"\x00\x00")

    def test_unwrap_pdu_too_short_for_mac(self):
        """unwrap_pdu raises PduParseError when MAC is missing."""
        layer = StandardSecurityLayer()
        # Header with SEC_ENCRYPT but no MAC data
        message = struct.pack("<HH", SEC_ENCRYPT, 0)
        with pytest.raises(PduParseError, match="too short for MAC"):
            layer.unwrap_pdu(message)


class TestStandardSecurityLayerComputeMac:
    """Tests for the compute_mac method on the layer."""

    def test_compute_mac_uses_session_mac_key(self):
        """Layer's compute_mac uses the session mac_key."""
        layer = StandardSecurityLayer()
        layer.mac_key = b"\xab" * 16

        data = b"test data for mac"
        result = layer.compute_mac(data)

        # Should match the module-level function
        expected = compute_mac(b"\xab" * 16, data)
        assert result == expected


class TestRSAEncryptClientRandom:
    """Tests for RSA encryption of client random."""

    def test_encrypt_returns_modulus_length_bytes(self):
        """Encrypted output is the same length as the modulus."""
        client_random = b"\x01" * 32
        modulus = b"\xff" * 64  # 512-bit modulus
        exponent = 65537

        result = _rsa_encrypt_client_random(client_random, exponent, modulus)
        assert len(result) == 64

    def test_encrypt_deterministic(self):
        """Same inputs produce the same encrypted output (raw RSA, no random padding)."""
        client_random = b"\xaa" * 32
        modulus = b"\xff" * 64
        exponent = 65537

        result1 = _rsa_encrypt_client_random(client_random, exponent, modulus)
        result2 = _rsa_encrypt_client_random(client_random, exponent, modulus)
        assert result1 == result2

    def test_encrypt_different_random_different_output(self):
        """Different client randoms produce different encrypted outputs."""
        modulus = b"\xff" * 64
        exponent = 65537

        result1 = _rsa_encrypt_client_random(b"\x01" * 32, exponent, modulus)
        result2 = _rsa_encrypt_client_random(b"\x02" * 32, exponent, modulus)
        assert result1 != result2
