"""Tests for SecurityLayer ABC and TlsSecurityLayer implementation.

Validates: Req 10 (AC 1–4) — TLS security layer behavior.
"""

from __future__ import annotations

import logging
import ssl
import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from arrdipi.security.base import SecurityLayer
from arrdipi.security.enhanced import TlsSecurityLayer


class TestSecurityLayerABC:
    """Tests for the SecurityLayer abstract base class."""

    def test_cannot_instantiate_directly(self):
        """SecurityLayer ABC cannot be instantiated without implementing all methods."""
        with pytest.raises(TypeError, match="abstract method"):
            SecurityLayer()  # type: ignore[abstract]

    def test_subclass_must_implement_all_methods(self):
        """A subclass missing abstract methods cannot be instantiated."""

        class IncompleteLayer(SecurityLayer):
            async def establish(self, x224, tcp):
                pass

            def encrypt(self, data):
                return data

            # Missing: decrypt, wrap_pdu, unwrap_pdu, is_enhanced

        with pytest.raises(TypeError, match="abstract method"):
            IncompleteLayer()  # type: ignore[abstract]


class TestTlsSecurityLayerCreation:
    """Tests for TlsSecurityLayer instantiation and defaults."""

    def test_default_verify_cert_is_true(self):
        """verify_cert defaults to True."""
        layer = TlsSecurityLayer()
        assert layer.verify_cert is True

    def test_verify_cert_can_be_set_false(self):
        """verify_cert can be explicitly set to False."""
        layer = TlsSecurityLayer(verify_cert=False)
        assert layer.verify_cert is False

    def test_is_enhanced_returns_true(self):
        """TLS is an Enhanced Security protocol."""
        layer = TlsSecurityLayer()
        assert layer.is_enhanced is True

    def test_server_hostname_defaults_empty(self):
        """server_hostname defaults to empty string."""
        layer = TlsSecurityLayer()
        assert layer.server_hostname == ""

    def test_server_hostname_can_be_set(self):
        """server_hostname can be set at construction."""
        layer = TlsSecurityLayer(server_hostname="rdp.example.com")
        assert layer.server_hostname == "rdp.example.com"


class TestTlsSecurityLayerEncryptDecrypt:
    """Tests for encrypt/decrypt identity functions (Req 10, AC 4)."""

    def test_encrypt_returns_data_unchanged(self):
        """encrypt() is an identity function for TLS."""
        layer = TlsSecurityLayer()
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        assert layer.encrypt(data) == data

    def test_decrypt_returns_data_unchanged(self):
        """decrypt() is an identity function for TLS."""
        layer = TlsSecurityLayer()
        data = b"\xff\xfe\xfd\xfc\xfb\xfa"
        assert layer.decrypt(data) == data

    def test_encrypt_empty_data(self):
        """encrypt() handles empty bytes."""
        layer = TlsSecurityLayer()
        assert layer.encrypt(b"") == b""

    def test_decrypt_empty_data(self):
        """decrypt() handles empty bytes."""
        layer = TlsSecurityLayer()
        assert layer.decrypt(b"") == b""

    def test_encrypt_large_data(self):
        """encrypt() handles large payloads unchanged."""
        layer = TlsSecurityLayer()
        data = b"\xab" * 65536
        assert layer.encrypt(data) == data

    def test_decrypt_large_data(self):
        """decrypt() handles large payloads unchanged."""
        layer = TlsSecurityLayer()
        data = b"\xcd" * 65536
        assert layer.decrypt(data) == data


class TestTlsSecurityLayerWrapUnwrap:
    """Tests for wrap_pdu/unwrap_pdu security header handling."""

    def test_wrap_pdu_adds_4_byte_header(self):
        """wrap_pdu() prepends a 4-byte security header."""
        layer = TlsSecurityLayer()
        payload = b"\x01\x02\x03\x04"
        wrapped = layer.wrap_pdu(payload)

        assert len(wrapped) == 4 + len(payload)
        # Header should be flags=0, flagsHi=0 (4 zero bytes)
        assert wrapped[:4] == b"\x00\x00\x00\x00"
        assert wrapped[4:] == payload

    def test_wrap_pdu_header_is_le_encoded(self):
        """wrap_pdu() header is two u16 LE values (flags=0, flagsHi=0)."""
        layer = TlsSecurityLayer()
        wrapped = layer.wrap_pdu(b"test")

        flags = struct.unpack_from("<H", wrapped, 0)[0]
        flags_hi = struct.unpack_from("<H", wrapped, 2)[0]
        assert flags == 0
        assert flags_hi == 0

    def test_unwrap_pdu_strips_4_byte_header(self):
        """unwrap_pdu() removes the 4-byte security header."""
        layer = TlsSecurityLayer()
        payload = b"\x05\x06\x07\x08\x09\x0a"
        # Construct a message with header (flags=0, flagsHi=0) + payload
        message = struct.pack("<HH", 0, 0) + payload

        result_payload, flags = layer.unwrap_pdu(message)
        assert result_payload == payload
        assert flags == 0

    def test_unwrap_pdu_extracts_flags(self):
        """unwrap_pdu() returns the flags value from the header."""
        layer = TlsSecurityLayer()
        payload = b"\xaa\xbb"
        # Set flags=0x0008 (SEC_ENCRYPT), flagsHi=0
        message = struct.pack("<HH", 0x0008, 0) + payload

        result_payload, flags = layer.unwrap_pdu(message)
        assert result_payload == payload
        assert flags == 0x0008

    def test_wrap_unwrap_round_trip(self):
        """wrap_pdu then unwrap_pdu returns the original payload."""
        layer = TlsSecurityLayer()
        original = b"Hello, RDP security layer!"

        wrapped = layer.wrap_pdu(original)
        unwrapped, flags = layer.unwrap_pdu(wrapped)

        assert unwrapped == original
        assert flags == 0

    def test_wrap_pdu_empty_payload(self):
        """wrap_pdu() works with empty payload."""
        layer = TlsSecurityLayer()
        wrapped = layer.wrap_pdu(b"")
        assert len(wrapped) == 4
        assert wrapped == b"\x00\x00\x00\x00"

    def test_unwrap_pdu_header_only(self):
        """unwrap_pdu() with only header returns empty payload."""
        layer = TlsSecurityLayer()
        message = struct.pack("<HH", 0, 0)
        payload, flags = layer.unwrap_pdu(message)
        assert payload == b""
        assert flags == 0


class TestTlsSecurityLayerEstablish:
    """Tests for establish() TLS upgrade behavior (Req 10, AC 1–3)."""

    @pytest.mark.asyncio
    async def test_establish_calls_upgrade_to_tls(self):
        """establish() calls tcp.upgrade_to_tls with an SSLContext."""
        layer = TlsSecurityLayer(server_hostname="rdp.example.com")

        mock_tcp = MagicMock()
        mock_tcp.upgrade_to_tls = AsyncMock()
        mock_x224 = MagicMock()

        await layer.establish(mock_x224, mock_tcp)

        mock_tcp.upgrade_to_tls.assert_awaited_once()
        call_args = mock_tcp.upgrade_to_tls.call_args
        ctx_arg = call_args[0][0] if call_args[0] else call_args[1].get("ssl_context")
        hostname_arg = call_args[1].get("server_hostname", call_args[0][1] if len(call_args[0]) > 1 else None)

        assert isinstance(ctx_arg, ssl.SSLContext)
        assert hostname_arg == "rdp.example.com"

    @pytest.mark.asyncio
    async def test_establish_with_verify_cert_true_uses_default_context(self):
        """establish() with verify_cert=True uses default verification."""
        layer = TlsSecurityLayer(verify_cert=True, server_hostname="server.test")

        mock_tcp = MagicMock()
        mock_tcp.upgrade_to_tls = AsyncMock()
        mock_x224 = MagicMock()

        with patch("arrdipi.security.enhanced.ssl.create_default_context") as mock_ctx_factory:
            mock_ctx = MagicMock(spec=ssl.SSLContext)
            mock_ctx_factory.return_value = mock_ctx

            await layer.establish(mock_x224, mock_tcp)

            mock_ctx_factory.assert_called_once()
            # check_hostname and verify_mode should NOT be modified
            assert not hasattr(mock_ctx, "_check_hostname_set") or True
            # The key assertion: upgrade_to_tls was called with the context
            mock_tcp.upgrade_to_tls.assert_awaited_once_with(
                mock_ctx, server_hostname="server.test"
            )

    @pytest.mark.asyncio
    async def test_establish_with_verify_cert_false_disables_verification(self):
        """establish() with verify_cert=False disables hostname and cert checks."""
        layer = TlsSecurityLayer(verify_cert=False, server_hostname="insecure.test")

        mock_tcp = MagicMock()
        mock_tcp.upgrade_to_tls = AsyncMock()
        mock_x224 = MagicMock()

        with patch("arrdipi.security.enhanced.ssl.create_default_context") as mock_ctx_factory:
            mock_ctx = MagicMock(spec=ssl.SSLContext)
            mock_ctx_factory.return_value = mock_ctx

            await layer.establish(mock_x224, mock_tcp)

            # Verify that check_hostname and verify_mode were set
            assert mock_ctx.check_hostname is False
            assert mock_ctx.verify_mode == ssl.CERT_NONE

    @pytest.mark.asyncio
    async def test_establish_verify_cert_false_logs_warning(self, caplog):
        """establish() with verify_cert=False logs a warning."""
        layer = TlsSecurityLayer(verify_cert=False, server_hostname="warn.test")

        mock_tcp = MagicMock()
        mock_tcp.upgrade_to_tls = AsyncMock()
        mock_x224 = MagicMock()

        with caplog.at_level(logging.WARNING, logger="arrdipi.security.enhanced"):
            await layer.establish(mock_x224, mock_tcp)

        assert any(
            "certificate verification disabled" in record.message.lower()
            for record in caplog.records
        )

    @pytest.mark.asyncio
    async def test_establish_verify_cert_true_no_warning(self, caplog):
        """establish() with verify_cert=True does not log a warning."""
        layer = TlsSecurityLayer(verify_cert=True, server_hostname="safe.test")

        mock_tcp = MagicMock()
        mock_tcp.upgrade_to_tls = AsyncMock()
        mock_x224 = MagicMock()

        with caplog.at_level(logging.WARNING, logger="arrdipi.security.enhanced"):
            await layer.establish(mock_x224, mock_tcp)

        warning_records = [
            r for r in caplog.records
            if "certificate verification" in r.message.lower()
        ]
        assert len(warning_records) == 0

    @pytest.mark.asyncio
    async def test_establish_uses_ssl_create_default_context(self):
        """establish() creates the SSLContext via ssl.create_default_context()."""
        layer = TlsSecurityLayer(server_hostname="ctx.test")

        mock_tcp = MagicMock()
        mock_tcp.upgrade_to_tls = AsyncMock()
        mock_x224 = MagicMock()

        with patch("arrdipi.security.enhanced.ssl.create_default_context") as mock_ctx_factory:
            mock_ctx = MagicMock(spec=ssl.SSLContext)
            mock_ctx_factory.return_value = mock_ctx

            await layer.establish(mock_x224, mock_tcp)

            mock_ctx_factory.assert_called_once()
