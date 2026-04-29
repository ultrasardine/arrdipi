"""Tests for NLA/CredSSP security layer and TSRequest PDU.

Tests cover:
- TSRequest parse/serialize round-trip
- TSCredentials and TSPasswordCreds round-trip
- Error code extraction from TSRequest
- NlaSecurityLayer creation and defaults
- NlaSecurityLayer establish() calls TLS upgrade then CredSSP
- AuthenticationError raised on error code
- NegotiationError raised on SPNEGO failure
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from arrdipi.errors import AuthenticationError, NegotiationError, PduParseError
from arrdipi.pdu.credssp import (
    CREDSSP_VERSION,
    TSCredentials,
    TSPasswordCreds,
    TSRequest,
)
from arrdipi.security.nla import NlaSecurityLayer


# ============================================================
# TSRequest PDU Tests
# ============================================================


class TestTSRequest:
    """Tests for TSRequest parse/serialize round-trip."""

    def test_serialize_minimal(self) -> None:
        """TSRequest with only version serializes correctly."""
        req = TSRequest(version=6)
        data = req.serialize()
        assert data[0] == 0x30  # SEQUENCE tag
        parsed = TSRequest.parse(data)
        assert parsed.version == 6
        assert parsed.nego_tokens == []
        assert parsed.auth_info == b""
        assert parsed.pub_key_auth == b""
        assert parsed.error_code == 0
        assert parsed.client_nonce == b""

    def test_round_trip_with_nego_tokens(self) -> None:
        """TSRequest with negoTokens round-trips correctly."""
        token = b"\x60\x28\x06\x06\x2b\x06\x01\x05\x05\x02"
        req = TSRequest(version=6, nego_tokens=[token])
        data = req.serialize()
        parsed = TSRequest.parse(data)
        assert parsed.version == 6
        assert parsed.nego_tokens == [token]

    def test_round_trip_with_multiple_nego_tokens(self) -> None:
        """TSRequest with multiple negoTokens round-trips correctly."""
        tokens = [b"\x01\x02\x03", b"\x04\x05\x06"]
        req = TSRequest(version=6, nego_tokens=tokens)
        data = req.serialize()
        parsed = TSRequest.parse(data)
        assert parsed.nego_tokens == tokens

    def test_round_trip_with_auth_info(self) -> None:
        """TSRequest with authInfo round-trips correctly."""
        auth = b"\xAA\xBB\xCC\xDD" * 10
        req = TSRequest(version=6, auth_info=auth)
        data = req.serialize()
        parsed = TSRequest.parse(data)
        assert parsed.auth_info == auth

    def test_round_trip_with_pub_key_auth(self) -> None:
        """TSRequest with pubKeyAuth round-trips correctly."""
        pub_key = b"\x01" * 64
        req = TSRequest(version=6, pub_key_auth=pub_key)
        data = req.serialize()
        parsed = TSRequest.parse(data)
        assert parsed.pub_key_auth == pub_key

    def test_round_trip_with_error_code(self) -> None:
        """TSRequest with errorCode round-trips correctly."""
        req = TSRequest(version=6, error_code=0xC000006D)
        data = req.serialize()
        parsed = TSRequest.parse(data)
        assert parsed.error_code == 0xC000006D

    def test_round_trip_with_client_nonce(self) -> None:
        """TSRequest with clientNonce round-trips correctly."""
        nonce = b"\x42" * 32
        req = TSRequest(version=6, client_nonce=nonce)
        data = req.serialize()
        parsed = TSRequest.parse(data)
        assert parsed.client_nonce == nonce

    def test_round_trip_full(self) -> None:
        """TSRequest with all fields round-trips correctly."""
        req = TSRequest(
            version=6,
            nego_tokens=[b"\x01\x02\x03"],
            auth_info=b"\xAA\xBB",
            pub_key_auth=b"\xCC\xDD",
            error_code=42,
            client_nonce=b"\xFF" * 32,
        )
        data = req.serialize()
        parsed = TSRequest.parse(data)
        assert parsed.version == req.version
        assert parsed.nego_tokens == req.nego_tokens
        assert parsed.auth_info == req.auth_info
        assert parsed.pub_key_auth == req.pub_key_auth
        assert parsed.error_code == req.error_code
        assert parsed.client_nonce == req.client_nonce

    def test_parse_empty_data_raises(self) -> None:
        """Parsing empty data raises PduParseError."""
        with pytest.raises(PduParseError, match="empty data"):
            TSRequest.parse(b"")

    def test_parse_invalid_tag_raises(self) -> None:
        """Parsing data with wrong tag raises PduParseError."""
        with pytest.raises(PduParseError, match="expected SEQUENCE tag"):
            TSRequest.parse(b"\x02\x01\x06")

    def test_error_code_extraction(self) -> None:
        """Error code is correctly extracted from a server TSRequest."""
        # STATUS_LOGON_FAILURE = 0xC000006D
        req = TSRequest(version=6, error_code=0xC000006D)
        data = req.serialize()
        parsed = TSRequest.parse(data)
        assert parsed.error_code == 0xC000006D

    def test_serialize_deterministic(self) -> None:
        """Serialization produces identical output for identical inputs."""
        req = TSRequest(version=6, nego_tokens=[b"\x01\x02"])
        assert req.serialize() == req.serialize()


# ============================================================
# TSCredentials / TSPasswordCreds Tests
# ============================================================


class TestTSPasswordCreds:
    """Tests for TSPasswordCreds parse/serialize."""

    def test_round_trip(self) -> None:
        """TSPasswordCreds round-trips correctly."""
        creds = TSPasswordCreds(
            domain_name="CORP",
            user_name="admin",
            password="secret123",
        )
        data = creds.serialize()
        parsed = TSPasswordCreds.parse(data)
        assert parsed.domain_name == "CORP"
        assert parsed.user_name == "admin"
        assert parsed.password == "secret123"

    def test_empty_fields(self) -> None:
        """TSPasswordCreds with empty fields round-trips."""
        creds = TSPasswordCreds()
        data = creds.serialize()
        parsed = TSPasswordCreds.parse(data)
        assert parsed.domain_name == ""
        assert parsed.user_name == ""
        assert parsed.password == ""

    def test_unicode_characters(self) -> None:
        """TSPasswordCreds handles unicode characters."""
        creds = TSPasswordCreds(
            domain_name="DOMÄIN",
            user_name="üser",
            password="pässwörd",
        )
        data = creds.serialize()
        parsed = TSPasswordCreds.parse(data)
        assert parsed.domain_name == "DOMÄIN"
        assert parsed.user_name == "üser"
        assert parsed.password == "pässwörd"


class TestTSCredentials:
    """Tests for TSCredentials parse/serialize."""

    def test_round_trip(self) -> None:
        """TSCredentials round-trips correctly."""
        inner = TSPasswordCreds(
            domain_name="CORP", user_name="user", password="pass"
        ).serialize()
        creds = TSCredentials(cred_type=1, credentials=inner)
        data = creds.serialize()
        parsed = TSCredentials.parse(data)
        assert parsed.cred_type == 1
        assert parsed.credentials == inner

    def test_default_cred_type(self) -> None:
        """TSCredentials defaults to cred_type=1."""
        creds = TSCredentials()
        assert creds.cred_type == 1


# ============================================================
# NlaSecurityLayer Tests
# ============================================================


class TestNlaSecurityLayer:
    """Tests for NlaSecurityLayer creation and behavior."""

    def test_defaults(self) -> None:
        """NlaSecurityLayer has correct defaults."""
        nla = NlaSecurityLayer()
        assert nla.username == ""
        assert nla.password == ""
        assert nla.domain == ""
        assert nla.verify_cert is True
        assert nla.server_hostname == ""
        assert nla.protocol == "ntlm"
        assert nla.is_enhanced is True

    def test_creation_with_params(self) -> None:
        """NlaSecurityLayer accepts all parameters."""
        nla = NlaSecurityLayer(
            username="admin",
            password="secret",
            domain="CORP",
            verify_cert=False,
            server_hostname="rdp.example.com",
            protocol="negotiate",
        )
        assert nla.username == "admin"
        assert nla.password == "secret"
        assert nla.domain == "CORP"
        assert nla.verify_cert is False
        assert nla.server_hostname == "rdp.example.com"
        assert nla.protocol == "negotiate"

    def test_encrypt_identity(self) -> None:
        """encrypt() is identity function for NLA."""
        nla = NlaSecurityLayer()
        data = b"\x01\x02\x03\x04"
        assert nla.encrypt(data) == data

    def test_decrypt_identity(self) -> None:
        """decrypt() is identity function for NLA."""
        nla = NlaSecurityLayer()
        data = b"\x01\x02\x03\x04"
        assert nla.decrypt(data) == data

    def test_wrap_pdu(self) -> None:
        """wrap_pdu() prepends 4-byte zero header."""
        nla = NlaSecurityLayer()
        payload = b"\xAA\xBB\xCC"
        wrapped = nla.wrap_pdu(payload)
        assert wrapped == b"\x00\x00\x00\x00\xAA\xBB\xCC"

    def test_unwrap_pdu(self) -> None:
        """unwrap_pdu() strips 4-byte header and returns flags."""
        nla = NlaSecurityLayer()
        data = b"\x01\x00\x00\x00\xAA\xBB\xCC"
        payload, flags = nla.unwrap_pdu(data)
        assert payload == b"\xAA\xBB\xCC"
        assert flags == 1

    def test_is_enhanced(self) -> None:
        """NLA is Enhanced Security."""
        nla = NlaSecurityLayer()
        assert nla.is_enhanced is True


class TestNlaEstablish:
    """Tests for NlaSecurityLayer.establish() flow."""

    @pytest.mark.asyncio
    async def test_establish_calls_tls_then_credssp(self) -> None:
        """establish() performs TLS upgrade then CredSSP handshake."""
        nla = NlaSecurityLayer(
            username="user",
            password="pass",
            server_hostname="server.test",
        )

        tcp = AsyncMock()
        x224 = AsyncMock()

        with (
            patch.object(nla, "_upgrade_tls", new_callable=AsyncMock) as mock_tls,
            patch.object(nla, "_credssp_handshake", new_callable=AsyncMock) as mock_credssp,
        ):
            await nla.establish(x224, tcp)
            mock_tls.assert_called_once_with(tcp)
            mock_credssp.assert_called_once_with(tcp)

    @pytest.mark.asyncio
    async def test_authentication_error_on_server_error_code(self) -> None:
        """AuthenticationError raised when server sends error code."""
        nla = NlaSecurityLayer(
            username="user",
            password="wrong",
            server_hostname="server.test",
        )

        # Build a server response with error code
        error_response = TSRequest(
            version=6, error_code=0xC000006D
        ).serialize()

        tcp = AsyncMock()
        # Mock the recv to return the error response
        # First call returns the tag byte, second the length, etc.
        tcp.recv = AsyncMock(side_effect=_build_recv_side_effect(error_response))

        mock_spnego = MagicMock()
        mock_spnego.complete = False
        # First step returns a token
        initial_token = b"\x60\x03\x01\x02\x03"
        mock_spnego.step = MagicMock(return_value=initial_token)

        with (
            patch.object(nla, "_upgrade_tls", new_callable=AsyncMock),
            patch.object(nla, "_get_server_public_key", return_value=b"\x00" * 32),
            patch("arrdipi.security.nla.spnego.client", return_value=mock_spnego),
        ):
            with pytest.raises(AuthenticationError) as exc_info:
                await nla._credssp_handshake(tcp)
            assert exc_info.value.error_code == 0xC000006D

    @pytest.mark.asyncio
    async def test_negotiation_error_on_spnego_failure(self) -> None:
        """NegotiationError raised when SPNEGO context creation fails."""
        nla = NlaSecurityLayer(
            username="user",
            password="pass",
            server_hostname="server.test",
        )

        tcp = AsyncMock()

        with (
            patch.object(nla, "_upgrade_tls", new_callable=AsyncMock),
            patch.object(nla, "_get_server_public_key", return_value=b"\x00" * 32),
            patch(
                "arrdipi.security.nla.spnego.client",
                side_effect=Exception("Kerberos not available"),
            ),
        ):
            with pytest.raises(NegotiationError, match="Failed to create SPNEGO context"):
                await nla._credssp_handshake(tcp)

    @pytest.mark.asyncio
    async def test_negotiation_error_on_token_exchange_failure(self) -> None:
        """NegotiationError raised when SPNEGO token exchange fails."""
        nla = NlaSecurityLayer(
            username="user",
            password="pass",
            server_hostname="server.test",
        )

        # Server response with a nego token
        server_response = TSRequest(
            version=6, nego_tokens=[b"\x01\x02\x03"]
        ).serialize()

        tcp = AsyncMock()
        tcp.recv = AsyncMock(side_effect=_build_recv_side_effect(server_response))

        mock_spnego = MagicMock()
        mock_spnego.complete = False
        # First step succeeds, second step raises
        mock_spnego.step = MagicMock(
            side_effect=[b"\x60\x03\x01\x02\x03", Exception("Token exchange failed")]
        )

        with (
            patch.object(nla, "_upgrade_tls", new_callable=AsyncMock),
            patch.object(nla, "_get_server_public_key", return_value=b"\x00" * 32),
            patch("arrdipi.security.nla.spnego.client", return_value=mock_spnego),
        ):
            with pytest.raises(NegotiationError, match="SPNEGO token exchange failed"):
                await nla._credssp_handshake(tcp)

    @pytest.mark.asyncio
    async def test_negotiation_error_missing_server_token(self) -> None:
        """NegotiationError raised when server response has no tokens."""
        nla = NlaSecurityLayer(
            username="user",
            password="pass",
            server_hostname="server.test",
        )

        # Server response with no nego tokens
        server_response = TSRequest(version=6).serialize()

        tcp = AsyncMock()
        tcp.recv = AsyncMock(side_effect=_build_recv_side_effect(server_response))

        mock_spnego = MagicMock()
        mock_spnego.complete = False
        mock_spnego.step = MagicMock(return_value=b"\x60\x03\x01\x02\x03")

        with (
            patch.object(nla, "_upgrade_tls", new_callable=AsyncMock),
            patch.object(nla, "_get_server_public_key", return_value=b"\x00" * 32),
            patch("arrdipi.security.nla.spnego.client", return_value=mock_spnego),
        ):
            with pytest.raises(NegotiationError, match="missing SPNEGO token"):
                await nla._credssp_handshake(tcp)

    @pytest.mark.asyncio
    async def test_kerberos_protocol_negotiate(self) -> None:
        """NlaSecurityLayer with protocol='negotiate' uses Kerberos."""
        nla = NlaSecurityLayer(
            username="user",
            password="pass",
            server_hostname="server.test",
            protocol="negotiate",
        )
        assert nla.protocol == "negotiate"


# ============================================================
# Helpers
# ============================================================


def _build_recv_side_effect(response_data: bytes):
    """Build a side_effect function for tcp.recv that returns TSRequest data.

    Simulates reading the ASN.1 DER-encoded TSRequest byte by byte as
    the _recv_tsrequest method does.
    """
    # The _recv_tsrequest reads: 1 byte tag, 1 byte length indicator,
    # possibly N length bytes, then content
    calls = []

    offset = 0
    # First call: 1 byte (tag)
    calls.append(response_data[offset : offset + 1])
    offset += 1

    # Second call: 1 byte (length first byte)
    length_byte = response_data[offset]
    calls.append(response_data[offset : offset + 1])
    offset += 1

    if length_byte < 0x80:
        # Short form: content is length_byte bytes
        calls.append(response_data[offset : offset + length_byte])
    else:
        # Long form: num_length_bytes more bytes for length
        num_length_bytes = length_byte & 0x7F
        calls.append(response_data[offset : offset + num_length_bytes])
        offset += num_length_bytes
        total_length = int.from_bytes(
            response_data[offset - num_length_bytes : offset], "big"
        )
        calls.append(response_data[offset : offset + total_length])

    async def side_effect(n: int) -> bytes:
        if calls:
            return calls.pop(0)
        return b""

    return side_effect
