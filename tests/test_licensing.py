"""Tests for the MS-RDPELE licensing exchange handler.

Tests cover:
- STATUS_VALID_CLIENT error PDU completes licensing immediately (common fast path)
- License Request → New License Request response
- Platform Challenge → Challenge Response
- Full exchange flow with mock send/recv
- PDU parse/serialize round-trip for all licensing PDU types
- Error handling for unexpected message types and licensing errors
"""

from __future__ import annotations

import struct
from unittest.mock import AsyncMock

import pytest

from arrdipi.errors import PduParseError
from arrdipi.security.licensing import (
    LicenseErrorCode,
    LicenseErrorPdu,
    LicenseMsgType,
    LicensePreamble,
    LicenseRequestPdu,
    LicenseStateTransition,
    LicensingHandler,
    NewLicenseRequestPdu,
    PlatformChallengePdu,
    PlatformChallengeResponsePdu,
    SEC_LICENSE_PKT,
)


# ============================================================
# LicensePreamble Tests
# ============================================================


class TestLicensePreamble:
    """Tests for LicensePreamble parse/serialize."""

    def test_round_trip(self) -> None:
        """Preamble round-trips correctly."""
        preamble = LicensePreamble(
            msg_type=LicenseMsgType.ERROR_ALERT,
            flags=0x03,
            msg_size=16,
        )
        data = preamble.serialize()
        parsed = LicensePreamble.parse(data)
        assert parsed.msg_type == LicenseMsgType.ERROR_ALERT
        assert parsed.flags == 0x03
        assert parsed.msg_size == 16

    def test_serialize_format(self) -> None:
        """Preamble serializes to 4 bytes in correct format."""
        preamble = LicensePreamble(msg_type=0x01, flags=0x02, msg_size=0x0010)
        data = preamble.serialize()
        assert len(data) == 4
        assert data[0] == 0x01  # msg_type
        assert data[1] == 0x02  # flags
        assert struct.unpack_from("<H", data, 2)[0] == 0x0010  # msg_size LE

    def test_parse_truncated_raises(self) -> None:
        """Parsing truncated data raises PduParseError."""
        with pytest.raises(PduParseError):
            LicensePreamble.parse(b"\x01\x02")


# ============================================================
# LicenseErrorPdu Tests
# ============================================================


class TestLicenseErrorPdu:
    """Tests for LicenseErrorPdu parse/serialize."""

    def test_round_trip_status_valid_client(self) -> None:
        """Error PDU with STATUS_VALID_CLIENT round-trips."""
        pdu = LicenseErrorPdu(
            error_code=LicenseErrorCode.STATUS_VALID_CLIENT,
            state_transition=LicenseStateTransition.ST_NO_TRANSITION,
            error_info=b"",
        )
        data = pdu.serialize()
        parsed = LicenseErrorPdu.parse(data)
        assert parsed.error_code == LicenseErrorCode.STATUS_VALID_CLIENT
        assert parsed.state_transition == LicenseStateTransition.ST_NO_TRANSITION
        assert parsed.error_info == b""

    def test_round_trip_with_error_info(self) -> None:
        """Error PDU with error info blob round-trips."""
        pdu = LicenseErrorPdu(
            error_code=LicenseErrorCode.ERR_NO_LICENSE,
            state_transition=LicenseStateTransition.ST_TOTAL_ABORT,
            error_info=b"\x01\x02\x03\x04",
        )
        data = pdu.serialize()
        parsed = LicenseErrorPdu.parse(data)
        assert parsed.error_code == LicenseErrorCode.ERR_NO_LICENSE
        assert parsed.state_transition == LicenseStateTransition.ST_TOTAL_ABORT
        assert parsed.error_info == b"\x01\x02\x03\x04"

    def test_parse_truncated_raises(self) -> None:
        """Parsing truncated data raises PduParseError."""
        with pytest.raises(PduParseError):
            LicenseErrorPdu.parse(b"\x07\x00\x00")


# ============================================================
# LicenseRequestPdu Tests
# ============================================================


class TestLicenseRequestPdu:
    """Tests for LicenseRequestPdu parse/serialize."""

    def test_round_trip(self) -> None:
        """License Request PDU round-trips correctly."""
        # Build a minimal product info block
        product_info = struct.pack("<I", 1)  # dwVersion
        company = b"M\x00S\x00\x00\x00"  # "MS" UTF-16LE null-terminated
        product_info += struct.pack("<I", len(company)) + company
        product_id = b"T\x00\x00\x00"
        product_info += struct.pack("<I", len(product_id)) + product_id

        server_random = b"\xAA" * 32
        key_exchange = b"\x01\x00\x00\x00"
        cert_data = b"\xDE\xAD\xBE\xEF" * 4

        pdu = LicenseRequestPdu(
            server_random=server_random,
            product_info=product_info,
            key_exchange_list=key_exchange,
            server_certificate=cert_data,
            scope_list=b"",
        )
        data = pdu.serialize()
        parsed = LicenseRequestPdu.parse(data)
        assert parsed.server_random == server_random
        assert parsed.key_exchange_list == key_exchange
        assert parsed.server_certificate == cert_data

    def test_parse_truncated_raises(self) -> None:
        """Parsing truncated data raises PduParseError."""
        with pytest.raises(PduParseError):
            LicenseRequestPdu.parse(b"\x00" * 10)


# ============================================================
# PlatformChallengePdu Tests
# ============================================================


class TestPlatformChallengePdu:
    """Tests for PlatformChallengePdu parse/serialize."""

    def test_round_trip(self) -> None:
        """Platform Challenge PDU round-trips correctly."""
        challenge = b"\x42" * 10
        mac = b"\xBB" * 16
        pdu = PlatformChallengePdu(mac_data=mac, encrypted_challenge=challenge)
        data = pdu.serialize()
        parsed = PlatformChallengePdu.parse(data)
        assert parsed.encrypted_challenge == challenge
        assert parsed.mac_data == mac

    def test_parse_truncated_raises(self) -> None:
        """Parsing truncated data raises PduParseError."""
        with pytest.raises(PduParseError):
            PlatformChallengePdu.parse(b"\x00" * 5)


# ============================================================
# NewLicenseRequestPdu Tests
# ============================================================


class TestNewLicenseRequestPdu:
    """Tests for NewLicenseRequestPdu parse/serialize."""

    def test_round_trip(self) -> None:
        """New License Request PDU round-trips correctly."""
        pdu = NewLicenseRequestPdu(
            key_exchange_alg=0x00000001,
            platform_id=0x04000100,
            client_random=b"\xCC" * 32,
            encrypted_premaster_secret=b"\xDD" * 48,
            client_username=b"user\x00",
            client_machine_name=b"host\x00",
        )
        data = pdu.serialize()
        parsed = NewLicenseRequestPdu.parse(data)
        assert parsed.key_exchange_alg == 0x00000001
        assert parsed.platform_id == 0x04000100
        assert parsed.client_random == b"\xCC" * 32
        assert parsed.encrypted_premaster_secret == b"\xDD" * 48
        assert parsed.client_username == b"user\x00"
        assert parsed.client_machine_name == b"host\x00"


# ============================================================
# PlatformChallengeResponsePdu Tests
# ============================================================


class TestPlatformChallengeResponsePdu:
    """Tests for PlatformChallengeResponsePdu parse/serialize."""

    def test_round_trip(self) -> None:
        """Platform Challenge Response PDU round-trips correctly."""
        pdu = PlatformChallengeResponsePdu(
            encrypted_response=b"\xEE" * 20,
            mac_data=b"\xFF" * 16,
        )
        data = pdu.serialize()
        parsed = PlatformChallengeResponsePdu.parse(data)
        assert parsed.encrypted_response == b"\xEE" * 20
        assert parsed.mac_data == b"\xFF" * 16


# ============================================================
# LicensingHandler Tests — Fast Path
# ============================================================


class TestLicensingHandlerFastPath:
    """Tests for the common fast path: STATUS_VALID_CLIENT error PDU."""

    @pytest.mark.asyncio
    async def test_status_valid_client_completes_licensing(self) -> None:
        """STATUS_VALID_CLIENT error PDU completes licensing immediately (Req 6, AC 4)."""
        handler = LicensingHandler(username="testuser", machine_name="testpc")

        # Build an ERROR_ALERT PDU with STATUS_VALID_CLIENT
        error_body = LicenseErrorPdu(
            error_code=LicenseErrorCode.STATUS_VALID_CLIENT,
            state_transition=LicenseStateTransition.ST_NO_TRANSITION,
            error_info=b"",
        ).serialize()

        preamble = LicensePreamble(
            msg_type=LicenseMsgType.ERROR_ALERT,
            flags=0x03,
            msg_size=len(error_body) + 4,
        ).serialize()

        pdu_data = preamble + error_body

        recv_fn = AsyncMock(return_value=pdu_data)
        send_fn = AsyncMock()

        await handler.handle_licensing(recv_fn, send_fn)

        assert handler.licensing_complete is True
        send_fn.assert_not_called()

    @pytest.mark.asyncio
    async def test_licensing_error_raises(self) -> None:
        """Non-STATUS_VALID_CLIENT error raises PduParseError."""
        handler = LicensingHandler()

        error_body = LicenseErrorPdu(
            error_code=LicenseErrorCode.ERR_NO_LICENSE,
            state_transition=LicenseStateTransition.ST_TOTAL_ABORT,
            error_info=b"",
        ).serialize()

        preamble = LicensePreamble(
            msg_type=LicenseMsgType.ERROR_ALERT,
            flags=0x03,
            msg_size=len(error_body) + 4,
        ).serialize()

        pdu_data = preamble + error_body

        recv_fn = AsyncMock(return_value=pdu_data)
        send_fn = AsyncMock()

        with pytest.raises(PduParseError, match="licensing error"):
            await handler.handle_licensing(recv_fn, send_fn)

    @pytest.mark.asyncio
    async def test_insufficient_data_raises(self) -> None:
        """Insufficient PDU data raises PduParseError."""
        handler = LicensingHandler()

        recv_fn = AsyncMock(return_value=b"\x01\x02")
        send_fn = AsyncMock()

        with pytest.raises(PduParseError, match="insufficient"):
            await handler.handle_licensing(recv_fn, send_fn)


# ============================================================
# LicensingHandler Tests — License Request
# ============================================================


class TestLicensingHandlerLicenseRequest:
    """Tests for License Request → New License Request response (Req 6, AC 1)."""

    @pytest.mark.asyncio
    async def test_license_request_sends_new_license_request(self) -> None:
        """License Request triggers a New License Request response."""
        handler = LicensingHandler(username="admin", machine_name="workstation")

        # Build a License Request PDU
        product_info = struct.pack("<I", 1)  # dwVersion
        company = b"M\x00i\x00c\x00r\x00o\x00s\x00o\x00f\x00t\x00\x00\x00"
        product_info += struct.pack("<I", len(company)) + company
        product_id = b"1\x00\x00\x00"
        product_info += struct.pack("<I", len(product_id)) + product_id

        license_req = LicenseRequestPdu(
            server_random=b"\xAA" * 32,
            product_info=product_info,
            key_exchange_list=b"\x01\x00\x00\x00",
            server_certificate=b"\xDE\xAD" * 8,
            scope_list=b"",
        )
        license_req_body = license_req.serialize()

        preamble = LicensePreamble(
            msg_type=LicenseMsgType.LICENSE_REQUEST,
            flags=0x03,
            msg_size=len(license_req_body) + 4,
        ).serialize()

        license_pdu_data = preamble + license_req_body

        # After sending the New License Request, server responds with STATUS_VALID_CLIENT
        error_body = LicenseErrorPdu(
            error_code=LicenseErrorCode.STATUS_VALID_CLIENT,
            state_transition=LicenseStateTransition.ST_NO_TRANSITION,
            error_info=b"",
        ).serialize()
        error_preamble = LicensePreamble(
            msg_type=LicenseMsgType.ERROR_ALERT,
            flags=0x03,
            msg_size=len(error_body) + 4,
        ).serialize()
        error_pdu_data = error_preamble + error_body

        recv_fn = AsyncMock(side_effect=[license_pdu_data, error_pdu_data])
        send_fn = AsyncMock()

        await handler.handle_licensing(recv_fn, send_fn)

        # Verify a response was sent
        assert send_fn.call_count == 1
        sent_data = send_fn.call_args[0][0]

        # Parse the sent response preamble
        sent_preamble = LicensePreamble.parse(sent_data[:4])
        assert sent_preamble.msg_type == LicenseMsgType.NEW_LICENSE_REQUEST

        # Parse the New License Request body
        sent_body = sent_data[4:]
        new_req = NewLicenseRequestPdu.parse(sent_body)
        assert new_req.key_exchange_alg == 0x00000001
        assert len(new_req.client_random) == 32
        assert len(new_req.encrypted_premaster_secret) == 48
        assert b"admin" in new_req.client_username
        assert b"workstation" in new_req.client_machine_name

        assert handler.licensing_complete is True


# ============================================================
# LicensingHandler Tests — Platform Challenge
# ============================================================


class TestLicensingHandlerPlatformChallenge:
    """Tests for Platform Challenge → Challenge Response (Req 6, AC 2)."""

    @pytest.mark.asyncio
    async def test_platform_challenge_sends_response(self) -> None:
        """Platform Challenge triggers a Challenge Response."""
        handler = LicensingHandler(username="user", machine_name="pc")

        # Build a Platform Challenge PDU
        challenge = PlatformChallengePdu(
            mac_data=b"\xBB" * 16,
            encrypted_challenge=b"\x42" * 10,
        )
        challenge_body = challenge.serialize()

        preamble = LicensePreamble(
            msg_type=LicenseMsgType.PLATFORM_CHALLENGE,
            flags=0x03,
            msg_size=len(challenge_body) + 4,
        ).serialize()

        challenge_pdu_data = preamble + challenge_body

        # After challenge response, server sends STATUS_VALID_CLIENT
        error_body = LicenseErrorPdu(
            error_code=LicenseErrorCode.STATUS_VALID_CLIENT,
            state_transition=LicenseStateTransition.ST_NO_TRANSITION,
            error_info=b"",
        ).serialize()
        error_preamble = LicensePreamble(
            msg_type=LicenseMsgType.ERROR_ALERT,
            flags=0x03,
            msg_size=len(error_body) + 4,
        ).serialize()
        error_pdu_data = error_preamble + error_body

        recv_fn = AsyncMock(side_effect=[challenge_pdu_data, error_pdu_data])
        send_fn = AsyncMock()

        await handler.handle_licensing(recv_fn, send_fn)

        # Verify a response was sent
        assert send_fn.call_count == 1
        sent_data = send_fn.call_args[0][0]

        # Parse the sent response preamble
        sent_preamble = LicensePreamble.parse(sent_data[:4])
        assert sent_preamble.msg_type == LicenseMsgType.PLATFORM_CHALLENGE_RESPONSE

        # Parse the response body
        sent_body = sent_data[4:]
        response = PlatformChallengeResponsePdu.parse(sent_body)
        assert len(response.mac_data) == 16
        assert len(response.encrypted_response) > 0

        assert handler.licensing_complete is True


# ============================================================
# LicensingHandler Tests — Full Exchange Flow
# ============================================================


class TestLicensingHandlerFullExchange:
    """Tests for the full licensing exchange flow."""

    @pytest.mark.asyncio
    async def test_full_exchange_flow(self) -> None:
        """Full exchange: License Request → Platform Challenge → NEW_LICENSE."""
        handler = LicensingHandler(username="admin", machine_name="desktop")

        # Step 1: Server sends LICENSE_REQUEST
        product_info = struct.pack("<I", 1)
        company = b"T\x00e\x00s\x00t\x00\x00\x00"
        product_info += struct.pack("<I", len(company)) + company
        product_id = b"P\x00\x00\x00"
        product_info += struct.pack("<I", len(product_id)) + product_id

        license_req = LicenseRequestPdu(
            server_random=b"\x11" * 32,
            product_info=product_info,
            key_exchange_list=b"\x01\x00\x00\x00",
            server_certificate=b"\xCA\xFE" * 8,
            scope_list=b"",
        )
        license_req_body = license_req.serialize()
        license_preamble = LicensePreamble(
            msg_type=LicenseMsgType.LICENSE_REQUEST,
            flags=0x03,
            msg_size=len(license_req_body) + 4,
        ).serialize()
        license_pdu = license_preamble + license_req_body

        # Step 2: Server sends PLATFORM_CHALLENGE
        challenge = PlatformChallengePdu(
            mac_data=b"\xCC" * 16,
            encrypted_challenge=b"\xDD" * 8,
        )
        challenge_body = challenge.serialize()
        challenge_preamble = LicensePreamble(
            msg_type=LicenseMsgType.PLATFORM_CHALLENGE,
            flags=0x03,
            msg_size=len(challenge_body) + 4,
        ).serialize()
        challenge_pdu = challenge_preamble + challenge_body

        # Step 3: Server sends NEW_LICENSE (licensing complete)
        # NEW_LICENSE is just a preamble with msg_type=0x03 and some body
        new_license_body = b"\x00" * 8  # minimal body
        new_license_preamble = LicensePreamble(
            msg_type=LicenseMsgType.NEW_LICENSE,
            flags=0x03,
            msg_size=len(new_license_body) + 4,
        ).serialize()
        new_license_pdu = new_license_preamble + new_license_body

        recv_fn = AsyncMock(side_effect=[license_pdu, challenge_pdu, new_license_pdu])
        send_fn = AsyncMock()

        await handler.handle_licensing(recv_fn, send_fn)

        # Client should have sent 2 responses: New License Request + Challenge Response
        assert send_fn.call_count == 2

        # First response: NEW_LICENSE_REQUEST
        first_sent = send_fn.call_args_list[0][0][0]
        first_preamble = LicensePreamble.parse(first_sent[:4])
        assert first_preamble.msg_type == LicenseMsgType.NEW_LICENSE_REQUEST

        # Second response: PLATFORM_CHALLENGE_RESPONSE
        second_sent = send_fn.call_args_list[1][0][0]
        second_preamble = LicensePreamble.parse(second_sent[:4])
        assert second_preamble.msg_type == LicenseMsgType.PLATFORM_CHALLENGE_RESPONSE

        assert handler.licensing_complete is True

    @pytest.mark.asyncio
    async def test_new_license_completes_licensing(self) -> None:
        """NEW_LICENSE message type completes licensing (Req 6, AC 3)."""
        handler = LicensingHandler()

        new_license_body = b"\x00" * 8
        preamble = LicensePreamble(
            msg_type=LicenseMsgType.NEW_LICENSE,
            flags=0x03,
            msg_size=len(new_license_body) + 4,
        ).serialize()
        pdu_data = preamble + new_license_body

        recv_fn = AsyncMock(return_value=pdu_data)
        send_fn = AsyncMock()

        await handler.handle_licensing(recv_fn, send_fn)

        assert handler.licensing_complete is True
        send_fn.assert_not_called()

    @pytest.mark.asyncio
    async def test_upgrade_license_completes_licensing(self) -> None:
        """UPGRADE_LICENSE message type completes licensing."""
        handler = LicensingHandler()

        upgrade_body = b"\x00" * 8
        preamble = LicensePreamble(
            msg_type=LicenseMsgType.UPGRADE_LICENSE,
            flags=0x03,
            msg_size=len(upgrade_body) + 4,
        ).serialize()
        pdu_data = preamble + upgrade_body

        recv_fn = AsyncMock(return_value=pdu_data)
        send_fn = AsyncMock()

        await handler.handle_licensing(recv_fn, send_fn)

        assert handler.licensing_complete is True
        send_fn.assert_not_called()

    @pytest.mark.asyncio
    async def test_unexpected_message_type_raises(self) -> None:
        """Unexpected message type raises PduParseError."""
        handler = LicensingHandler()

        # Use LICENSE_INFO (0x12) which is not handled by the client
        body = b"\x00" * 8
        preamble = LicensePreamble(
            msg_type=LicenseMsgType.LICENSE_INFO,
            flags=0x03,
            msg_size=len(body) + 4,
        ).serialize()
        pdu_data = preamble + body

        recv_fn = AsyncMock(return_value=pdu_data)
        send_fn = AsyncMock()

        with pytest.raises(PduParseError, match="unexpected licensing message type"):
            await handler.handle_licensing(recv_fn, send_fn)
