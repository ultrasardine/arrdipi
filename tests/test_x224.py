"""Tests for X.224 / TPKT transport layer.

Tests cover:
- TPKT header encode/decode
- X224ConnectionRequest serialize round-trip
- X224ConnectionConfirm parse
- X224NegotiationFailure parse and description mapping
- X224Layer negotiate (success and failure paths)
- X224Layer send_pdu / recv_pdu for Data TPDUs
"""

from __future__ import annotations

import struct
from unittest.mock import AsyncMock, MagicMock

import pytest

from arrdipi.errors import NegotiationFailureError
from arrdipi.pdu.types import NegotiationProtocol
from arrdipi.transport.tcp import TcpTransport
from arrdipi.transport.x224 import (
    FAILURE_CODE_DESCRIPTIONS,
    NEG_STRUCTURE_LENGTH,
    NEG_TYPE_FAILURE,
    NEG_TYPE_REQUEST,
    NEG_TYPE_RESPONSE,
    TPKT_HEADER_SIZE,
    TPKT_VERSION,
    X224ConnectionConfirm,
    X224ConnectionRequest,
    X224Layer,
    X224NegotiationFailure,
    X224_DATA_HEADER,
    X224_TPDU_CONNECTION_CONFIRM,
    X224_TPDU_DATA,
    decode_tpkt_header,
    encode_tpkt,
)


# --- TPKT encode/decode tests ---


class TestTpktEncoding:
    """Tests for TPKT header encode and decode."""

    def test_encode_tpkt_empty_payload(self):
        """TPKT with empty payload has length 4 (header only)."""
        result = encode_tpkt(b"")
        assert result == b"\x03\x00\x00\x04"

    def test_encode_tpkt_with_payload(self):
        """TPKT length includes header + payload."""
        payload = b"\x01\x02\x03"
        result = encode_tpkt(payload)
        # Total length = 4 (header) + 3 (payload) = 7
        expected_header = struct.pack(">BBH", 3, 0, 7)
        assert result == expected_header + payload

    def test_decode_tpkt_header_valid(self):
        """Decode a valid TPKT header returns total length."""
        header = struct.pack(">BBH", 3, 0, 100)
        assert decode_tpkt_header(header) == 100

    def test_decode_tpkt_header_invalid_version(self):
        """Decode raises ValueError for non-3 version."""
        header = struct.pack(">BBH", 2, 0, 50)
        with pytest.raises(ValueError, match="Invalid TPKT version"):
            decode_tpkt_header(header)

    def test_decode_tpkt_header_too_short(self):
        """Decode raises ValueError for data shorter than 4 bytes."""
        with pytest.raises(ValueError, match="requires 4 bytes"):
            decode_tpkt_header(b"\x03\x00")

    def test_encode_decode_round_trip(self):
        """Encoding then decoding the header gives the correct length."""
        payload = b"A" * 200
        frame = encode_tpkt(payload)
        length = decode_tpkt_header(frame[:4])
        assert length == TPKT_HEADER_SIZE + len(payload)
        assert frame[4:] == payload


# --- X224ConnectionRequest tests ---


class TestX224ConnectionRequest:
    """Tests for X224ConnectionRequest serialization."""

    def test_serialize_basic(self):
        """Serialize a basic Connection Request with SSL protocol."""
        req = X224ConnectionRequest(
            cookie="Cookie: mstshash=testuser\r\n",
            requested_protocols=NegotiationProtocol.PROTOCOL_SSL,
        )
        data = req.serialize()

        # Verify TPKT header
        assert data[0] == TPKT_VERSION
        assert data[1] == 0  # reserved
        total_length = struct.unpack(">H", data[2:4])[0]
        assert total_length == len(data)

        # Verify X.224 CR header
        li = data[4]  # length indicator
        tpdu_code = data[5]
        assert tpdu_code == 0xE0  # CR TPDU

        # dst-ref = 0, src-ref = 0
        dst_ref = struct.unpack(">H", data[6:8])[0]
        src_ref = struct.unpack(">H", data[8:10])[0]
        assert dst_ref == 0
        assert src_ref == 0

        # class options = 0
        assert data[10] == 0

        # Cookie
        cookie_str = "Cookie: mstshash=testuser\r\n"
        cookie_start = 11
        cookie_end = cookie_start + len(cookie_str)
        assert data[cookie_start:cookie_end] == cookie_str.encode("ascii")

        # RDP Negotiation Request
        neg_start = cookie_end
        assert data[neg_start] == NEG_TYPE_REQUEST  # type
        assert data[neg_start + 1] == 0  # flags
        neg_length = struct.unpack_from("<H", data, neg_start + 2)[0]
        assert neg_length == NEG_STRUCTURE_LENGTH
        requested = struct.unpack_from("<I", data, neg_start + 4)[0]
        assert requested == int(NegotiationProtocol.PROTOCOL_SSL)

    def test_serialize_hybrid_protocol(self):
        """Serialize with HYBRID (CredSSP) protocol flag."""
        req = X224ConnectionRequest(
            cookie="Cookie: mstshash=admin\r\n",
            requested_protocols=NegotiationProtocol.PROTOCOL_HYBRID,
        )
        data = req.serialize()

        # Find the negotiation request at the end
        # Last 8 bytes are the negotiation structure
        neg_data = data[-8:]
        assert neg_data[0] == NEG_TYPE_REQUEST
        requested = struct.unpack_from("<I", neg_data, 4)[0]
        assert requested == int(NegotiationProtocol.PROTOCOL_HYBRID)

    def test_serialize_combined_protocols(self):
        """Serialize with combined SSL | HYBRID protocol flags."""
        req = X224ConnectionRequest(
            cookie="Cookie: mstshash=user\r\n",
            requested_protocols=NegotiationProtocol.PROTOCOL_SSL
            | NegotiationProtocol.PROTOCOL_HYBRID,
        )
        data = req.serialize()

        neg_data = data[-8:]
        requested = struct.unpack_from("<I", neg_data, 4)[0]
        assert requested == (
            int(NegotiationProtocol.PROTOCOL_SSL)
            | int(NegotiationProtocol.PROTOCOL_HYBRID)
        )

    def test_serialize_length_indicator_correct(self):
        """Length indicator equals the number of bytes following it."""
        req = X224ConnectionRequest(
            cookie="Cookie: mstshash=x\r\n",
            requested_protocols=NegotiationProtocol.PROTOCOL_RDP,
        )
        data = req.serialize()

        li = data[4]
        # Everything after TPKT header (4 bytes) and LI byte (1 byte)
        # should have length == li
        payload_after_li = data[5:]
        assert li == len(payload_after_li)


# --- X224ConnectionConfirm tests ---


class TestX224ConnectionConfirm:
    """Tests for X224ConnectionConfirm parsing."""

    def _build_confirm_payload(
        self, selected_protocol: int, flags: int = 0
    ) -> bytes:
        """Build a Connection Confirm TPKT payload (after TPKT header)."""
        # X.224 CC header
        x224_header = bytearray()
        x224_header.append(X224_TPDU_CONNECTION_CONFIRM)  # CC code
        x224_header.extend(struct.pack(">H", 0))  # dst-ref
        x224_header.extend(struct.pack(">H", 0))  # src-ref
        x224_header.append(0)  # class options

        # RDP Negotiation Response
        neg_response = bytearray()
        neg_response.append(NEG_TYPE_RESPONSE)  # type
        neg_response.append(flags)  # flags
        neg_response.extend(struct.pack("<H", NEG_STRUCTURE_LENGTH))  # length
        neg_response.extend(struct.pack("<I", selected_protocol))  # selectedProtocol

        # Combine with LI
        payload = bytes(x224_header) + bytes(neg_response)
        li = len(payload)
        return bytes([li]) + payload

    def test_parse_ssl_selected(self):
        """Parse a confirm with SSL selected."""
        payload = self._build_confirm_payload(int(NegotiationProtocol.PROTOCOL_SSL))
        confirm = X224ConnectionConfirm.parse(payload)
        assert confirm.selected_protocol == NegotiationProtocol.PROTOCOL_SSL
        assert confirm.flags == 0

    def test_parse_hybrid_selected(self):
        """Parse a confirm with HYBRID selected."""
        payload = self._build_confirm_payload(
            int(NegotiationProtocol.PROTOCOL_HYBRID), flags=0x01
        )
        confirm = X224ConnectionConfirm.parse(payload)
        assert confirm.selected_protocol == NegotiationProtocol.PROTOCOL_HYBRID
        assert confirm.flags == 0x01

    def test_parse_rdp_selected(self):
        """Parse a confirm with standard RDP (no TLS/NLA)."""
        payload = self._build_confirm_payload(int(NegotiationProtocol.PROTOCOL_RDP))
        confirm = X224ConnectionConfirm.parse(payload)
        assert confirm.selected_protocol == NegotiationProtocol.PROTOCOL_RDP

    def test_parse_no_negotiation_data(self):
        """Parse a confirm with no negotiation response defaults to PROTOCOL_RDP."""
        # Just the X.224 CC header, no negotiation data
        x224_header = bytearray()
        x224_header.append(X224_TPDU_CONNECTION_CONFIRM)
        x224_header.extend(struct.pack(">H", 0))  # dst-ref
        x224_header.extend(struct.pack(">H", 0))  # src-ref
        x224_header.append(0)  # class options

        li = len(x224_header)
        payload = bytes([li]) + bytes(x224_header)

        confirm = X224ConnectionConfirm.parse(payload)
        assert confirm.selected_protocol == NegotiationProtocol.PROTOCOL_RDP
        assert confirm.flags == 0

    def test_parse_failure_raises_negotiation_failure_error(self):
        """Parse a confirm with Negotiation Failure raises NegotiationFailureError."""
        # X.224 CC header
        x224_header = bytearray()
        x224_header.append(X224_TPDU_CONNECTION_CONFIRM)
        x224_header.extend(struct.pack(">H", 0))
        x224_header.extend(struct.pack(">H", 0))
        x224_header.append(0)

        # RDP Negotiation Failure
        neg_failure = bytearray()
        neg_failure.append(NEG_TYPE_FAILURE)  # type = 0x03
        neg_failure.append(0)  # flags
        neg_failure.extend(struct.pack("<H", NEG_STRUCTURE_LENGTH))  # length
        neg_failure.extend(struct.pack("<I", 0x00000001))  # SSL_REQUIRED_BY_SERVER

        payload = bytes(x224_header) + bytes(neg_failure)
        li = len(payload)
        full_payload = bytes([li]) + payload

        with pytest.raises(NegotiationFailureError) as exc_info:
            X224ConnectionConfirm.parse(full_payload)

        assert exc_info.value.failure_code == 0x00000001
        assert exc_info.value.description == "SSL_REQUIRED_BY_SERVER"

    def test_parse_too_short_raises_value_error(self):
        """Parse raises ValueError for truncated data."""
        with pytest.raises(ValueError, match="too short"):
            X224ConnectionConfirm.parse(b"\x02\xD0\x00")


# --- X224NegotiationFailure tests ---


class TestX224NegotiationFailure:
    """Tests for X224NegotiationFailure parsing and description."""

    def test_parse_ssl_required(self):
        """Parse SSL_REQUIRED_BY_SERVER failure code."""
        data = bytearray()
        data.append(NEG_TYPE_FAILURE)
        data.append(0)  # flags
        data.extend(struct.pack("<H", NEG_STRUCTURE_LENGTH))
        data.extend(struct.pack("<I", 0x00000001))

        failure = X224NegotiationFailure.parse(bytes(data))
        assert failure.failure_code == 0x00000001
        assert failure.description == "SSL_REQUIRED_BY_SERVER"

    def test_parse_hybrid_required(self):
        """Parse HYBRID_REQUIRED_BY_SERVER failure code."""
        data = bytearray()
        data.append(NEG_TYPE_FAILURE)
        data.append(0)
        data.extend(struct.pack("<H", NEG_STRUCTURE_LENGTH))
        data.extend(struct.pack("<I", 0x00000005))

        failure = X224NegotiationFailure.parse(bytes(data))
        assert failure.failure_code == 0x00000005
        assert failure.description == "HYBRID_REQUIRED_BY_SERVER"

    def test_parse_unknown_failure_code(self):
        """Unknown failure code produces a hex description."""
        data = bytearray()
        data.append(NEG_TYPE_FAILURE)
        data.append(0)
        data.extend(struct.pack("<H", NEG_STRUCTURE_LENGTH))
        data.extend(struct.pack("<I", 0x000000FF))

        failure = X224NegotiationFailure.parse(bytes(data))
        assert failure.failure_code == 0x000000FF
        assert "UNKNOWN" in failure.description
        assert "000000FF" in failure.description

    def test_parse_too_short_raises_value_error(self):
        """Parse raises ValueError for data shorter than 8 bytes."""
        with pytest.raises(ValueError, match="requires 8 bytes"):
            X224NegotiationFailure.parse(b"\x03\x00\x08\x00")

    def test_parse_wrong_type_raises_value_error(self):
        """Parse raises ValueError for wrong negotiation type."""
        data = bytearray()
        data.append(0x02)  # wrong type (response, not failure)
        data.append(0)
        data.extend(struct.pack("<H", NEG_STRUCTURE_LENGTH))
        data.extend(struct.pack("<I", 0x00000001))

        with pytest.raises(ValueError, match="Expected negotiation failure"):
            X224NegotiationFailure.parse(bytes(data))

    def test_all_failure_codes_have_descriptions(self):
        """All defined failure codes map to descriptions."""
        for code in range(1, 7):
            assert code in FAILURE_CODE_DESCRIPTIONS


# --- X224Layer tests ---


def _make_mock_tcp() -> TcpTransport:
    """Create a mock TcpTransport for testing."""
    mock_tcp = MagicMock(spec=TcpTransport)
    mock_tcp.send = AsyncMock()
    mock_tcp.recv = AsyncMock()
    return mock_tcp


class TestX224LayerNegotiate:
    """Tests for X224Layer.negotiate()."""

    @pytest.mark.asyncio
    async def test_negotiate_success_ssl(self):
        """Successful negotiation returns the selected protocol."""
        mock_tcp = _make_mock_tcp()

        # Build the Connection Confirm response
        x224_header = bytearray()
        x224_header.append(X224_TPDU_CONNECTION_CONFIRM)
        x224_header.extend(struct.pack(">H", 0))
        x224_header.extend(struct.pack(">H", 0))
        x224_header.append(0)

        neg_response = bytearray()
        neg_response.append(NEG_TYPE_RESPONSE)
        neg_response.append(0)
        neg_response.extend(struct.pack("<H", NEG_STRUCTURE_LENGTH))
        neg_response.extend(struct.pack("<I", int(NegotiationProtocol.PROTOCOL_SSL)))

        payload = bytes(x224_header) + bytes(neg_response)
        li = len(payload)
        tpkt_payload = bytes([li]) + payload
        total_length = TPKT_HEADER_SIZE + len(tpkt_payload)
        tpkt_header = struct.pack(">BBH", TPKT_VERSION, 0, total_length)

        # Mock recv: first call returns TPKT header, second returns payload
        mock_tcp.recv = AsyncMock(side_effect=[tpkt_header, tpkt_payload])

        layer = X224Layer(mock_tcp)
        result = await layer.negotiate(
            cookie="Cookie: mstshash=user\r\n",
            requested_protocols=NegotiationProtocol.PROTOCOL_SSL,
        )

        assert result == NegotiationProtocol.PROTOCOL_SSL
        # Verify send was called with the serialized request
        mock_tcp.send.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_negotiate_failure_raises_error(self):
        """Negotiation failure raises NegotiationFailureError."""
        mock_tcp = _make_mock_tcp()

        # Build a Negotiation Failure response
        x224_header = bytearray()
        x224_header.append(X224_TPDU_CONNECTION_CONFIRM)
        x224_header.extend(struct.pack(">H", 0))
        x224_header.extend(struct.pack(">H", 0))
        x224_header.append(0)

        neg_failure = bytearray()
        neg_failure.append(NEG_TYPE_FAILURE)
        neg_failure.append(0)
        neg_failure.extend(struct.pack("<H", NEG_STRUCTURE_LENGTH))
        neg_failure.extend(struct.pack("<I", 0x00000005))  # HYBRID_REQUIRED

        payload = bytes(x224_header) + bytes(neg_failure)
        li = len(payload)
        tpkt_payload = bytes([li]) + payload
        total_length = TPKT_HEADER_SIZE + len(tpkt_payload)
        tpkt_header = struct.pack(">BBH", TPKT_VERSION, 0, total_length)

        mock_tcp.recv = AsyncMock(side_effect=[tpkt_header, tpkt_payload])

        layer = X224Layer(mock_tcp)

        with pytest.raises(NegotiationFailureError) as exc_info:
            await layer.negotiate(
                cookie="Cookie: mstshash=user\r\n",
                requested_protocols=NegotiationProtocol.PROTOCOL_HYBRID,
            )

        assert exc_info.value.failure_code == 0x00000005
        assert "HYBRID_REQUIRED_BY_SERVER" in exc_info.value.description

    @pytest.mark.asyncio
    async def test_negotiate_sends_correct_request(self):
        """negotiate() sends a properly formatted Connection Request."""
        mock_tcp = _make_mock_tcp()

        # Build a simple success response
        x224_header = bytearray()
        x224_header.append(X224_TPDU_CONNECTION_CONFIRM)
        x224_header.extend(struct.pack(">H", 0))
        x224_header.extend(struct.pack(">H", 0))
        x224_header.append(0)

        neg_response = bytearray()
        neg_response.append(NEG_TYPE_RESPONSE)
        neg_response.append(0)
        neg_response.extend(struct.pack("<H", NEG_STRUCTURE_LENGTH))
        neg_response.extend(struct.pack("<I", int(NegotiationProtocol.PROTOCOL_SSL)))

        payload = bytes(x224_header) + bytes(neg_response)
        li = len(payload)
        tpkt_payload = bytes([li]) + payload
        total_length = TPKT_HEADER_SIZE + len(tpkt_payload)
        tpkt_header = struct.pack(">BBH", TPKT_VERSION, 0, total_length)

        mock_tcp.recv = AsyncMock(side_effect=[tpkt_header, tpkt_payload])

        layer = X224Layer(mock_tcp)
        await layer.negotiate(
            cookie="Cookie: mstshash=admin\r\n",
            requested_protocols=NegotiationProtocol.PROTOCOL_SSL,
        )

        # Verify the sent data is a valid TPKT frame
        sent_data = mock_tcp.send.call_args[0][0]
        assert sent_data[0] == TPKT_VERSION
        assert sent_data[1] == 0
        sent_length = struct.unpack(">H", sent_data[2:4])[0]
        assert sent_length == len(sent_data)


class TestX224LayerDataPdu:
    """Tests for X224Layer.send_pdu() and recv_pdu()."""

    @pytest.mark.asyncio
    async def test_send_pdu_wraps_in_tpkt_and_data_header(self):
        """send_pdu wraps payload in TPKT + X.224 Data TPDU header."""
        mock_tcp = _make_mock_tcp()
        layer = X224Layer(mock_tcp)

        payload = b"\x01\x02\x03\x04\x05"
        await layer.send_pdu(payload)

        sent_data = mock_tcp.send.call_args[0][0]

        # Verify TPKT header
        assert sent_data[0] == TPKT_VERSION
        assert sent_data[1] == 0
        total_length = struct.unpack(">H", sent_data[2:4])[0]
        # 4 (TPKT) + 3 (X.224 Data header) + 5 (payload) = 12
        assert total_length == 12
        assert total_length == len(sent_data)

        # Verify X.224 Data TPDU header
        assert sent_data[4] == 0x02  # LI = 2
        assert sent_data[5] == 0xF0  # DT TPDU code
        assert sent_data[6] == 0x80  # EOT

        # Verify payload
        assert sent_data[7:] == payload

    @pytest.mark.asyncio
    async def test_recv_pdu_strips_tpkt_and_data_header(self):
        """recv_pdu strips TPKT and X.224 Data TPDU header, returns payload."""
        mock_tcp = _make_mock_tcp()
        layer = X224Layer(mock_tcp)

        payload = b"\xAA\xBB\xCC\xDD"
        # Build the full frame: TPKT + X.224 Data header + payload
        data_header = X224_DATA_HEADER  # [0x02, 0xF0, 0x80]
        tpkt_payload = data_header + payload
        total_length = TPKT_HEADER_SIZE + len(tpkt_payload)
        tpkt_header = struct.pack(">BBH", TPKT_VERSION, 0, total_length)

        mock_tcp.recv = AsyncMock(
            side_effect=[tpkt_header, tpkt_payload]
        )

        result = await layer.recv_pdu()
        assert result == payload

    @pytest.mark.asyncio
    async def test_send_recv_round_trip(self):
        """Data sent via send_pdu can be received via recv_pdu."""
        mock_tcp = _make_mock_tcp()
        layer = X224Layer(mock_tcp)

        original_payload = b"Hello, RDP!"

        # Send
        await layer.send_pdu(original_payload)
        sent_frame = mock_tcp.send.call_args[0][0]

        # Simulate receiving the same frame
        mock_tcp.recv = AsyncMock(
            side_effect=[sent_frame[:4], sent_frame[4:]]
        )

        # Receive
        received_payload = await layer.recv_pdu()
        assert received_payload == original_payload

    @pytest.mark.asyncio
    async def test_recv_pdu_invalid_tpdu_code_raises(self):
        """recv_pdu raises ValueError for non-Data TPDU code."""
        mock_tcp = _make_mock_tcp()
        layer = X224Layer(mock_tcp)

        # Build a frame with wrong TPDU code (0xE0 = CR instead of 0xF0 = DT)
        bad_payload = bytes([0x02, 0xE0, 0x80]) + b"\x01\x02"
        total_length = TPKT_HEADER_SIZE + len(bad_payload)
        tpkt_header = struct.pack(">BBH", TPKT_VERSION, 0, total_length)

        mock_tcp.recv = AsyncMock(side_effect=[tpkt_header, bad_payload])

        with pytest.raises(ValueError, match="Expected Data TPDU"):
            await layer.recv_pdu()

    @pytest.mark.asyncio
    async def test_recv_pdu_too_short_raises(self):
        """recv_pdu raises ValueError for payload shorter than 3 bytes."""
        mock_tcp = _make_mock_tcp()
        layer = X224Layer(mock_tcp)

        # Only 2 bytes of payload (need at least 3 for X.224 Data header)
        bad_payload = bytes([0x02, 0xF0])
        total_length = TPKT_HEADER_SIZE + len(bad_payload)
        tpkt_header = struct.pack(">BBH", TPKT_VERSION, 0, total_length)

        mock_tcp.recv = AsyncMock(side_effect=[tpkt_header, bad_payload])

        with pytest.raises(ValueError, match="too short"):
            await layer.recv_pdu()

    @pytest.mark.asyncio
    async def test_send_pdu_empty_payload(self):
        """send_pdu handles empty payload correctly."""
        mock_tcp = _make_mock_tcp()
        layer = X224Layer(mock_tcp)

        await layer.send_pdu(b"")

        sent_data = mock_tcp.send.call_args[0][0]
        # 4 (TPKT) + 3 (X.224 Data header) + 0 (payload) = 7
        total_length = struct.unpack(">H", sent_data[2:4])[0]
        assert total_length == 7
