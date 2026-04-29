"""X.224 / TPKT transport layer for RDP connection negotiation.

Implements TPKT framing (RFC 1006) and X.224 connection-oriented transport
for the initial RDP protocol negotiation phase per [MS-RDPBCGR] 2.2.1.1–2.2.1.2.

Requirements addressed: Req 1 (AC 1–4)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from arrdipi.errors import NegotiationFailureError
from arrdipi.pdu.types import NegotiationProtocol
from arrdipi.transport.tcp import TcpTransport

# TPKT constants (RFC 1006)
TPKT_VERSION = 3
TPKT_HEADER_SIZE = 4

# X.224 TPDU type codes
X224_TPDU_CONNECTION_REQUEST = 0xE0
X224_TPDU_CONNECTION_CONFIRM = 0xD0
X224_TPDU_DATA = 0xF0

# RDP Negotiation type codes [MS-RDPBCGR] 2.2.1.1.1 / 2.2.1.2.1
NEG_TYPE_REQUEST = 0x01
NEG_TYPE_RESPONSE = 0x02
NEG_TYPE_FAILURE = 0x03

# Negotiation structure length (always 8 bytes)
NEG_STRUCTURE_LENGTH = 8

# X.224 Data TPDU header: length indicator (2), DT code (0xF0), EOT (0x80)
X224_DATA_HEADER = bytes([0x02, X224_TPDU_DATA, 0x80])

# Failure code descriptions [MS-RDPBCGR] 2.2.1.2.2
FAILURE_CODE_DESCRIPTIONS: dict[int, str] = {
    0x00000001: "SSL_REQUIRED_BY_SERVER",
    0x00000002: "SSL_NOT_ALLOWED_BY_SERVER",
    0x00000003: "SSL_CERT_NOT_ON_SERVER",
    0x00000004: "INCONSISTENT_FLAGS",
    0x00000005: "HYBRID_REQUIRED_BY_SERVER",
    0x00000006: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
}


def encode_tpkt(payload: bytes) -> bytes:
    """Encode a payload into a TPKT frame.

    TPKT header (4 bytes): version (u8=3), reserved (u8=0), length (u16 BE).
    Length includes the 4-byte TPKT header itself.

    Args:
        payload: The data to frame.

    Returns:
        TPKT-framed bytes.
    """
    total_length = TPKT_HEADER_SIZE + len(payload)
    header = struct.pack(">BBH", TPKT_VERSION, 0, total_length)
    return header + payload


def decode_tpkt_header(data: bytes) -> int:
    """Decode a 4-byte TPKT header and return the total packet length.

    Args:
        data: Exactly 4 bytes of TPKT header.

    Returns:
        Total packet length (including the 4-byte header).

    Raises:
        ValueError: If the version byte is not 3.
    """
    if len(data) < TPKT_HEADER_SIZE:
        msg = f"TPKT header requires 4 bytes, got {len(data)}"
        raise ValueError(msg)

    version, reserved, length = struct.unpack(">BBH", data[:TPKT_HEADER_SIZE])
    if version != TPKT_VERSION:
        msg = f"Invalid TPKT version: expected {TPKT_VERSION}, got {version}"
        raise ValueError(msg)

    return length


@dataclass
class X224ConnectionRequest:
    """X.224 Connection Request PDU [MS-RDPBCGR] 2.2.1.1.

    Contains the cookie and RDP Negotiation Request with protocol flags.

    Attributes:
        cookie: RDP cookie string (e.g., "Cookie: mstshash=user\\r\\n").
        requested_protocols: Protocol flags to request from the server.
    """

    cookie: str
    requested_protocols: NegotiationProtocol

    def serialize(self) -> bytes:
        """Serialize the Connection Request into a TPKT-framed PDU.

        Structure:
        - TPKT header (4 bytes)
        - X.224 CR header: LI (u8), CR code (0xE0), dst-ref (u16 BE=0),
          src-ref (u16 BE=0), class options (u8=0)
        - Cookie: "Cookie: mstshash=<username>\\r\\n"
        - RDP Negotiation Request: type (u8=0x01), flags (u8=0),
          length (u16 LE=8), requestedProtocols (u32 LE)
        """
        # Build the X.224 payload (after the length indicator)
        x224_payload = bytearray()

        # CR TPDU code (upper nibble = 0xE, lower nibble = 0) + CDT
        x224_payload.append(X224_TPDU_CONNECTION_REQUEST)
        # dst-ref (u16 BE = 0)
        x224_payload.extend(struct.pack(">H", 0))
        # src-ref (u16 BE = 0)
        x224_payload.extend(struct.pack(">H", 0))
        # class options (u8 = 0)
        x224_payload.append(0)

        # Cookie
        cookie_bytes = self.cookie.encode("ascii")
        x224_payload.extend(cookie_bytes)

        # RDP Negotiation Request
        x224_payload.append(NEG_TYPE_REQUEST)  # type
        x224_payload.append(0)  # flags
        x224_payload.extend(struct.pack("<H", NEG_STRUCTURE_LENGTH))  # length (LE)
        x224_payload.extend(
            struct.pack("<I", int(self.requested_protocols))
        )  # requestedProtocols (LE)

        # Length indicator = number of bytes following the LI field
        length_indicator = len(x224_payload)

        # Assemble: LI + x224_payload
        tpkt_payload = bytes([length_indicator]) + bytes(x224_payload)

        return encode_tpkt(tpkt_payload)


@dataclass
class X224ConnectionConfirm:
    """X.224 Connection Confirm PDU [MS-RDPBCGR] 2.2.1.2.

    Contains the selected protocol from the RDP Negotiation Response.

    Attributes:
        selected_protocol: The protocol selected by the server.
        flags: Negotiation response flags.
    """

    selected_protocol: NegotiationProtocol
    flags: int

    @classmethod
    def parse(cls, data: bytes) -> X224ConnectionConfirm:
        """Parse a Connection Confirm from the TPKT payload (after TPKT header).

        Expected structure:
        - X.224 CC header: LI (u8), CC code (0xD0), dst-ref (u16 BE),
          src-ref (u16 BE), class options (u8)
        - RDP Negotiation Response: type (u8=0x02), flags (u8),
          length (u16 LE=8), selectedProtocol (u32 LE)

        Args:
            data: The TPKT payload bytes (everything after the 4-byte TPKT header).

        Returns:
            Parsed X224ConnectionConfirm instance.

        Raises:
            NegotiationFailureError: If the response contains a Negotiation Failure.
            ValueError: If the data is malformed.
        """
        if len(data) < 7:
            msg = "X.224 Connection Confirm too short"
            raise ValueError(msg)

        offset = 0
        # Length indicator
        _li = data[offset]
        offset += 1

        # CC TPDU code
        tpdu_code = data[offset] & 0xF0
        offset += 1

        if tpdu_code != X224_TPDU_CONNECTION_CONFIRM:
            msg = f"Expected CC TPDU (0xD0), got 0x{tpdu_code:02X}"
            raise ValueError(msg)

        # dst-ref (u16 BE)
        offset += 2
        # src-ref (u16 BE)
        offset += 2
        # class options (u8)
        offset += 1

        # Check for RDP Negotiation Response or Failure
        if offset >= len(data):
            # No negotiation data — default to PROTOCOL_RDP
            return cls(
                selected_protocol=NegotiationProtocol.PROTOCOL_RDP,
                flags=0,
            )

        neg_type = data[offset]
        offset += 1

        if neg_type == NEG_TYPE_FAILURE:
            # Parse failure
            failure = X224NegotiationFailure.parse(data[offset - 1 :])
            description = FAILURE_CODE_DESCRIPTIONS.get(
                failure.failure_code, f"UNKNOWN_FAILURE_CODE_0x{failure.failure_code:08X}"
            )
            raise NegotiationFailureError(
                failure_code=failure.failure_code,
                description=description,
            )

        if neg_type != NEG_TYPE_RESPONSE:
            msg = f"Expected negotiation response type 0x02, got 0x{neg_type:02X}"
            raise ValueError(msg)

        # flags (u8)
        flags = data[offset]
        offset += 1

        # length (u16 LE) — should be 8
        _neg_length = struct.unpack_from("<H", data, offset)[0]
        offset += 2

        # selectedProtocol (u32 LE)
        selected_protocol_value = struct.unpack_from("<I", data, offset)[0]

        return cls(
            selected_protocol=NegotiationProtocol(selected_protocol_value),
            flags=flags,
        )


@dataclass
class X224NegotiationFailure:
    """X.224 Negotiation Failure [MS-RDPBCGR] 2.2.1.2.2.

    Attributes:
        failure_code: The failure code from the server.
    """

    failure_code: int

    @classmethod
    def parse(cls, data: bytes) -> X224NegotiationFailure:
        """Parse a Negotiation Failure structure.

        Structure: type (u8=0x03), flags (u8), length (u16 LE=8), failureCode (u32 LE)

        Args:
            data: Bytes starting at the negotiation type field.

        Returns:
            Parsed X224NegotiationFailure instance.

        Raises:
            ValueError: If the data is too short.
        """
        if len(data) < NEG_STRUCTURE_LENGTH:
            msg = f"Negotiation Failure requires {NEG_STRUCTURE_LENGTH} bytes, got {len(data)}"
            raise ValueError(msg)

        offset = 0
        neg_type = data[offset]
        offset += 1

        if neg_type != NEG_TYPE_FAILURE:
            msg = f"Expected negotiation failure type 0x03, got 0x{neg_type:02X}"
            raise ValueError(msg)

        # flags (u8)
        offset += 1
        # length (u16 LE)
        offset += 2
        # failureCode (u32 LE)
        failure_code = struct.unpack_from("<I", data, offset)[0]

        return cls(failure_code=failure_code)

    @property
    def description(self) -> str:
        """Human-readable description of the failure code."""
        return FAILURE_CODE_DESCRIPTIONS.get(
            self.failure_code,
            f"UNKNOWN_FAILURE_CODE_0x{self.failure_code:08X}",
        )


class X224Layer:
    """X.224 / TPKT transport layer for RDP.

    Handles TPKT framing and X.224 connection negotiation. Upper layers
    use send_pdu/recv_pdu for transparent TPKT-framed data exchange.

    Args:
        tcp: The underlying TCP transport.
    """

    def __init__(self, tcp: TcpTransport) -> None:
        self._tcp = tcp

    async def negotiate(
        self, cookie: str, requested_protocols: NegotiationProtocol
    ) -> NegotiationProtocol:
        """Perform X.224 connection negotiation.

        Sends a Connection Request PDU and receives a Connection Confirm
        or Negotiation Failure from the server.

        Args:
            cookie: RDP cookie (e.g., "Cookie: mstshash=user\\r\\n").
            requested_protocols: Protocol flags to request.

        Returns:
            The protocol selected by the server.

        Raises:
            NegotiationFailureError: If the server responds with a failure
                (Req 1, AC 4).
        """
        # Build and send Connection Request
        request = X224ConnectionRequest(
            cookie=cookie,
            requested_protocols=requested_protocols,
        )
        await self._tcp.send(request.serialize())

        # Receive Connection Confirm
        # Read TPKT header first (4 bytes)
        header_data = await self._tcp.recv(TPKT_HEADER_SIZE)
        total_length = decode_tpkt_header(header_data)

        # Read remaining payload
        payload_length = total_length - TPKT_HEADER_SIZE
        payload = await self._tcp.recv(payload_length)

        # Parse the Connection Confirm (raises NegotiationFailureError on failure)
        confirm = X224ConnectionConfirm.parse(payload)
        return confirm.selected_protocol

    async def send_pdu(self, data: bytes) -> None:
        """Send data wrapped in a TPKT frame with X.224 Data TPDU header.

        The X.224 Data TPDU header is: LI=2, DT code=0xF0, EOT=0x80.

        Args:
            data: The payload to send.
        """
        # X.224 Data TPDU: header (3 bytes) + payload
        tpdu = X224_DATA_HEADER + data
        frame = encode_tpkt(tpdu)
        await self._tcp.send(frame)

    async def recv_pdu(self) -> bytes:
        """Receive a TPKT frame, strip the X.224 Data TPDU header, return payload.

        Returns:
            The payload bytes after stripping TPKT and X.224 Data headers.
        """
        # Read TPKT header (4 bytes)
        header_data = await self._tcp.recv(TPKT_HEADER_SIZE)
        total_length = decode_tpkt_header(header_data)

        # Read remaining data
        payload_length = total_length - TPKT_HEADER_SIZE
        payload = await self._tcp.recv(payload_length)

        # Strip X.224 Data TPDU header (3 bytes: LI, DT code, EOT)
        if len(payload) < 3:
            msg = "X.224 Data TPDU too short"
            raise ValueError(msg)

        # Verify it's a Data TPDU
        li = payload[0]
        tpdu_code = payload[1] & 0xF0
        if tpdu_code != X224_TPDU_DATA:
            msg = f"Expected Data TPDU (0xF0), got 0x{tpdu_code:02X}"
            raise ValueError(msg)

        # Return payload after the X.224 Data header
        # LI tells us the header length (excluding LI byte itself)
        header_size = li + 1  # LI byte + LI value bytes
        return payload[header_size:]
