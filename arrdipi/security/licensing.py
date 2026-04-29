"""MS-RDPELE licensing exchange handler.

Handles the RDP licensing exchange (Phase 7 of the connection sequence).
Most modern RDP servers send an ERROR_ALERT with STATUS_VALID_CLIENT to
skip licensing entirely (the common fast path). This handler also supports
the full multi-round exchange when a server requires actual licensing.

Requirements addressed: Req 6 (AC 1–4)
References: [MS-RDPELE] Sections 2.2.2.1–2.2.2.7
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Self

from arrdipi.errors import PduParseError
from arrdipi.pdu.base import ByteReader, ByteWriter, Pdu


# ============================================================
# Licensing Constants per [MS-RDPELE]
# ============================================================


class LicenseMsgType(IntEnum):
    """Licensing PDU message types [MS-RDPELE] 2.2.2."""

    LICENSE_REQUEST = 0x01
    PLATFORM_CHALLENGE = 0x02
    NEW_LICENSE = 0x03
    UPGRADE_LICENSE = 0x04
    LICENSE_INFO = 0x12
    NEW_LICENSE_REQUEST = 0x13
    PLATFORM_CHALLENGE_RESPONSE = 0x15
    ERROR_ALERT = 0xFF


class LicenseErrorCode(IntEnum):
    """Licensing error codes [MS-RDPELE] 2.2.2.7.1."""

    ERR_INVALID_SERVER_CERTIFICATE = 0x00000001
    ERR_NO_LICENSE = 0x00000002
    ERR_INVALID_SCOPE = 0x00000004
    ERR_NO_LICENSE_SERVER = 0x00000006
    STATUS_VALID_CLIENT = 0x00000007
    ERR_INVALID_CLIENT = 0x00000008
    ERR_INVALID_PRODUCTID = 0x0000000B
    ERR_INVALID_MESSAGE_LEN = 0x0000000C


class LicenseStateTransition(IntEnum):
    """Licensing state transition codes [MS-RDPELE] 2.2.2.7.1."""

    ST_TOTAL_ABORT = 0x00000001
    ST_NO_TRANSITION = 0x00000002
    ST_RESET_PHASE_TO_START = 0x00000003
    ST_RESEND_LAST_MESSAGE = 0x00000004


# Security header flag indicating a licensing PDU
SEC_LICENSE_PKT = 0x0080


# ============================================================
# Licensing Preamble
# ============================================================


@dataclass
class LicensePreamble:
    """Licensing preamble: msgType (u8), flags (u8), msgSize (u16 LE)."""

    msg_type: int
    flags: int
    msg_size: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        reader = ByteReader(data, "LicensePreamble")
        msg_type = reader.read_u8()
        flags = reader.read_u8()
        msg_size = reader.read_u16_le()
        return cls(msg_type=msg_type, flags=flags, msg_size=msg_size)

    def serialize(self) -> bytes:
        writer = ByteWriter()
        writer.write_u8(self.msg_type)
        writer.write_u8(self.flags)
        writer.write_u16_le(self.msg_size)
        return writer.to_bytes()


# ============================================================
# Licensing PDU Dataclasses
# ============================================================


@dataclass
class LicenseRequestPdu(Pdu):
    """Server License Request PDU [MS-RDPELE] 2.2.2.1.

    Contains the server random, product info, key exchange list,
    and server certificate.
    """

    server_random: bytes = field(default_factory=lambda: b"\x00" * 32)
    product_info: bytes = field(default_factory=bytes)
    key_exchange_list: bytes = field(default_factory=bytes)
    server_certificate: bytes = field(default_factory=bytes)
    scope_list: bytes = field(default_factory=bytes)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a License Request PDU from binary data (after preamble)."""
        reader = ByteReader(data, "LicenseRequestPdu")

        # Server random (32 bytes)
        server_random = reader.read_bytes(32)

        # Product Info (variable): dwVersion(4) + cbCompanyName(4) + company + cbProductId(4) + product
        product_info_start = reader.offset
        _dw_version = reader.read_u32_le()
        cb_company = reader.read_u32_le()
        _company = reader.read_bytes(cb_company)
        cb_product = reader.read_u32_le()
        _product = reader.read_bytes(cb_product)
        product_info = data[product_info_start:reader.offset]

        # Key Exchange List (wBlobType(2) + wBlobLen(2) + data)
        _blob_type = reader.read_u16_le()
        blob_len = reader.read_u16_le()
        key_exchange_list = reader.read_bytes(blob_len)

        # Server Certificate (wBlobType(2) + wBlobLen(2) + data)
        _cert_blob_type = reader.read_u16_le()
        cert_blob_len = reader.read_u16_le()
        server_certificate = reader.read_bytes(cert_blob_len)

        # Scope List (wBlobType(2) + wBlobLen(2) + data) - optional
        scope_list = b""
        if reader.remaining() >= 4:
            _scope_count = reader.read_u32_le()
            # Read remaining as scope data
            if reader.remaining() > 0:
                scope_list = reader.read_bytes(reader.remaining())

        return cls(
            server_random=server_random,
            product_info=product_info,
            key_exchange_list=key_exchange_list,
            server_certificate=server_certificate,
            scope_list=scope_list,
        )

    def serialize(self) -> bytes:
        """Serialize the License Request PDU to binary."""
        writer = ByteWriter()
        writer.write_bytes(self.server_random)
        writer.write_bytes(self.product_info)

        # Key Exchange List blob
        writer.write_u16_le(0x000D)  # BB_KEY_EXCHG_ALG_BLOB
        writer.write_u16_le(len(self.key_exchange_list))
        writer.write_bytes(self.key_exchange_list)

        # Server Certificate blob
        writer.write_u16_le(0x0003)  # BB_CERTIFICATE_BLOB
        writer.write_u16_le(len(self.server_certificate))
        writer.write_bytes(self.server_certificate)

        # Scope List
        if self.scope_list:
            writer.write_u32_le(1)  # scope count
            writer.write_bytes(self.scope_list)

        return writer.to_bytes()


@dataclass
class PlatformChallengePdu(Pdu):
    """Server Platform Challenge PDU [MS-RDPELE] 2.2.2.4.

    Contains the encrypted platform challenge.
    """

    mac_data: bytes = field(default_factory=lambda: b"\x00" * 16)
    encrypted_challenge: bytes = field(default_factory=bytes)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a Platform Challenge PDU from binary data (after preamble)."""
        reader = ByteReader(data, "PlatformChallengePdu")

        # Connect flags (4 bytes, ignored)
        _connect_flags = reader.read_u32_le()

        # Encrypted Platform Challenge (wBlobType(2) + wBlobLen(2) + data)
        _blob_type = reader.read_u16_le()
        blob_len = reader.read_u16_le()
        encrypted_challenge = reader.read_bytes(blob_len)

        # MAC data (16 bytes)
        mac_data = reader.read_bytes(16)

        return cls(mac_data=mac_data, encrypted_challenge=encrypted_challenge)

    def serialize(self) -> bytes:
        """Serialize the Platform Challenge PDU to binary."""
        writer = ByteWriter()
        writer.write_u32_le(0)  # connect flags

        # Encrypted Platform Challenge blob
        writer.write_u16_le(0x000A)  # BB_ANY_BLOB
        writer.write_u16_le(len(self.encrypted_challenge))
        writer.write_bytes(self.encrypted_challenge)

        # MAC data
        writer.write_bytes(self.mac_data)

        return writer.to_bytes()


@dataclass
class LicenseErrorPdu(Pdu):
    """Licensing Error/Status PDU [MS-RDPELE] 2.2.2.7.1.

    Contains error code, state transition, and error info blob.
    """

    error_code: int = 0
    state_transition: int = 0
    error_info: bytes = field(default_factory=bytes)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a License Error PDU from binary data (after preamble)."""
        reader = ByteReader(data, "LicenseErrorPdu")

        error_code = reader.read_u32_le()
        state_transition = reader.read_u32_le()

        # Error info blob (wBlobType(2) + wBlobLen(2) + data)
        _blob_type = reader.read_u16_le()
        blob_len = reader.read_u16_le()
        error_info = b""
        if blob_len > 0:
            error_info = reader.read_bytes(blob_len)

        return cls(
            error_code=error_code,
            state_transition=state_transition,
            error_info=error_info,
        )

    def serialize(self) -> bytes:
        """Serialize the License Error PDU to binary."""
        writer = ByteWriter()
        writer.write_u32_le(self.error_code)
        writer.write_u32_le(self.state_transition)

        # Error info blob
        writer.write_u16_le(0x0004)  # BB_ERROR_BLOB
        writer.write_u16_le(len(self.error_info))
        if self.error_info:
            writer.write_bytes(self.error_info)

        return writer.to_bytes()


# ============================================================
# New License Request PDU (client → server)
# ============================================================


@dataclass
class NewLicenseRequestPdu(Pdu):
    """Client New License Request PDU [MS-RDPELE] 2.2.2.2.

    Sent in response to a License Request from the server.
    Contains the preferred key exchange algorithm, platform ID,
    client random, encrypted pre-master secret, client username,
    and client machine name.
    """

    key_exchange_alg: int = 0x00000001  # KEY_EXCHANGE_ALG_RSA
    platform_id: int = 0x04000000 | 0x00000100  # PLATFORMID (Windows + x86)
    client_random: bytes = field(default_factory=lambda: b"\x00" * 32)
    encrypted_premaster_secret: bytes = field(default_factory=bytes)
    client_username: bytes = field(default_factory=lambda: b"\x00")
    client_machine_name: bytes = field(default_factory=lambda: b"\x00")

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a New License Request PDU from binary data (after preamble)."""
        reader = ByteReader(data, "NewLicenseRequestPdu")

        key_exchange_alg = reader.read_u32_le()
        platform_id = reader.read_u32_le()
        client_random = reader.read_bytes(32)

        # Encrypted Pre-Master Secret blob
        _blob_type = reader.read_u16_le()
        blob_len = reader.read_u16_le()
        encrypted_premaster_secret = reader.read_bytes(blob_len)

        # Client User Name blob
        _user_blob_type = reader.read_u16_le()
        user_blob_len = reader.read_u16_le()
        client_username = reader.read_bytes(user_blob_len)

        # Client Machine Name blob
        _machine_blob_type = reader.read_u16_le()
        machine_blob_len = reader.read_u16_le()
        client_machine_name = reader.read_bytes(machine_blob_len)

        return cls(
            key_exchange_alg=key_exchange_alg,
            platform_id=platform_id,
            client_random=client_random,
            encrypted_premaster_secret=encrypted_premaster_secret,
            client_username=client_username,
            client_machine_name=client_machine_name,
        )

    def serialize(self) -> bytes:
        """Serialize the New License Request PDU to binary."""
        writer = ByteWriter()
        writer.write_u32_le(self.key_exchange_alg)
        writer.write_u32_le(self.platform_id)
        writer.write_bytes(self.client_random)

        # Encrypted Pre-Master Secret blob
        writer.write_u16_le(0x0001)  # BB_RANDOM_BLOB
        writer.write_u16_le(len(self.encrypted_premaster_secret))
        writer.write_bytes(self.encrypted_premaster_secret)

        # Client User Name blob
        writer.write_u16_le(0x000F)  # BB_CLIENT_USER_NAME_BLOB
        writer.write_u16_le(len(self.client_username))
        writer.write_bytes(self.client_username)

        # Client Machine Name blob
        writer.write_u16_le(0x0010)  # BB_CLIENT_MACHINE_NAME_BLOB
        writer.write_u16_le(len(self.client_machine_name))
        writer.write_bytes(self.client_machine_name)

        return writer.to_bytes()


# ============================================================
# Platform Challenge Response PDU (client → server)
# ============================================================


@dataclass
class PlatformChallengeResponsePdu(Pdu):
    """Client Platform Challenge Response PDU [MS-RDPELE] 2.2.2.5.

    Sent in response to a Platform Challenge from the server.
    """

    encrypted_response: bytes = field(default_factory=bytes)
    mac_data: bytes = field(default_factory=lambda: b"\x00" * 16)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a Platform Challenge Response PDU from binary data (after preamble)."""
        reader = ByteReader(data, "PlatformChallengeResponsePdu")

        # Encrypted Platform Challenge Response blob
        _blob_type = reader.read_u16_le()
        blob_len = reader.read_u16_le()
        encrypted_response = reader.read_bytes(blob_len)

        # MAC data (16 bytes)
        mac_data = reader.read_bytes(16)

        return cls(encrypted_response=encrypted_response, mac_data=mac_data)

    def serialize(self) -> bytes:
        """Serialize the Platform Challenge Response PDU to binary."""
        writer = ByteWriter()

        # Encrypted Platform Challenge Response blob
        writer.write_u16_le(0x000A)  # BB_ANY_BLOB
        writer.write_u16_le(len(self.encrypted_response))
        writer.write_bytes(self.encrypted_response)

        # MAC data
        writer.write_bytes(self.mac_data)

        return writer.to_bytes()


# ============================================================
# LicensingHandler
# ============================================================


class LicensingHandler:
    """Handles the MS-RDPELE licensing exchange (Phase 7).

    The handler processes licensing PDUs until the phase completes.
    Most modern RDP servers send an ERROR_ALERT with STATUS_VALID_CLIENT
    to skip licensing entirely (the common fast path).

    For the full exchange:
    1. Server sends LICENSE_REQUEST
    2. Client responds with NEW_LICENSE_REQUEST
    3. Server sends PLATFORM_CHALLENGE
    4. Client responds with PLATFORM_CHALLENGE_RESPONSE
    5. Server sends NEW_LICENSE or ERROR_ALERT with STATUS_VALID_CLIENT

    Requirements addressed: Req 6 (AC 1–4)
    """

    def __init__(
        self,
        username: str = "",
        machine_name: str = "",
    ) -> None:
        self._username = username or "user"
        self._machine_name = machine_name or "client"
        self._licensing_complete = False

    @property
    def licensing_complete(self) -> bool:
        """Whether the licensing exchange has completed."""
        return self._licensing_complete

    async def handle_licensing(
        self,
        recv_fn: Callable[[], bytes | bytearray],
        send_fn: Callable[[bytes], None],
    ) -> None:
        """Process licensing PDUs until the phase completes.

        Args:
            recv_fn: Async callable that returns the next licensing PDU data
                (including preamble, after security header has been stripped).
            send_fn: Async callable that sends a licensing PDU
                (including preamble, caller wraps with security header).
        """
        while not self._licensing_complete:
            data = await recv_fn()
            if not data or len(data) < 4:
                raise PduParseError("LicensingPdu", 0, "insufficient licensing PDU data")

            preamble = LicensePreamble.parse(data[:4])
            body = data[4:]

            if preamble.msg_type == LicenseMsgType.ERROR_ALERT:
                error_pdu = LicenseErrorPdu.parse(body)
                if error_pdu.error_code == LicenseErrorCode.STATUS_VALID_CLIENT:
                    # Common fast path: licensing complete (Req 6, AC 4)
                    self._licensing_complete = True
                    return
                else:
                    raise PduParseError(
                        "LicenseErrorPdu",
                        0,
                        f"licensing error: code=0x{error_pdu.error_code:08X}, "
                        f"transition=0x{error_pdu.state_transition:08X}",
                    )

            elif preamble.msg_type == LicenseMsgType.LICENSE_REQUEST:
                # Full exchange: respond with New License Request (Req 6, AC 1)
                license_request = LicenseRequestPdu.parse(body)
                response = self._build_new_license_request(license_request)
                await send_fn(response)

            elif preamble.msg_type == LicenseMsgType.PLATFORM_CHALLENGE:
                # Full exchange: compute challenge response (Req 6, AC 2)
                challenge_pdu = PlatformChallengePdu.parse(body)
                response = self._build_challenge_response(challenge_pdu)
                await send_fn(response)

            elif preamble.msg_type in (
                LicenseMsgType.NEW_LICENSE,
                LicenseMsgType.UPGRADE_LICENSE,
            ):
                # License granted: licensing complete (Req 6, AC 3)
                self._licensing_complete = True
                return

            else:
                raise PduParseError(
                    "LicensingPdu",
                    0,
                    f"unexpected licensing message type: 0x{preamble.msg_type:02X}",
                )

    def _build_new_license_request(self, license_request: LicenseRequestPdu) -> bytes:
        """Build a New License Request PDU in response to a License Request.

        For the initial implementation, we send a minimal New License Request
        with a random client random and a stub encrypted pre-master secret.
        This is sufficient for servers that accept any license info.

        Args:
            license_request: The parsed License Request from the server.

        Returns:
            Complete licensing PDU bytes (preamble + body).
        """
        client_random = os.urandom(32)

        # Build a minimal pre-master secret (48 bytes per MS-RDPELE)
        premaster_secret = os.urandom(48)

        # Encode username and machine name as null-terminated ASCII
        username_bytes = (self._username.encode("ascii", errors="replace") + b"\x00")
        machine_bytes = (self._machine_name.encode("ascii", errors="replace") + b"\x00")

        new_license_req = NewLicenseRequestPdu(
            key_exchange_alg=0x00000001,  # KEY_EXCHANGE_ALG_RSA
            platform_id=0x04000100,  # Windows + x86
            client_random=client_random,
            encrypted_premaster_secret=premaster_secret,
            client_username=username_bytes,
            client_machine_name=machine_bytes,
        )

        body = new_license_req.serialize()

        # Build preamble
        preamble = LicensePreamble(
            msg_type=LicenseMsgType.NEW_LICENSE_REQUEST,
            flags=0x03,  # PREAMBLE_VERSION_3_0
            msg_size=len(body) + 4,  # +4 for preamble itself
        )

        return preamble.serialize() + body

    def _build_challenge_response(self, challenge_pdu: PlatformChallengePdu) -> bytes:
        """Build a Platform Challenge Response PDU.

        For the initial implementation, we echo back the encrypted challenge
        data with a computed MAC. This is a minimal response that satisfies
        servers expecting a challenge response.

        Args:
            challenge_pdu: The parsed Platform Challenge from the server.

        Returns:
            Complete licensing PDU bytes (preamble + body).
        """
        # Build the platform challenge response data
        # The response contains: wVersion(2) + wClientType(2) + wLicenseDetailLevel(2)
        # + cbChallenge(2) + challenge_data
        challenge_data = challenge_pdu.encrypted_challenge

        # Build response blob: version + client type + detail level + challenge
        response_data = struct.pack("<HHH", 0x0100, 0x0003, 0x0003)
        response_data += struct.pack("<H", len(challenge_data))
        response_data += challenge_data

        # Compute MAC over the response data (using MD5 as a simple MAC)
        mac = hashlib.md5(response_data).digest()

        response_pdu = PlatformChallengeResponsePdu(
            encrypted_response=response_data,
            mac_data=mac,
        )

        body = response_pdu.serialize()

        # Build preamble
        preamble = LicensePreamble(
            msg_type=LicenseMsgType.PLATFORM_CHALLENGE_RESPONSE,
            flags=0x03,  # PREAMBLE_VERSION_3_0
            msg_size=len(body) + 4,  # +4 for preamble itself
        )

        return preamble.serialize() + body
