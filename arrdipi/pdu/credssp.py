"""CredSSP TSRequest PDU structures per [MS-CSSP] Section 2.2.1.

Implements ASN.1 DER encoding/decoding for TSRequest, TSCredentials,
and TSPasswordCreds structures used in the CredSSP handshake.

Requirements addressed: Req 11 (AC 1, 4)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Self

from arrdipi.errors import PduParseError


# ASN.1 DER tag constants
_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_SEQUENCE = 0x30
_TAG_CONTEXT_0 = 0xA0
_TAG_CONTEXT_1 = 0xA1
_TAG_CONTEXT_2 = 0xA2
_TAG_CONTEXT_3 = 0xA3
_TAG_CONTEXT_4 = 0xA4
_TAG_CONTEXT_5 = 0xA5

# CredSSP version
CREDSSP_VERSION = 6


def _encode_length(length: int) -> bytes:
    """Encode ASN.1 DER length."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])


def _decode_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode ASN.1 DER length. Returns (length, new_offset)."""
    if offset >= len(data):
        raise PduParseError("TSRequest", offset, "unexpected end of data reading length")
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    num_bytes = first & 0x7F
    if num_bytes == 0:
        raise PduParseError("TSRequest", offset, "indefinite length not supported")
    if offset + 1 + num_bytes > len(data):
        raise PduParseError("TSRequest", offset, "truncated length encoding")
    length = 0
    for i in range(num_bytes):
        length = (length << 8) | data[offset + 1 + i]
    return length, offset + 1 + num_bytes


def _encode_integer(value: int) -> bytes:
    """Encode an ASN.1 DER INTEGER."""
    if value == 0:
        content = b"\x00"
    elif value > 0:
        # Encode as unsigned, add leading zero if high bit set
        byte_length = (value.bit_length() + 8) // 8  # +8 to account for sign bit
        content = value.to_bytes(byte_length, "big")
        # Strip leading zeros but keep one if needed for sign
        while len(content) > 1 and content[0] == 0 and content[1] < 0x80:
            content = content[1:]
    else:
        # Negative integers
        byte_length = (value.bit_length() + 9) // 8
        content = value.to_bytes(byte_length, "big", signed=True)
    return bytes([_TAG_INTEGER]) + _encode_length(len(content)) + content


def _decode_integer(data: bytes, offset: int) -> tuple[int, int]:
    """Decode an ASN.1 DER INTEGER. Returns (value, new_offset)."""
    if offset >= len(data) or data[offset] != _TAG_INTEGER:
        raise PduParseError("TSRequest", offset, "expected INTEGER tag")
    length, offset = _decode_length(data, offset + 1)
    if offset + length > len(data):
        raise PduParseError("TSRequest", offset, "truncated INTEGER value")
    value = int.from_bytes(data[offset : offset + length], "big", signed=True)
    return value, offset + length


def _encode_octet_string(value: bytes) -> bytes:
    """Encode an ASN.1 DER OCTET STRING."""
    return bytes([_TAG_OCTET_STRING]) + _encode_length(len(value)) + value


def _decode_octet_string(data: bytes, offset: int) -> tuple[bytes, int]:
    """Decode an ASN.1 DER OCTET STRING. Returns (value, new_offset)."""
    if offset >= len(data) or data[offset] != _TAG_OCTET_STRING:
        raise PduParseError("TSRequest", offset, "expected OCTET STRING tag")
    length, offset = _decode_length(data, offset + 1)
    if offset + length > len(data):
        raise PduParseError("TSRequest", offset, "truncated OCTET STRING value")
    return data[offset : offset + length], offset + length


def _encode_context_tag(tag_number: int, content: bytes) -> bytes:
    """Encode an ASN.1 context-specific constructed tag."""
    tag = 0xA0 | tag_number
    return bytes([tag]) + _encode_length(len(content)) + content


def _decode_tag(data: bytes, offset: int) -> tuple[int, int, int]:
    """Decode an ASN.1 tag. Returns (tag_byte, content_length, content_offset)."""
    if offset >= len(data):
        raise PduParseError("TSRequest", offset, "unexpected end of data reading tag")
    tag = data[offset]
    length, content_offset = _decode_length(data, offset + 1)
    return tag, length, content_offset


@dataclass
class TSPasswordCreds:
    """TSPasswordCreds structure per [MS-CSSP] 2.2.1.2.1.

    All string fields are UTF-16LE encoded in the wire format.
    """

    domain_name: str = ""
    user_name: str = ""
    password: str = ""

    def serialize(self) -> bytes:
        """Encode as ASN.1 DER SEQUENCE."""
        domain_bytes = self.domain_name.encode("utf-16-le")
        user_bytes = self.user_name.encode("utf-16-le")
        pass_bytes = self.password.encode("utf-16-le")

        content = (
            _encode_context_tag(0, _encode_octet_string(domain_bytes))
            + _encode_context_tag(1, _encode_octet_string(user_bytes))
            + _encode_context_tag(2, _encode_octet_string(pass_bytes))
        )
        return bytes([_TAG_SEQUENCE]) + _encode_length(len(content)) + content

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Decode from ASN.1 DER SEQUENCE."""
        offset = 0
        if offset >= len(data) or data[offset] != _TAG_SEQUENCE:
            raise PduParseError("TSPasswordCreds", offset, "expected SEQUENCE tag")
        _, offset = _decode_length(data, offset + 1)

        domain_name = ""
        user_name = ""
        password = ""

        while offset < len(data):
            tag, length, content_offset = _decode_tag(data, offset)
            end = content_offset + length

            if tag == _TAG_CONTEXT_0:
                raw, _ = _decode_octet_string(data, content_offset)
                domain_name = raw.decode("utf-16-le")
            elif tag == _TAG_CONTEXT_1:
                raw, _ = _decode_octet_string(data, content_offset)
                user_name = raw.decode("utf-16-le")
            elif tag == _TAG_CONTEXT_2:
                raw, _ = _decode_octet_string(data, content_offset)
                password = raw.decode("utf-16-le")

            offset = end

        return cls(domain_name=domain_name, user_name=user_name, password=password)


@dataclass
class TSCredentials:
    """TSCredentials structure per [MS-CSSP] 2.2.1.2.

    credType 1 = password credentials (TSPasswordCreds).
    """

    cred_type: int = 1
    credentials: bytes = field(default=b"")

    def serialize(self) -> bytes:
        """Encode as ASN.1 DER SEQUENCE."""
        content = (
            _encode_context_tag(0, _encode_integer(self.cred_type))
            + _encode_context_tag(1, _encode_octet_string(self.credentials))
        )
        return bytes([_TAG_SEQUENCE]) + _encode_length(len(content)) + content

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Decode from ASN.1 DER SEQUENCE."""
        offset = 0
        if offset >= len(data) or data[offset] != _TAG_SEQUENCE:
            raise PduParseError("TSCredentials", offset, "expected SEQUENCE tag")
        _, offset = _decode_length(data, offset + 1)

        cred_type = 1
        credentials = b""

        while offset < len(data):
            tag, length, content_offset = _decode_tag(data, offset)
            end = content_offset + length

            if tag == _TAG_CONTEXT_0:
                cred_type, _ = _decode_integer(data, content_offset)
            elif tag == _TAG_CONTEXT_1:
                credentials, _ = _decode_octet_string(data, content_offset)

            offset = end

        return cls(cred_type=cred_type, credentials=credentials)


@dataclass
class TSRequest:
    """TSRequest structure per [MS-CSSP] 2.2.1.

    The top-level CredSSP message exchanged between client and server.

    Attributes:
        version: CredSSP protocol version (default 6).
        nego_tokens: List of SPNEGO tokens (negoTokens field).
        auth_info: Encrypted TSCredentials (authInfo field).
        pub_key_auth: Encrypted public key (pubKeyAuth field).
        error_code: NTSTATUS error code from server.
        client_nonce: 32-byte nonce for version >= 5.
    """

    version: int = CREDSSP_VERSION
    nego_tokens: list[bytes] = field(default_factory=list)
    auth_info: bytes = field(default=b"")
    pub_key_auth: bytes = field(default=b"")
    error_code: int = 0
    client_nonce: bytes = field(default=b"")

    def serialize(self) -> bytes:
        """Encode as ASN.1 DER SEQUENCE (TSRequest)."""
        # version [0] INTEGER
        content = _encode_context_tag(0, _encode_integer(self.version))

        # negoTokens [1] SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }
        if self.nego_tokens:
            tokens_content = b""
            for token in self.nego_tokens:
                # Each token is wrapped: SEQUENCE { [0] OCTET STRING }
                inner = _encode_context_tag(0, _encode_octet_string(token))
                tokens_content += bytes([_TAG_SEQUENCE]) + _encode_length(len(inner)) + inner
            # Wrap in outer SEQUENCE
            nego_seq = bytes([_TAG_SEQUENCE]) + _encode_length(len(tokens_content)) + tokens_content
            content += _encode_context_tag(1, nego_seq)

        # authInfo [2] OCTET STRING
        if self.auth_info:
            content += _encode_context_tag(2, _encode_octet_string(self.auth_info))

        # pubKeyAuth [3] OCTET STRING
        if self.pub_key_auth:
            content += _encode_context_tag(3, _encode_octet_string(self.pub_key_auth))

        # errorCode [4] INTEGER (only if non-zero)
        if self.error_code:
            content += _encode_context_tag(4, _encode_integer(self.error_code))

        # clientNonce [5] OCTET STRING
        if self.client_nonce:
            content += _encode_context_tag(5, _encode_octet_string(self.client_nonce))

        return bytes([_TAG_SEQUENCE]) + _encode_length(len(content)) + content

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Decode from ASN.1 DER SEQUENCE (TSRequest).

        Raises PduParseError on malformed data.
        """
        if not data:
            raise PduParseError("TSRequest", 0, "empty data")

        offset = 0
        if data[offset] != _TAG_SEQUENCE:
            raise PduParseError("TSRequest", offset, "expected SEQUENCE tag")
        seq_length, offset = _decode_length(data, offset + 1)
        end_of_sequence = offset + seq_length

        version = CREDSSP_VERSION
        nego_tokens: list[bytes] = []
        auth_info = b""
        pub_key_auth = b""
        error_code = 0
        client_nonce = b""

        while offset < end_of_sequence:
            tag, length, content_offset = _decode_tag(data, offset)
            field_end = content_offset + length

            if tag == _TAG_CONTEXT_0:
                # version
                version, _ = _decode_integer(data, content_offset)
            elif tag == _TAG_CONTEXT_1:
                # negoTokens: SEQUENCE OF SEQUENCE { [0] OCTET STRING }
                nego_tokens = _parse_nego_tokens(data, content_offset, field_end)
            elif tag == _TAG_CONTEXT_2:
                # authInfo
                auth_info, _ = _decode_octet_string(data, content_offset)
            elif tag == _TAG_CONTEXT_3:
                # pubKeyAuth
                pub_key_auth, _ = _decode_octet_string(data, content_offset)
            elif tag == _TAG_CONTEXT_4:
                # errorCode
                error_code, _ = _decode_integer(data, content_offset)
            elif tag == _TAG_CONTEXT_5:
                # clientNonce
                client_nonce, _ = _decode_octet_string(data, content_offset)

            offset = field_end

        return cls(
            version=version,
            nego_tokens=nego_tokens,
            auth_info=auth_info,
            pub_key_auth=pub_key_auth,
            error_code=error_code,
            client_nonce=client_nonce,
        )


def _parse_nego_tokens(data: bytes, offset: int, end: int) -> list[bytes]:
    """Parse the negoTokens SEQUENCE OF SEQUENCE structure."""
    tokens: list[bytes] = []

    # Outer SEQUENCE
    if offset >= end or data[offset] != _TAG_SEQUENCE:
        return tokens
    seq_length, offset = _decode_length(data, offset + 1)
    seq_end = offset + seq_length

    while offset < seq_end:
        # Each element is SEQUENCE { [0] OCTET STRING }
        if data[offset] != _TAG_SEQUENCE:
            break
        inner_length, inner_offset = _decode_length(data, offset + 1)
        inner_end = inner_offset + inner_length

        # Look for [0] context tag containing the OCTET STRING
        if inner_offset < inner_end and data[inner_offset] == _TAG_CONTEXT_0:
            _, ctx_length, ctx_content_offset = _decode_tag(data, inner_offset)
            token_data, _ = _decode_octet_string(data, ctx_content_offset)
            tokens.append(token_data)

        offset = inner_end

    return tokens
