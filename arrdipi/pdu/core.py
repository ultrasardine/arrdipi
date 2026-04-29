"""Core PDU headers: ShareControl, ShareData, and Security headers.

Implements the RDP slow-path PDU header structures per [MS-RDPBCGR]:
- ShareControlHeader (Section 2.2.8.1.1.1.1)
- ShareDataHeader (Section 2.2.8.1.1.1.2)
- SecurityHeader (Section 2.2.8.1.1.2)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Self

from arrdipi.errors import PduParseError
from arrdipi.pdu.base import ByteReader, ByteWriter, Pdu
from arrdipi.pdu.types import ShareControlPduType, ShareDataPduType

# Version 1 is encoded in the upper 12 bits of the pdu_type field.
_SHARE_CONTROL_VERSION_1 = 0x0010
_SHARE_CONTROL_TYPE_MASK = 0x000F


@dataclass
class ShareControlHeader(Pdu):
    """Share Control PDU header [MS-RDPBCGR] 2.2.8.1.1.1.1.

    Fields (6 bytes total):
        total_length: u16 LE — total length of the PDU including this header.
        pdu_type: ShareControlPduType — lower 4 bits of the wire u16.
        pdu_source: u16 LE — MCS channel ID of the sender.

    The wire format encodes pdu_type | version in a single u16 LE field.
    Version is typically 0x0010 (version 1).
    """

    total_length: int
    pdu_type: ShareControlPduType
    pdu_source: int
    version: int = _SHARE_CONTROL_VERSION_1

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a ShareControlHeader from binary data.

        Raises PduParseError if data is truncated (< 6 bytes).
        """
        reader = ByteReader(data, pdu_type="ShareControlHeader")
        total_length = reader.read_u16_le()
        pdu_type_and_version = reader.read_u16_le()
        pdu_source = reader.read_u16_le()

        pdu_type_value = pdu_type_and_version & _SHARE_CONTROL_TYPE_MASK
        version = pdu_type_and_version & ~_SHARE_CONTROL_TYPE_MASK

        pdu_type = ShareControlPduType(pdu_type_value)

        return cls(
            total_length=total_length,
            pdu_type=pdu_type,
            pdu_source=pdu_source,
            version=version,
        )

    def serialize(self) -> bytes:
        """Serialize this ShareControlHeader to binary wire format."""
        writer = ByteWriter()
        writer.write_u16_le(self.total_length)
        writer.write_u16_le(int(self.pdu_type) | self.version)
        writer.write_u16_le(self.pdu_source)
        return writer.to_bytes()


@dataclass
class ShareDataHeader(Pdu):
    """Share Data PDU header [MS-RDPBCGR] 2.2.8.1.1.1.2.

    Fields (12 bytes total, follows the ShareControlHeader):
        share_id: u32 LE — share identifier.
        pad1: u8 — padding (always 0).
        stream_id: u8 — stream priority.
        uncompressed_length: u16 LE — uncompressed length of the PDU data.
        pdu_type: ShareDataPduType — u8 identifying the data PDU type.
        compressed_type: u8 — compression flags.
        compressed_length: u16 LE — compressed length (0 if not compressed).
    """

    share_id: int
    pad1: int
    stream_id: int
    uncompressed_length: int
    pdu_type: ShareDataPduType
    compressed_type: int
    compressed_length: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a ShareDataHeader from binary data.

        Raises PduParseError if data is truncated (< 12 bytes).
        """
        reader = ByteReader(data, pdu_type="ShareDataHeader")
        share_id = reader.read_u32_le()
        pad1 = reader.read_u8()
        stream_id = reader.read_u8()
        uncompressed_length = reader.read_u16_le()
        pdu_type_value = reader.read_u8()
        compressed_type = reader.read_u8()
        compressed_length = reader.read_u16_le()

        pdu_type = ShareDataPduType(pdu_type_value)

        return cls(
            share_id=share_id,
            pad1=pad1,
            stream_id=stream_id,
            uncompressed_length=uncompressed_length,
            pdu_type=pdu_type,
            compressed_type=compressed_type,
            compressed_length=compressed_length,
        )

    def serialize(self) -> bytes:
        """Serialize this ShareDataHeader to binary wire format."""
        writer = ByteWriter()
        writer.write_u32_le(self.share_id)
        writer.write_u8(self.pad1)
        writer.write_u8(self.stream_id)
        writer.write_u16_le(self.uncompressed_length)
        writer.write_u8(int(self.pdu_type))
        writer.write_u8(self.compressed_type)
        writer.write_u16_le(self.compressed_length)
        return writer.to_bytes()


@dataclass
class SecurityHeader(Pdu):
    """Security header [MS-RDPBCGR] 2.2.8.1.1.2.

    Fields:
        flags: u16 LE — security flags.
        flags_hi: u16 LE — high security flags.
        mac: optional bytes — 8-byte MAC signature when encryption is active.

    The MAC field is present only when the SEC_ENCRYPT flag (0x0008) is set
    in the flags field.
    """

    flags: int
    flags_hi: int
    mac: bytes | None = None

    # Security flag indicating encryption is active.
    SEC_ENCRYPT: int = 0x0008

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a SecurityHeader from binary data.

        Reads the 4-byte base header (flags + flags_hi). If SEC_ENCRYPT
        is set in flags, reads an additional 8-byte MAC signature.

        Raises PduParseError if data is truncated.
        """
        reader = ByteReader(data, pdu_type="SecurityHeader")
        flags = reader.read_u16_le()
        flags_hi = reader.read_u16_le()

        mac: bytes | None = None
        if flags & cls.SEC_ENCRYPT:
            mac = reader.read_bytes(8)

        return cls(flags=flags, flags_hi=flags_hi, mac=mac)

    def serialize(self) -> bytes:
        """Serialize this SecurityHeader to binary wire format."""
        writer = ByteWriter()
        writer.write_u16_le(self.flags)
        writer.write_u16_le(self.flags_hi)
        if self.mac is not None:
            writer.write_bytes(self.mac)
        return writer.to_bytes()
