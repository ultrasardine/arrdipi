"""Connection finalization PDUs [MS-RDPBCGR] 2.2.1.14–2.2.1.22.

Implements the PDU types exchanged during Phase 10 (Connection Finalization)
of the RDP connection sequence:
- SynchronizePdu (2.2.1.14 / 2.2.1.19)
- ControlPdu (2.2.1.15–2.2.1.16 / 2.2.1.20–2.2.1.21)
- PersistentKeyListPdu (2.2.1.17)
- FontListPdu (2.2.1.18)
- FontMapPdu (2.2.1.22)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Self

from arrdipi.pdu.base import ByteReader, ByteWriter, Pdu


class ControlAction(IntEnum):
    """Control PDU action values [MS-RDPBCGR] 2.2.1.15."""

    REQUEST_CONTROL = 0x0001
    GRANTED_CONTROL = 0x0002
    DETACH = 0x0003
    COOPERATE = 0x0004


class PersistentKeyListFlag(IntEnum):
    """Persistent Key List PDU bitmask flags [MS-RDPBCGR] 2.2.1.17."""

    PERSIST_FIRST_PDU = 0x01
    PERSIST_LAST_PDU = 0x02


@dataclass
class SynchronizePdu(Pdu):
    """Client/Server Synchronize PDU [MS-RDPBCGR] 2.2.1.14 / 2.2.1.19.

    Fields (4 bytes):
        message_type: u16 LE — always 1 (SYNCMSGTYPE_SYNC).
        target_user: u16 LE — MCS user channel ID of the target.
    """

    message_type: int
    target_user: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a SynchronizePdu from binary data."""
        reader = ByteReader(data, pdu_type="SynchronizePdu")
        message_type = reader.read_u16_le()
        target_user = reader.read_u16_le()
        return cls(message_type=message_type, target_user=target_user)

    def serialize(self) -> bytes:
        """Serialize this SynchronizePdu to binary wire format."""
        writer = ByteWriter()
        writer.write_u16_le(self.message_type)
        writer.write_u16_le(self.target_user)
        return writer.to_bytes()


@dataclass
class ControlPdu(Pdu):
    """Client/Server Control PDU [MS-RDPBCGR] 2.2.1.15–2.2.1.16 / 2.2.1.20–2.2.1.21.

    Fields (8 bytes):
        action: u16 LE — ControlAction value.
        grant_id: u16 LE — granted control ID (0 for requests).
        control_id: u32 LE — control identifier (0 for requests).
    """

    action: int
    grant_id: int
    control_id: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a ControlPdu from binary data."""
        reader = ByteReader(data, pdu_type="ControlPdu")
        action = reader.read_u16_le()
        grant_id = reader.read_u16_le()
        control_id = reader.read_u32_le()
        return cls(action=action, grant_id=grant_id, control_id=control_id)

    def serialize(self) -> bytes:
        """Serialize this ControlPdu to binary wire format."""
        writer = ByteWriter()
        writer.write_u16_le(self.action)
        writer.write_u16_le(self.grant_id)
        writer.write_u32_le(self.control_id)
        return writer.to_bytes()


@dataclass
class PersistentKeyListPdu(Pdu):
    """Client Persistent Key List PDU [MS-RDPBCGR] 2.2.1.17.

    Fields:
        num_entries_cache0: u16 LE
        num_entries_cache1: u16 LE
        num_entries_cache2: u16 LE
        num_entries_cache3: u16 LE
        num_entries_cache4: u16 LE
        total_entries_cache0: u16 LE
        total_entries_cache1: u16 LE
        total_entries_cache2: u16 LE
        total_entries_cache3: u16 LE
        total_entries_cache4: u16 LE
        b_bit_mask: u8 — PERSIST_FIRST_PDU / PERSIST_LAST_PDU flags
        pad2: u8
        pad3: u16 LE
        entries: list[int] — persistent bitmap cache keys (u64 LE each)
    """

    num_entries_cache0: int
    num_entries_cache1: int
    num_entries_cache2: int
    num_entries_cache3: int
    num_entries_cache4: int
    total_entries_cache0: int
    total_entries_cache1: int
    total_entries_cache2: int
    total_entries_cache3: int
    total_entries_cache4: int
    b_bit_mask: int
    pad2: int
    pad3: int
    entries: list[int] = field(default_factory=list)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a PersistentKeyListPdu from binary data."""
        reader = ByteReader(data, pdu_type="PersistentKeyListPdu")
        num_entries_cache0 = reader.read_u16_le()
        num_entries_cache1 = reader.read_u16_le()
        num_entries_cache2 = reader.read_u16_le()
        num_entries_cache3 = reader.read_u16_le()
        num_entries_cache4 = reader.read_u16_le()
        total_entries_cache0 = reader.read_u16_le()
        total_entries_cache1 = reader.read_u16_le()
        total_entries_cache2 = reader.read_u16_le()
        total_entries_cache3 = reader.read_u16_le()
        total_entries_cache4 = reader.read_u16_le()
        b_bit_mask = reader.read_u8()
        pad2 = reader.read_u8()
        pad3 = reader.read_u16_le()

        # Total number of key entries in this PDU
        total_keys = (
            num_entries_cache0
            + num_entries_cache1
            + num_entries_cache2
            + num_entries_cache3
            + num_entries_cache4
        )
        entries: list[int] = []
        for _ in range(total_keys):
            entries.append(reader.read_u64_le())

        return cls(
            num_entries_cache0=num_entries_cache0,
            num_entries_cache1=num_entries_cache1,
            num_entries_cache2=num_entries_cache2,
            num_entries_cache3=num_entries_cache3,
            num_entries_cache4=num_entries_cache4,
            total_entries_cache0=total_entries_cache0,
            total_entries_cache1=total_entries_cache1,
            total_entries_cache2=total_entries_cache2,
            total_entries_cache3=total_entries_cache3,
            total_entries_cache4=total_entries_cache4,
            b_bit_mask=b_bit_mask,
            pad2=pad2,
            pad3=pad3,
            entries=entries,
        )

    def serialize(self) -> bytes:
        """Serialize this PersistentKeyListPdu to binary wire format."""
        writer = ByteWriter()
        writer.write_u16_le(self.num_entries_cache0)
        writer.write_u16_le(self.num_entries_cache1)
        writer.write_u16_le(self.num_entries_cache2)
        writer.write_u16_le(self.num_entries_cache3)
        writer.write_u16_le(self.num_entries_cache4)
        writer.write_u16_le(self.total_entries_cache0)
        writer.write_u16_le(self.total_entries_cache1)
        writer.write_u16_le(self.total_entries_cache2)
        writer.write_u16_le(self.total_entries_cache3)
        writer.write_u16_le(self.total_entries_cache4)
        writer.write_u8(self.b_bit_mask)
        writer.write_u8(self.pad2)
        writer.write_u16_le(self.pad3)
        for key in self.entries:
            writer.write_u64_le(key)
        return writer.to_bytes()


@dataclass
class FontListPdu(Pdu):
    """Client Font List PDU [MS-RDPBCGR] 2.2.1.18.

    Fields (8 bytes):
        number_fonts: u16 LE — number of fonts (always 0).
        total_num_fonts: u16 LE — total number of fonts (always 0).
        list_flags: u16 LE — 0x0003 (FONTLIST_FIRST | FONTLIST_LAST).
        entry_size: u16 LE — 0x0032 (50).
    """

    number_fonts: int
    total_num_fonts: int
    list_flags: int
    entry_size: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a FontListPdu from binary data."""
        reader = ByteReader(data, pdu_type="FontListPdu")
        number_fonts = reader.read_u16_le()
        total_num_fonts = reader.read_u16_le()
        list_flags = reader.read_u16_le()
        entry_size = reader.read_u16_le()
        return cls(
            number_fonts=number_fonts,
            total_num_fonts=total_num_fonts,
            list_flags=list_flags,
            entry_size=entry_size,
        )

    def serialize(self) -> bytes:
        """Serialize this FontListPdu to binary wire format."""
        writer = ByteWriter()
        writer.write_u16_le(self.number_fonts)
        writer.write_u16_le(self.total_num_fonts)
        writer.write_u16_le(self.list_flags)
        writer.write_u16_le(self.entry_size)
        return writer.to_bytes()


@dataclass
class FontMapPdu(Pdu):
    """Server Font Map PDU [MS-RDPBCGR] 2.2.1.22.

    Fields (8 bytes):
        number_entries: u16 LE — number of entries (always 0).
        total_num_entries: u16 LE — total number of entries (always 0).
        map_flags: u16 LE — 0x0003 (FONTMAP_FIRST | FONTMAP_LAST).
        entry_size: u16 LE — 0x0004.
    """

    number_entries: int
    total_num_entries: int
    map_flags: int
    entry_size: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a FontMapPdu from binary data."""
        reader = ByteReader(data, pdu_type="FontMapPdu")
        number_entries = reader.read_u16_le()
        total_num_entries = reader.read_u16_le()
        map_flags = reader.read_u16_le()
        entry_size = reader.read_u16_le()
        return cls(
            number_entries=number_entries,
            total_num_entries=total_num_entries,
            map_flags=map_flags,
            entry_size=entry_size,
        )

    def serialize(self) -> bytes:
        """Serialize this FontMapPdu to binary wire format."""
        writer = ByteWriter()
        writer.write_u16_le(self.number_entries)
        writer.write_u16_le(self.total_num_entries)
        writer.write_u16_le(self.map_flags)
        writer.write_u16_le(self.entry_size)
        return writer.to_bytes()
