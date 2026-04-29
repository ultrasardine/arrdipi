"""Pointer update PDU dataclasses for cursor shape and position.

Implements the pointer update PDUs defined in [MS-RDPBCGR] Section 2.2.9.1:
- PointerPositionUpdate (2.2.9.1.1.4.2)
- SystemPointerUpdate (2.2.9.1.1.4.3)
- ColorPointerUpdate (2.2.9.1.1.4.4)
- NewPointerUpdate (2.2.9.1.1.4.5)
- CachedPointerUpdate (2.2.9.1.1.4.6)
- LargePointerUpdate (2.2.9.1.2.1.11)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Self

from arrdipi.pdu.base import ByteReader, ByteWriter, Pdu


# System pointer type constants
SYSTEM_POINTER_DEFAULT = 0x7F00
SYSTEM_POINTER_NULL = 0x0000


@dataclass
class PointerPositionUpdate(Pdu):
    """Pointer Position Update PDU [MS-RDPBCGR] 2.2.9.1.1.4.2.

    Updates the cursor position on the client display.
    """

    x: int
    y: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        reader = ByteReader(data, "PointerPositionUpdate")
        x = reader.read_u16_le()
        y = reader.read_u16_le()
        return cls(x=x, y=y)

    def serialize(self) -> bytes:
        writer = ByteWriter()
        writer.write_u16_le(self.x)
        writer.write_u16_le(self.y)
        return writer.to_bytes()


@dataclass
class SystemPointerUpdate(Pdu):
    """System Pointer Update PDU [MS-RDPBCGR] 2.2.9.1.1.4.3.

    Sets the cursor to a system pointer type (default or hidden).
    """

    system_pointer_type: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        reader = ByteReader(data, "SystemPointerUpdate")
        system_pointer_type = reader.read_u32_le()
        return cls(system_pointer_type=system_pointer_type)

    def serialize(self) -> bytes:
        writer = ByteWriter()
        writer.write_u32_le(self.system_pointer_type)
        return writer.to_bytes()


@dataclass
class ColorPointerUpdate(Pdu):
    """Color Pointer Update PDU [MS-RDPBCGR] 2.2.9.1.1.4.4.

    Defines a 24-bit color pointer with XOR and AND masks.
    """

    cache_index: int
    hotspot_x: int
    hotspot_y: int
    width: int
    height: int
    and_mask_data: bytes
    xor_mask_data: bytes

    @classmethod
    def parse(cls, data: bytes) -> Self:
        reader = ByteReader(data, "ColorPointerUpdate")
        cache_index = reader.read_u16_le()
        hotspot_x = reader.read_u16_le()
        hotspot_y = reader.read_u16_le()
        width = reader.read_u16_le()
        height = reader.read_u16_le()
        and_mask_len = reader.read_u16_le()
        xor_mask_len = reader.read_u16_le()
        xor_mask_data = reader.read_bytes(xor_mask_len)
        and_mask_data = reader.read_bytes(and_mask_len)
        return cls(
            cache_index=cache_index,
            hotspot_x=hotspot_x,
            hotspot_y=hotspot_y,
            width=width,
            height=height,
            and_mask_data=and_mask_data,
            xor_mask_data=xor_mask_data,
        )

    def serialize(self) -> bytes:
        writer = ByteWriter()
        writer.write_u16_le(self.cache_index)
        writer.write_u16_le(self.hotspot_x)
        writer.write_u16_le(self.hotspot_y)
        writer.write_u16_le(self.width)
        writer.write_u16_le(self.height)
        writer.write_u16_le(len(self.and_mask_data))
        writer.write_u16_le(len(self.xor_mask_data))
        writer.write_bytes(self.xor_mask_data)
        writer.write_bytes(self.and_mask_data)
        return writer.to_bytes()


@dataclass
class NewPointerUpdate(Pdu):
    """New Pointer Update PDU [MS-RDPBCGR] 2.2.9.1.1.4.5.

    Defines a pointer with variable color depth XOR and AND masks.
    """

    xor_bpp: int
    cache_index: int
    hotspot_x: int
    hotspot_y: int
    width: int
    height: int
    and_mask_data: bytes
    xor_mask_data: bytes

    @classmethod
    def parse(cls, data: bytes) -> Self:
        reader = ByteReader(data, "NewPointerUpdate")
        xor_bpp = reader.read_u16_le()
        cache_index = reader.read_u16_le()
        hotspot_x = reader.read_u16_le()
        hotspot_y = reader.read_u16_le()
        width = reader.read_u16_le()
        height = reader.read_u16_le()
        and_mask_len = reader.read_u16_le()
        xor_mask_len = reader.read_u16_le()
        xor_mask_data = reader.read_bytes(xor_mask_len)
        and_mask_data = reader.read_bytes(and_mask_len)
        return cls(
            xor_bpp=xor_bpp,
            cache_index=cache_index,
            hotspot_x=hotspot_x,
            hotspot_y=hotspot_y,
            width=width,
            height=height,
            and_mask_data=and_mask_data,
            xor_mask_data=xor_mask_data,
        )

    def serialize(self) -> bytes:
        writer = ByteWriter()
        writer.write_u16_le(self.xor_bpp)
        writer.write_u16_le(self.cache_index)
        writer.write_u16_le(self.hotspot_x)
        writer.write_u16_le(self.hotspot_y)
        writer.write_u16_le(self.width)
        writer.write_u16_le(self.height)
        writer.write_u16_le(len(self.and_mask_data))
        writer.write_u16_le(len(self.xor_mask_data))
        writer.write_bytes(self.xor_mask_data)
        writer.write_bytes(self.and_mask_data)
        return writer.to_bytes()


@dataclass
class CachedPointerUpdate(Pdu):
    """Cached Pointer Update PDU [MS-RDPBCGR] 2.2.9.1.1.4.6.

    Sets the active cursor from the pointer cache.
    """

    cache_index: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        reader = ByteReader(data, "CachedPointerUpdate")
        cache_index = reader.read_u16_le()
        return cls(cache_index=cache_index)

    def serialize(self) -> bytes:
        writer = ByteWriter()
        writer.write_u16_le(self.cache_index)
        return writer.to_bytes()


@dataclass
class LargePointerUpdate(Pdu):
    """Large Pointer Update PDU [MS-RDPBCGR] 2.2.9.1.2.1.11.

    Same as NewPointerUpdate but supports cursor sizes up to 384x384 pixels.
    Uses 32-bit length fields for the mask data.
    """

    xor_bpp: int
    cache_index: int
    hotspot_x: int
    hotspot_y: int
    width: int
    height: int
    and_mask_data: bytes
    xor_mask_data: bytes

    @classmethod
    def parse(cls, data: bytes) -> Self:
        reader = ByteReader(data, "LargePointerUpdate")
        xor_bpp = reader.read_u16_le()
        cache_index = reader.read_u16_le()
        hotspot_x = reader.read_u16_le()
        hotspot_y = reader.read_u16_le()
        width = reader.read_u16_le()
        height = reader.read_u16_le()
        and_mask_len = reader.read_u32_le()
        xor_mask_len = reader.read_u32_le()
        xor_mask_data = reader.read_bytes(xor_mask_len)
        and_mask_data = reader.read_bytes(and_mask_len)
        return cls(
            xor_bpp=xor_bpp,
            cache_index=cache_index,
            hotspot_x=hotspot_x,
            hotspot_y=hotspot_y,
            width=width,
            height=height,
            and_mask_data=and_mask_data,
            xor_mask_data=xor_mask_data,
        )

    def serialize(self) -> bytes:
        writer = ByteWriter()
        writer.write_u16_le(self.xor_bpp)
        writer.write_u16_le(self.cache_index)
        writer.write_u16_le(self.hotspot_x)
        writer.write_u16_le(self.hotspot_y)
        writer.write_u16_le(self.width)
        writer.write_u16_le(self.height)
        writer.write_u32_le(len(self.and_mask_data))
        writer.write_u32_le(len(self.xor_mask_data))
        writer.write_bytes(self.xor_mask_data)
        writer.write_bytes(self.and_mask_data)
        return writer.to_bytes()
