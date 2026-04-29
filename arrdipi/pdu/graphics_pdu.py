"""Graphics PDU dataclasses for bitmap and order updates.

Provides BitmapUpdatePdu and OrderUpdatePdu with parse methods for
processing server-sent graphics data.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Self

from arrdipi.errors import PduParseError
from arrdipi.pdu.base import ByteReader, Pdu


# --- Update Types ---

class UpdateType(enum.IntEnum):
    """Graphics update types per [MS-RDPBCGR] 2.2.9.1.1.3."""
    ORDERS = 0x0000
    BITMAP = 0x0001
    PALETTE = 0x0002
    SYNCHRONIZE = 0x0003


# --- Order Control Flags ---

class OrderFlags(enum.IntFlag):
    """Order control flags per [MS-RDPEGDI] 2.2.2.1.1."""
    STANDARD = 0x01
    SECONDARY = 0x02
    BOUNDS = 0x04
    TYPE_CHANGE = 0x08
    DELTA_COORDINATES = 0x10
    ZERO_BOUNDS_DELTAS = 0x20
    ZERO_FIELD_BYTE_BIT0 = 0x40
    ZERO_FIELD_BYTE_BIT1 = 0x80


# --- Bitmap Update PDU ---

@dataclass
class BitmapRectangle:
    """A single bitmap rectangle within a Bitmap Update PDU."""
    dest_left: int
    dest_top: int
    dest_right: int
    dest_bottom: int
    width: int
    height: int
    bpp: int
    compressed: bool
    data: bytes


@dataclass
class BitmapUpdatePdu(Pdu):
    """Bitmap Update PDU containing one or more bitmap rectangles.

    Per [MS-RDPBCGR] 2.2.9.1.1.3.1.2.
    """
    rectangles: list[BitmapRectangle] = field(default_factory=list)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a Bitmap Update PDU from binary data.

        Args:
            data: Raw PDU data (after update type field).

        Returns:
            Parsed BitmapUpdatePdu instance.
        """
        reader = ByteReader(data, "BitmapUpdatePdu")
        num_rects = reader.read_u16_le()
        rectangles: list[BitmapRectangle] = []

        for i in range(num_rects):
            if reader.remaining() < 18:
                raise PduParseError(
                    pdu_type="BitmapUpdatePdu",
                    offset=reader.offset,
                    description=f"truncated bitmap rectangle {i}",
                )
            dest_left = reader.read_u16_le()
            dest_top = reader.read_u16_le()
            dest_right = reader.read_u16_le()
            dest_bottom = reader.read_u16_le()
            width = reader.read_u16_le()
            height = reader.read_u16_le()
            bpp = reader.read_u16_le()
            flags = reader.read_u16_le()
            compressed = bool(flags & 0x0001)
            data_length = reader.read_u16_le()

            if reader.remaining() < data_length:
                raise PduParseError(
                    pdu_type="BitmapUpdatePdu",
                    offset=reader.offset,
                    description=(
                        f"bitmap rectangle {i} data truncated: "
                        f"need {data_length} bytes, have {reader.remaining()}"
                    ),
                )
            bitmap_data = reader.read_bytes(data_length)

            rectangles.append(BitmapRectangle(
                dest_left=dest_left,
                dest_top=dest_top,
                dest_right=dest_right,
                dest_bottom=dest_bottom,
                width=width,
                height=height,
                bpp=bpp,
                compressed=compressed,
                data=bitmap_data,
            ))

        return cls(rectangles=rectangles)

    def serialize(self) -> bytes:
        """Serialize the Bitmap Update PDU to binary format."""
        from arrdipi.pdu.base import ByteWriter
        writer = ByteWriter()
        writer.write_u16_le(len(self.rectangles))
        for rect in self.rectangles:
            writer.write_u16_le(rect.dest_left)
            writer.write_u16_le(rect.dest_top)
            writer.write_u16_le(rect.dest_right)
            writer.write_u16_le(rect.dest_bottom)
            writer.write_u16_le(rect.width)
            writer.write_u16_le(rect.height)
            writer.write_u16_le(rect.bpp)
            flags = 0x0001 if rect.compressed else 0x0000
            writer.write_u16_le(flags)
            writer.write_u16_le(len(rect.data))
            writer.write_bytes(rect.data)
        return writer.to_bytes()


# --- Order Update PDU ---

@dataclass
class OrderEntry:
    """A parsed drawing order entry."""
    order_class: str  # 'primary', 'secondary', 'alternate_secondary'
    order_type: int
    fields: dict[str, Any] = field(default_factory=dict)
    data: bytes = b''


@dataclass
class OrderUpdatePdu(Pdu):
    """Order Update PDU containing one or more drawing orders.

    Per [MS-RDPEGDI] 2.2.2.1.
    """
    orders: list[OrderEntry] = field(default_factory=list)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse an Order Update PDU from binary data.

        Args:
            data: Raw PDU data (after update type field).

        Returns:
            Parsed OrderUpdatePdu instance.
        """
        reader = ByteReader(data, "OrderUpdatePdu")

        if reader.remaining() < 2:
            raise PduParseError(
                pdu_type="OrderUpdatePdu",
                offset=reader.offset,
                description="truncated order count",
            )

        num_orders = reader.read_u16_le()
        orders: list[OrderEntry] = []
        last_order_type = 0

        for _ in range(num_orders):
            if reader.remaining() < 1:
                break

            control_flags = reader.read_u8()

            if not (control_flags & OrderFlags.STANDARD):
                # Alternate secondary order
                order_type = (control_flags >> 2) & 0x0F
                if reader.remaining() < 2:
                    break
                order_length = reader.read_u16_le()
                if reader.remaining() < order_length:
                    break
                order_data = reader.read_bytes(order_length)
                orders.append(OrderEntry(
                    order_class='alternate_secondary',
                    order_type=order_type,
                    data=order_data,
                ))
                continue

            if control_flags & OrderFlags.SECONDARY:
                # Secondary order
                if reader.remaining() < 5:
                    break
                order_length = reader.read_u16_le()
                _extra_flags = reader.read_u16_le()
                order_type = reader.read_u8()
                remaining_length = order_length + 7 - 6  # Adjust for header
                if remaining_length > 0 and reader.remaining() >= remaining_length:
                    order_data = reader.read_bytes(remaining_length)
                else:
                    order_data = reader.read_bytes(
                        min(reader.remaining(), max(0, remaining_length))
                    )
                orders.append(OrderEntry(
                    order_class='secondary',
                    order_type=order_type,
                    data=order_data,
                ))
                continue

            # Primary order
            if control_flags & OrderFlags.TYPE_CHANGE:
                if reader.remaining() < 1:
                    break
                order_type = reader.read_u8()
                last_order_type = order_type
            else:
                order_type = last_order_type

            # Parse bounds if present
            bounds: dict[str, int] = {}
            if control_flags & OrderFlags.BOUNDS:
                if not (control_flags & OrderFlags.ZERO_BOUNDS_DELTAS):
                    if reader.remaining() >= 1:
                        bounds_flags = reader.read_u8()
                        # Parse bound coordinates based on flags
                        bounds = _parse_bounds(reader, bounds_flags)

            # Parse field encoding bytes
            field_bytes = _get_field_bytes(control_flags, order_type, reader)

            # Parse the primary order fields based on type
            fields = _parse_primary_fields(
                order_type, field_bytes, reader, control_flags
            )
            fields.update(bounds)

            orders.append(OrderEntry(
                order_class='primary',
                order_type=order_type,
                fields=fields,
            ))

        return cls(orders=orders)

    def serialize(self) -> bytes:
        """Serialize the Order Update PDU to binary format."""
        from arrdipi.pdu.base import ByteWriter
        writer = ByteWriter()
        writer.write_u16_le(len(self.orders))
        # Minimal serialization - orders are primarily server-to-client
        for order in self.orders:
            if order.order_class == 'primary':
                flags = OrderFlags.STANDARD | OrderFlags.TYPE_CHANGE
                writer.write_u8(flags)
                writer.write_u8(order.order_type)
            elif order.order_class == 'secondary':
                flags = OrderFlags.STANDARD | OrderFlags.SECONDARY
                writer.write_u8(flags)
                writer.write_u16_le(len(order.data))
                writer.write_u16_le(0)  # extra flags
                writer.write_u8(order.order_type)
                writer.write_bytes(order.data)
            elif order.order_class == 'alternate_secondary':
                flags = (order.order_type << 2) & 0xFF
                writer.write_u8(flags)
                writer.write_u16_le(len(order.data))
                writer.write_bytes(order.data)
        return writer.to_bytes()


# --- Helper Functions ---

def _parse_bounds(reader: ByteReader, bounds_flags: int) -> dict[str, int]:
    """Parse bounding rectangle from order data."""
    bounds: dict[str, int] = {}
    if bounds_flags & 0x01:
        if reader.remaining() >= 2:
            bounds['bounds_left'] = reader.read_u16_le()
    if bounds_flags & 0x02:
        if reader.remaining() >= 2:
            bounds['bounds_top'] = reader.read_u16_le()
    if bounds_flags & 0x04:
        if reader.remaining() >= 2:
            bounds['bounds_right'] = reader.read_u16_le()
    if bounds_flags & 0x08:
        if reader.remaining() >= 2:
            bounds['bounds_bottom'] = reader.read_u16_le()
    if bounds_flags & 0x10:
        if reader.remaining() >= 1:
            bounds['bounds_left'] = _sign_extend_8(reader.read_u8())
    if bounds_flags & 0x20:
        if reader.remaining() >= 1:
            bounds['bounds_top'] = _sign_extend_8(reader.read_u8())
    if bounds_flags & 0x40:
        if reader.remaining() >= 1:
            bounds['bounds_right'] = _sign_extend_8(reader.read_u8())
    if bounds_flags & 0x80:
        if reader.remaining() >= 1:
            bounds['bounds_bottom'] = _sign_extend_8(reader.read_u8())
    return bounds


def _get_field_bytes(
    control_flags: int, order_type: int, reader: ByteReader
) -> int:
    """Get the field encoding flags for a primary order."""
    # Determine number of field bytes based on order type
    num_field_bytes = _field_byte_count(order_type)

    if control_flags & OrderFlags.ZERO_FIELD_BYTE_BIT0:
        if num_field_bytes > 0:
            num_field_bytes -= 1
    if control_flags & OrderFlags.ZERO_FIELD_BYTE_BIT1:
        if num_field_bytes > 1:
            num_field_bytes -= 1

    field_flags = 0
    for i in range(num_field_bytes):
        if reader.remaining() >= 1:
            field_flags |= reader.read_u8() << (i * 8)

    return field_flags


def _field_byte_count(order_type: int) -> int:
    """Return the number of field encoding bytes for a given order type."""
    # Per [MS-RDPEGDI] each order type has a fixed number of fields
    field_counts: dict[int, int] = {
        0x00: 1,  # DstBlt - 5 fields -> 1 byte
        0x01: 2,  # PatBlt - 12 fields -> 2 bytes
        0x02: 1,  # ScrBlt - 7 fields -> 1 byte
        0x09: 2,  # LineTo - 10 fields -> 2 bytes
        0x0A: 1,  # OpaqueRect - 7 fields -> 1 byte
        0x0D: 2,  # MemBlt - 9 fields -> 2 bytes
        0x0E: 3,  # Mem3Blt - 16 fields -> 3 bytes
        0x0F: 2,  # MultiDstBlt - 7 fields -> 1 byte
        0x10: 2,  # MultiPatBlt - 14 fields -> 2 bytes
        0x11: 2,  # MultiScrBlt - 9 fields -> 2 bytes
        0x12: 2,  # MultiOpaqueRect - 9 fields -> 2 bytes
        0x1B: 3,  # GlyphIndex - 22 fields -> 3 bytes
    }
    return field_counts.get(order_type, 1)


def _parse_primary_fields(
    order_type: int,
    field_flags: int,
    reader: ByteReader,
    control_flags: int,
) -> dict[str, Any]:
    """Parse primary order fields based on type and field flags.

    Uses delta encoding: only fields indicated by field_flags are present.
    """
    fields: dict[str, Any] = {}
    delta = bool(control_flags & OrderFlags.DELTA_COORDINATES)

    match order_type:
        case 0x00:  # DstBlt
            fields = _parse_dstblt_fields(field_flags, reader, delta)
        case 0x01:  # PatBlt
            fields = _parse_patblt_fields(field_flags, reader, delta)
        case 0x02:  # ScrBlt
            fields = _parse_scrblt_fields(field_flags, reader, delta)
        case 0x09:  # LineTo
            fields = _parse_lineto_fields(field_flags, reader, delta)
        case 0x0A:  # OpaqueRect
            fields = _parse_opaque_rect_fields(field_flags, reader, delta)
        case 0x0D:  # MemBlt
            fields = _parse_memblt_fields(field_flags, reader, delta)
        case 0x0E:  # Mem3Blt
            fields = _parse_mem3blt_fields(field_flags, reader, delta)
        case 0x1B:  # GlyphIndex
            fields = _parse_glyph_index_fields(field_flags, reader, delta)
        case _:
            pass  # Unknown order type

    return fields


def _read_coord(reader: ByteReader, delta: bool) -> int | None:
    """Read a coordinate value, either absolute or delta-encoded."""
    if delta:
        if reader.remaining() >= 1:
            return _sign_extend_8(reader.read_u8())
    else:
        if reader.remaining() >= 2:
            return reader.read_u16_le()
    return None


def _read_color(reader: ByteReader) -> int | None:
    """Read a 3-byte RGB color value."""
    if reader.remaining() >= 3:
        r = reader.read_u8()
        g = reader.read_u8()
        b = reader.read_u8()
        return r | (g << 8) | (b << 16)
    return None


def _sign_extend_8(value: int) -> int:
    """Sign-extend an 8-bit value to a signed integer."""
    if value & 0x80:
        return value - 256
    return value


def _parse_dstblt_fields(
    flags: int, reader: ByteReader, delta: bool
) -> dict[str, Any]:
    """Parse DstBlt order fields."""
    fields: dict[str, Any] = {}
    if flags & 0x01:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['x'] = v
    if flags & 0x02:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['y'] = v
    if flags & 0x04:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['width'] = v
    if flags & 0x08:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['height'] = v
    if flags & 0x10:
        if reader.remaining() >= 1:
            fields['rop'] = reader.read_u8()
    return fields


def _parse_patblt_fields(
    flags: int, reader: ByteReader, delta: bool
) -> dict[str, Any]:
    """Parse PatBlt order fields."""
    fields: dict[str, Any] = {}
    if flags & 0x0001:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['x'] = v
    if flags & 0x0002:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['y'] = v
    if flags & 0x0004:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['width'] = v
    if flags & 0x0008:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['height'] = v
    if flags & 0x0010:
        if reader.remaining() >= 1:
            fields['rop'] = reader.read_u8()
    if flags & 0x0020:
        c = _read_color(reader)
        if c is not None:
            fields['bg_color'] = c
    if flags & 0x0040:
        c = _read_color(reader)
        if c is not None:
            fields['fg_color'] = c
    if flags & 0x0080:
        if reader.remaining() >= 1:
            fields['brush_org_x'] = reader.read_u8()
    if flags & 0x0100:
        if reader.remaining() >= 1:
            fields['brush_org_y'] = reader.read_u8()
    if flags & 0x0200:
        if reader.remaining() >= 1:
            fields['brush_style'] = reader.read_u8()
    if flags & 0x0400:
        if reader.remaining() >= 1:
            fields['brush_hatch'] = reader.read_u8()
    if flags & 0x0800:
        if reader.remaining() >= 7:
            fields['brush_extra'] = reader.read_bytes(7)
    return fields


def _parse_scrblt_fields(
    flags: int, reader: ByteReader, delta: bool
) -> dict[str, Any]:
    """Parse ScrBlt order fields."""
    fields: dict[str, Any] = {}
    if flags & 0x01:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['x'] = v
    if flags & 0x02:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['y'] = v
    if flags & 0x04:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['width'] = v
    if flags & 0x08:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['height'] = v
    if flags & 0x10:
        if reader.remaining() >= 1:
            fields['rop'] = reader.read_u8()
    if flags & 0x20:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['src_x'] = v
    if flags & 0x40:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['src_y'] = v
    return fields


def _parse_lineto_fields(
    flags: int, reader: ByteReader, delta: bool
) -> dict[str, Any]:
    """Parse LineTo order fields."""
    fields: dict[str, Any] = {}
    if flags & 0x0001:
        if reader.remaining() >= 2:
            fields['line_back_mode'] = reader.read_u16_le()
    if flags & 0x0002:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['line_start_x'] = v
    if flags & 0x0004:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['line_start_y'] = v
    if flags & 0x0008:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['line_end_x'] = v
    if flags & 0x0010:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['line_end_y'] = v
    if flags & 0x0020:
        c = _read_color(reader)
        if c is not None:
            fields['line_bg_color'] = c
    if flags & 0x0040:
        if reader.remaining() >= 1:
            fields['line_pen_style'] = reader.read_u8()
    if flags & 0x0080:
        if reader.remaining() >= 1:
            fields['line_pen_width'] = reader.read_u8()
    if flags & 0x0100:
        c = _read_color(reader)
        if c is not None:
            fields['line_fg_color'] = c
    return fields


def _parse_opaque_rect_fields(
    flags: int, reader: ByteReader, delta: bool
) -> dict[str, Any]:
    """Parse OpaqueRect order fields."""
    fields: dict[str, Any] = {}
    if flags & 0x01:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['x'] = v
    if flags & 0x02:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['y'] = v
    if flags & 0x04:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['width'] = v
    if flags & 0x08:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['height'] = v
    if flags & 0x10:
        if reader.remaining() >= 1:
            fields['fg_color'] = reader.read_u8()  # Red byte
    if flags & 0x20:
        if reader.remaining() >= 1:
            # Green byte - combine with existing
            g = reader.read_u8()
            existing = fields.get('fg_color', 0)
            fields['fg_color'] = existing | (g << 8)
    if flags & 0x40:
        if reader.remaining() >= 1:
            # Blue byte - combine with existing
            b = reader.read_u8()
            existing = fields.get('fg_color', 0)
            fields['fg_color'] = existing | (b << 16)
    return fields


def _parse_memblt_fields(
    flags: int, reader: ByteReader, delta: bool
) -> dict[str, Any]:
    """Parse MemBlt order fields."""
    fields: dict[str, Any] = {}
    if flags & 0x0001:
        if reader.remaining() >= 2:
            fields['cache_id'] = reader.read_u16_le()
    if flags & 0x0002:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['x'] = v
    if flags & 0x0004:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['y'] = v
    if flags & 0x0008:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['width'] = v
    if flags & 0x0010:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['height'] = v
    if flags & 0x0020:
        if reader.remaining() >= 1:
            fields['rop'] = reader.read_u8()
    if flags & 0x0040:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['src_x'] = v
    if flags & 0x0080:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['src_y'] = v
    if flags & 0x0100:
        if reader.remaining() >= 2:
            fields['cache_index'] = reader.read_u16_le()
    return fields


def _parse_mem3blt_fields(
    flags: int, reader: ByteReader, delta: bool
) -> dict[str, Any]:
    """Parse Mem3Blt order fields."""
    # Mem3Blt has the same base fields as MemBlt plus brush and colors
    fields = _parse_memblt_fields(flags & 0x01FF, reader, delta)
    if flags & 0x0200:
        c = _read_color(reader)
        if c is not None:
            fields['bg_color'] = c
    if flags & 0x0400:
        c = _read_color(reader)
        if c is not None:
            fields['fg_color'] = c
    if flags & 0x0800:
        if reader.remaining() >= 1:
            fields['brush_org_x'] = reader.read_u8()
    if flags & 0x1000:
        if reader.remaining() >= 1:
            fields['brush_org_y'] = reader.read_u8()
    if flags & 0x2000:
        if reader.remaining() >= 1:
            fields['brush_style'] = reader.read_u8()
    if flags & 0x4000:
        if reader.remaining() >= 1:
            fields['brush_hatch'] = reader.read_u8()
    if flags & 0x8000:
        if reader.remaining() >= 7:
            fields['brush_extra'] = reader.read_bytes(7)
    return fields


def _parse_glyph_index_fields(
    flags: int, reader: ByteReader, delta: bool
) -> dict[str, Any]:
    """Parse GlyphIndex order fields."""
    fields: dict[str, Any] = {}
    if flags & 0x000001:
        if reader.remaining() >= 1:
            fields['glyph_cache_id'] = reader.read_u8()
    if flags & 0x000002:
        if reader.remaining() >= 1:
            fields['glyph_fl_accel'] = reader.read_u8()
    if flags & 0x000004:
        if reader.remaining() >= 1:
            fields['glyph_ul_char_inc'] = reader.read_u8()
    if flags & 0x000008:
        if reader.remaining() >= 1:
            fields['glyph_f_op_redundant'] = reader.read_u8()
    if flags & 0x000010:
        c = _read_color(reader)
        if c is not None:
            fields['bg_color'] = c
    if flags & 0x000020:
        c = _read_color(reader)
        if c is not None:
            fields['fg_color'] = c
    if flags & 0x000040:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['glyph_bk_left'] = v
    if flags & 0x000080:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['glyph_bk_top'] = v
    if flags & 0x000100:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['glyph_bk_right'] = v
    if flags & 0x000200:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['glyph_bk_bottom'] = v
    if flags & 0x000400:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['glyph_op_left'] = v
    if flags & 0x000800:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['glyph_op_top'] = v
    if flags & 0x001000:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['glyph_op_right'] = v
    if flags & 0x002000:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['glyph_op_bottom'] = v
    if flags & 0x004000:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['glyph_x'] = v
    if flags & 0x008000:
        v = _read_coord(reader, delta)
        if v is not None:
            fields['glyph_y'] = v
    if flags & 0x010000:
        if reader.remaining() >= 1:
            data_len = reader.read_u8()
            if reader.remaining() >= data_len:
                fields['glyph_data'] = reader.read_bytes(data_len)
    return fields
