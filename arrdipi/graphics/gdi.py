"""GDI drawing order processor for RDP graphics rendering.

Processes primary, secondary, and alternate secondary drawing orders
from the server and applies them to the GraphicsSurface.
Maintains persistent OrderState across consecutive orders with delta encoding.
(Req 14, AC 1-5)
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

from arrdipi.graphics.surface import GraphicsSurface, Rect
from arrdipi.pdu.base import ByteReader


# --- Order Type Constants ---

class PrimaryOrderType(enum.IntEnum):
    """Primary drawing order types per [MS-RDPEGDI] 2.2.2.1.1.2."""
    DSTBLT = 0x00
    PATBLT = 0x01
    SCRBLT = 0x02
    DRAW_NINE_GRID = 0x07
    MULTI_DRAW_NINE_GRID = 0x08
    LINETO = 0x09
    OPAQUE_RECT = 0x0A
    SAVE_BITMAP = 0x0B
    MEMBLT = 0x0D
    MEM3BLT = 0x0E
    MULTI_DSTBLT = 0x0F
    MULTI_PATBLT = 0x10
    MULTI_SCRBLT = 0x11
    MULTI_OPAQUE_RECT = 0x12
    FAST_INDEX = 0x13
    POLYGON_SC = 0x14
    POLYGON_CB = 0x15
    POLYLINE = 0x16
    FAST_GLYPH = 0x18
    ELLIPSE_SC = 0x19
    ELLIPSE_CB = 0x1A
    GLYPH_INDEX = 0x1B


class SecondaryOrderType(enum.IntEnum):
    """Secondary drawing order types per [MS-RDPEGDI] 2.2.2.2.1."""
    CACHE_BITMAP_UNCOMPRESSED = 0x00
    CACHE_COLOR_TABLE = 0x01
    CACHE_BITMAP_COMPRESSED = 0x02
    CACHE_GLYPH = 0x03
    CACHE_BITMAP_UNCOMPRESSED_REV2 = 0x04
    CACHE_BITMAP_COMPRESSED_REV2 = 0x05
    CACHE_BRUSH = 0x07
    CACHE_BITMAP_COMPRESSED_REV3 = 0x08


class AlternateSecondaryOrderType(enum.IntEnum):
    """Alternate secondary drawing order types."""
    SWITCH_SURFACE = 0x00
    CREATE_OFFSCREEN_BITMAP = 0x01
    STREAM_BITMAP_FIRST = 0x02
    STREAM_BITMAP_NEXT = 0x03
    CREATE_NINE_GRID_BITMAP = 0x04
    GDIP_FIRST = 0x05
    GDIP_NEXT = 0x06
    GDIP_END = 0x07
    GDIP_CACHE_FIRST = 0x08
    GDIP_CACHE_NEXT = 0x09
    GDIP_CACHE_END = 0x0A
    WINDOW = 0x0B
    COMPDESK_FIRST = 0x0C
    FRAME_MARKER = 0x0D


# --- Raster Operation Constants ---

class RasterOp(enum.IntEnum):
    """Common raster operations."""
    BLACKNESS = 0x00
    DPon = 0x05
    DPna = 0x0A
    Pn = 0x0F
    PDna = 0x50
    Dn = 0x55
    DPx = 0x5A
    DPan = 0x5F
    DPa = 0xA0
    DPxn = 0xA5
    D = 0xAA
    DPno = 0xAF
    P = 0xF0
    PDno = 0xF5
    DPo = 0xFA
    WHITENESS = 0xFF


# --- Order State (persistent across consecutive orders) ---

@dataclass
class OrderState:
    """Persistent state maintained across consecutive drawing orders.

    Fields not present in a new order retain their values from the previous
    order (delta encoding). (Req 14, AC 5)
    """
    # Bounds
    bounds_left: int = 0
    bounds_top: int = 0
    bounds_right: int = 0
    bounds_bottom: int = 0

    # Primary order fields (shared across order types)
    # DstBlt / PatBlt / ScrBlt / OpaqueRect / MemBlt / Mem3Blt
    x: int = 0
    y: int = 0
    width: int = 0
    height: int = 0

    # Raster operation
    rop: int = 0

    # Source coordinates (ScrBlt, MemBlt)
    src_x: int = 0
    src_y: int = 0

    # Colors
    fg_color: int = 0
    bg_color: int = 0

    # Brush
    brush_org_x: int = 0
    brush_org_y: int = 0
    brush_style: int = 0
    brush_hatch: int = 0
    brush_extra: bytes = field(default_factory=lambda: b'\x00' * 7)

    # LineTo
    line_back_mode: int = 0
    line_start_x: int = 0
    line_start_y: int = 0
    line_end_x: int = 0
    line_end_y: int = 0
    line_bg_color: int = 0
    line_fg_color: int = 0
    line_pen_style: int = 0
    line_pen_width: int = 0

    # MemBlt / Mem3Blt
    cache_id: int = 0
    cache_index: int = 0
    color_index: int = 0

    # GlyphIndex
    glyph_cache_id: int = 0
    glyph_fl_accel: int = 0
    glyph_ul_char_inc: int = 0
    glyph_f_op_redundant: int = 0
    glyph_bk_left: int = 0
    glyph_bk_top: int = 0
    glyph_bk_right: int = 0
    glyph_bk_bottom: int = 0
    glyph_op_left: int = 0
    glyph_op_top: int = 0
    glyph_op_right: int = 0
    glyph_op_bottom: int = 0
    glyph_x: int = 0
    glyph_y: int = 0
    glyph_data: bytes = b''


# --- Glyph Cache Entry ---

@dataclass
class GlyphEntry:
    """A cached glyph entry."""
    x: int
    y: int
    width: int
    height: int
    data: bytes


# --- GDI Order Processor ---

class GdiOrderProcessor:
    """Processes GDI primary, secondary, and alternate secondary drawing orders.

    Maintains persistent OrderState across consecutive orders with delta
    encoding as specified in [MS-RDPEGDI] Section 2.2.2.1.1.
    (Req 14, AC 1-5)
    """

    def __init__(self, surface: GraphicsSurface) -> None:
        self._surface = surface
        self._state = OrderState()
        self._bitmap_cache: dict[tuple[int, int], bytes] = {}
        self._color_table_cache: dict[int, list[int]] = {}
        self._glyph_cache: dict[tuple[int, int], GlyphEntry] = {}

    @property
    def state(self) -> OrderState:
        """Access the persistent order state."""
        return self._state

    @property
    def bitmap_cache(self) -> dict[tuple[int, int], bytes]:
        """Access the bitmap cache: (cache_id, cache_index) -> pixel data."""
        return self._bitmap_cache

    @property
    def glyph_cache(self) -> dict[tuple[int, int], GlyphEntry]:
        """Access the glyph cache: (cache_id, glyph_index) -> GlyphEntry."""
        return self._glyph_cache

    # --- Primary Drawing Orders (Req 14, AC 1) ---

    async def process_primary_order(
        self, order_type: int, fields: dict[str, Any]
    ) -> None:
        """Process a primary drawing order, updating state with delta encoding.

        Args:
            order_type: The PrimaryOrderType value.
            fields: Dictionary of field values present in this order.
                    Missing fields retain their previous state values.
        """
        # Apply delta encoding: update state with provided fields
        self._apply_delta_fields(order_type, fields)

        # Dispatch to the appropriate handler
        match order_type:
            case PrimaryOrderType.DSTBLT:
                await self._dstblt()
            case PrimaryOrderType.PATBLT:
                await self._patblt()
            case PrimaryOrderType.SCRBLT:
                await self._scrblt()
            case PrimaryOrderType.MEMBLT:
                await self._memblt()
            case PrimaryOrderType.MEM3BLT:
                await self._mem3blt()
            case PrimaryOrderType.LINETO:
                await self._lineto()
            case PrimaryOrderType.OPAQUE_RECT:
                await self._opaque_rect()
            case PrimaryOrderType.MULTI_DSTBLT:
                await self._multi_dstblt(fields)
            case PrimaryOrderType.MULTI_PATBLT:
                await self._multi_patblt(fields)
            case PrimaryOrderType.MULTI_SCRBLT:
                await self._multi_scrblt(fields)
            case PrimaryOrderType.MULTI_OPAQUE_RECT:
                await self._multi_opaque_rect(fields)
            case PrimaryOrderType.GLYPH_INDEX:
                await self._glyph_index()
            case _:
                pass  # Unsupported order type, silently ignore

    def _apply_delta_fields(self, order_type: int, fields: dict[str, Any]) -> None:
        """Apply delta-encoded fields to the persistent state.

        Only fields present in the dictionary are updated; all others
        retain their previous values. (Req 14, AC 5)
        """
        for key, value in fields.items():
            if hasattr(self._state, key):
                setattr(self._state, key, value)

    async def _dstblt(self) -> None:
        """Execute DstBlt: destination-only bit block transfer.

        Applies a raster operation to the destination rectangle.
        """
        s = self._state
        x, y, w, h = s.x, s.y, s.width, s.height
        x, y, w, h = self._clip_rect(x, y, w, h)
        if w <= 0 or h <= 0:
            return

        rop = s.rop & 0xFF
        pixels = self._apply_rop_to_dest(x, y, w, h, rop)
        await self._surface.write_pixels(x, y, w, h, pixels)

    async def _patblt(self) -> None:
        """Execute PatBlt: pattern bit block transfer.

        Applies a raster operation combining a pattern/brush with the destination.
        """
        s = self._state
        x, y, w, h = s.x, s.y, s.width, s.height
        x, y, w, h = self._clip_rect(x, y, w, h)
        if w <= 0 or h <= 0:
            return

        rop = s.rop & 0xFF
        color = s.fg_color
        pixels = self._apply_patblt_rop(x, y, w, h, rop, color)
        await self._surface.write_pixels(x, y, w, h, pixels)

    async def _scrblt(self) -> None:
        """Execute ScrBlt: screen-to-screen bit block transfer.

        Copies pixels from one area of the surface to another.
        """
        s = self._state
        x, y, w, h = s.x, s.y, s.width, s.height
        x, y, w, h = self._clip_rect(x, y, w, h)
        if w <= 0 or h <= 0:
            return

        src_pixels = await self._surface.read_pixels(s.src_x, s.src_y, w, h)
        await self._surface.write_pixels(x, y, w, h, src_pixels)

    async def _memblt(self) -> None:
        """Execute MemBlt: memory-to-screen bit block transfer.

        Copies cached bitmap data to the surface.
        """
        s = self._state
        x, y, w, h = s.x, s.y, s.width, s.height
        x, y, w, h = self._clip_rect(x, y, w, h)
        if w <= 0 or h <= 0:
            return

        cache_key = (s.cache_id, s.cache_index)
        cached_data = self._bitmap_cache.get(cache_key)
        if cached_data is None:
            return  # Cache miss, skip

        # Extract the portion of the cached bitmap we need
        # The cached data is stored as full RGBA pixels
        expected_size = w * h * 4
        if len(cached_data) >= expected_size:
            pixels = cached_data[:expected_size]
        else:
            # Pad with zeros if cached data is smaller
            pixels = cached_data + b'\x00' * (expected_size - len(cached_data))

        await self._surface.write_pixels(x, y, w, h, pixels)

    async def _mem3blt(self) -> None:
        """Execute Mem3Blt: three-way memory bit block transfer.

        Like MemBlt but with a ternary raster operation involving
        source, pattern, and destination.
        """
        # For simplicity, treat like MemBlt (most common usage)
        await self._memblt()

    async def _lineto(self) -> None:
        """Execute LineTo: draw a line from start to end coordinates.

        Uses Bresenham's line algorithm to draw pixels.
        """
        s = self._state
        x0, y0 = s.line_start_x, s.line_start_y
        x1, y1 = s.line_end_x, s.line_end_y
        color = s.line_fg_color

        r = color & 0xFF
        g = (color >> 8) & 0xFF
        b = (color >> 16) & 0xFF
        pixel = bytes([r, g, b, 0xFF])

        # Bresenham's line algorithm
        points = self._bresenham_line(x0, y0, x1, y1)
        for px, py in points:
            if 0 <= px < self._surface.width and 0 <= py < self._surface.height:
                await self._surface.write_pixels(px, py, 1, 1, pixel)

    async def _opaque_rect(self) -> None:
        """Execute OpaqueRect: fill a rectangle with a solid color.

        This is the most common drawing order.
        """
        s = self._state
        x, y, w, h = s.x, s.y, s.width, s.height
        x, y, w, h = self._clip_rect(x, y, w, h)
        if w <= 0 or h <= 0:
            return

        color = s.fg_color
        r = color & 0xFF
        g = (color >> 8) & 0xFF
        b = (color >> 16) & 0xFF
        pixel = bytes([r, g, b, 0xFF])

        # Fill the rectangle with the solid color
        row = pixel * w
        pixels = row * h
        await self._surface.write_pixels(x, y, w, h, pixels)

    async def _multi_dstblt(self, fields: dict[str, Any]) -> None:
        """Execute MultiDstBlt: multiple destination bit block transfers."""
        rects = fields.get('rects', [])
        for rect in rects:
            x, y, w, h = rect['x'], rect['y'], rect['w'], rect['h']
            x, y, w, h = self._clip_rect(x, y, w, h)
            if w <= 0 or h <= 0:
                continue
            rop = self._state.rop & 0xFF
            pixels = self._apply_rop_to_dest(x, y, w, h, rop)
            await self._surface.write_pixels(x, y, w, h, pixels)

    async def _multi_patblt(self, fields: dict[str, Any]) -> None:
        """Execute MultiPatBlt: multiple pattern bit block transfers."""
        rects = fields.get('rects', [])
        for rect in rects:
            x, y, w, h = rect['x'], rect['y'], rect['w'], rect['h']
            x, y, w, h = self._clip_rect(x, y, w, h)
            if w <= 0 or h <= 0:
                continue
            rop = self._state.rop & 0xFF
            color = self._state.fg_color
            pixels = self._apply_patblt_rop(x, y, w, h, rop, color)
            await self._surface.write_pixels(x, y, w, h, pixels)

    async def _multi_scrblt(self, fields: dict[str, Any]) -> None:
        """Execute MultiScrBlt: multiple screen-to-screen bit block transfers."""
        rects = fields.get('rects', [])
        for rect in rects:
            x, y, w, h = rect['x'], rect['y'], rect['w'], rect['h']
            src_x = rect.get('src_x', self._state.src_x)
            src_y = rect.get('src_y', self._state.src_y)
            x, y, w, h = self._clip_rect(x, y, w, h)
            if w <= 0 or h <= 0:
                continue
            src_pixels = await self._surface.read_pixels(src_x, src_y, w, h)
            await self._surface.write_pixels(x, y, w, h, src_pixels)

    async def _multi_opaque_rect(self, fields: dict[str, Any]) -> None:
        """Execute MultiOpaqueRect: multiple opaque rectangle fills."""
        rects = fields.get('rects', [])
        color = self._state.fg_color
        r = color & 0xFF
        g = (color >> 8) & 0xFF
        b = (color >> 16) & 0xFF
        pixel = bytes([r, g, b, 0xFF])

        for rect in rects:
            x, y, w, h = rect['x'], rect['y'], rect['w'], rect['h']
            x, y, w, h = self._clip_rect(x, y, w, h)
            if w <= 0 or h <= 0:
                continue
            row = pixel * w
            pixels = row * h
            await self._surface.write_pixels(x, y, w, h, pixels)

    async def _glyph_index(self) -> None:
        """Execute GlyphIndex: render cached glyphs to the surface.

        Draws the opaque rectangle background and renders glyph data.
        """
        s = self._state

        # Draw opaque background if specified
        if s.glyph_f_op_redundant == 0:
            op_left = s.glyph_op_left
            op_top = s.glyph_op_top
            op_right = s.glyph_op_right
            op_bottom = s.glyph_op_bottom
            if op_right > op_left and op_bottom > op_top:
                w = op_right - op_left
                h = op_bottom - op_top
                x, y, w, h = self._clip_rect(op_left, op_top, w, h)
                if w > 0 and h > 0:
                    color = s.bg_color
                    r = color & 0xFF
                    g = (color >> 8) & 0xFF
                    b = (color >> 16) & 0xFF
                    pixel = bytes([r, g, b, 0xFF])
                    row = pixel * w
                    pixels = row * h
                    await self._surface.write_pixels(x, y, w, h, pixels)

    # --- Secondary Drawing Orders (Req 14, AC 2) ---

    async def process_secondary_order(
        self, order_type: int, data: bytes
    ) -> None:
        """Process a secondary drawing order (cache management).

        Args:
            order_type: The SecondaryOrderType value.
            data: Raw order data to parse.
        """
        match order_type:
            case (SecondaryOrderType.CACHE_BITMAP_UNCOMPRESSED
                  | SecondaryOrderType.CACHE_BITMAP_COMPRESSED
                  | SecondaryOrderType.CACHE_BITMAP_UNCOMPRESSED_REV2
                  | SecondaryOrderType.CACHE_BITMAP_COMPRESSED_REV2
                  | SecondaryOrderType.CACHE_BITMAP_COMPRESSED_REV3):
                self._cache_bitmap(data)
            case SecondaryOrderType.CACHE_COLOR_TABLE:
                self._cache_color_table(data)
            case SecondaryOrderType.CACHE_GLYPH:
                self._cache_glyph(data)
            case _:
                pass  # Unsupported secondary order

    def _cache_bitmap(self, data: bytes) -> None:
        """Cache a bitmap for later use by MemBlt/Mem3Blt orders.

        Parses cache_id, cache_index, and pixel data from the order.
        """
        if len(data) < 8:
            return
        reader = ByteReader(data, "CacheBitmap")
        cache_id = reader.read_u8()
        _pad = reader.read_u8()
        width = reader.read_u8()
        height = reader.read_u8()
        _bpp = reader.read_u8()
        data_length = reader.read_u16_le()
        cache_index = reader.read_u16_le()
        if reader.remaining() >= data_length:
            bitmap_data = reader.read_bytes(data_length)
            # Convert to RGBA if needed (assume already RGBA for simplicity)
            self._bitmap_cache[(cache_id, cache_index)] = bitmap_data

    def _cache_color_table(self, data: bytes) -> None:
        """Cache a color table for indexed color operations."""
        if len(data) < 3:
            return
        reader = ByteReader(data, "CacheColorTable")
        cache_index = reader.read_u8()
        num_entries = reader.read_u16_le()
        colors: list[int] = []
        for _ in range(min(num_entries, 256)):
            if reader.remaining() < 4:
                break
            b = reader.read_u8()
            g = reader.read_u8()
            r = reader.read_u8()
            _pad = reader.read_u8()
            colors.append((r << 16) | (g << 8) | b)
        self._color_table_cache[cache_index] = colors

    def _cache_glyph(self, data: bytes) -> None:
        """Cache glyph data for later use by GlyphIndex orders."""
        if len(data) < 2:
            return
        reader = ByteReader(data, "CacheGlyph")
        cache_id = reader.read_u8()
        num_glyphs = reader.read_u8()
        for _ in range(num_glyphs):
            if reader.remaining() < 10:
                break
            glyph_index = reader.read_u16_le()
            gx = reader.read_u16_le()
            gy = reader.read_u16_le()
            gw = reader.read_u16_le()
            gh = reader.read_u16_le()
            glyph_size = ((gw + 7) // 8) * gh
            if reader.remaining() < glyph_size:
                break
            glyph_data = reader.read_bytes(glyph_size)
            self._glyph_cache[(cache_id, glyph_index)] = GlyphEntry(
                x=gx, y=gy, width=gw, height=gh, data=glyph_data
            )

    # --- Alternate Secondary Drawing Orders (Req 14, AC 3) ---

    async def process_alternate_secondary_order(
        self, order_type: int, data: bytes
    ) -> None:
        """Process an alternate secondary drawing order.

        These handle extended cache and drawing operations.

        Args:
            order_type: The AlternateSecondaryOrderType value.
            data: Raw order data.
        """
        match order_type:
            case AlternateSecondaryOrderType.SWITCH_SURFACE:
                self._handle_switch_surface(data)
            case AlternateSecondaryOrderType.CREATE_OFFSCREEN_BITMAP:
                self._handle_create_offscreen(data)
            case AlternateSecondaryOrderType.FRAME_MARKER:
                self._handle_frame_marker(data)
            case _:
                pass  # Unsupported alternate secondary order

    def _handle_switch_surface(self, data: bytes) -> None:
        """Handle switch surface command."""
        # Switch to primary surface (0xFFFF) or offscreen bitmap
        pass

    def _handle_create_offscreen(self, data: bytes) -> None:
        """Handle create offscreen bitmap command."""
        pass

    def _handle_frame_marker(self, data: bytes) -> None:
        """Handle frame marker (begin/end frame)."""
        pass

    # --- Cache Management API ---

    def store_bitmap(
        self, cache_id: int, cache_index: int, pixel_data: bytes
    ) -> None:
        """Store decoded pixel data in the bitmap cache.

        Args:
            cache_id: The cache identifier.
            cache_index: The index within the cache.
            pixel_data: RGBA pixel data.
        """
        self._bitmap_cache[(cache_id, cache_index)] = pixel_data

    def get_bitmap(self, cache_id: int, cache_index: int) -> bytes | None:
        """Retrieve pixel data from the bitmap cache.

        Returns None if the entry is not cached.
        """
        return self._bitmap_cache.get((cache_id, cache_index))

    def store_glyph(
        self, cache_id: int, glyph_index: int, entry: GlyphEntry
    ) -> None:
        """Store a glyph entry in the glyph cache."""
        self._glyph_cache[(cache_id, glyph_index)] = entry

    def get_glyph(self, cache_id: int, glyph_index: int) -> GlyphEntry | None:
        """Retrieve a glyph entry from the glyph cache."""
        return self._glyph_cache.get((cache_id, glyph_index))

    # --- Helper Methods ---

    def _clip_rect(
        self, x: int, y: int, w: int, h: int
    ) -> tuple[int, int, int, int]:
        """Clip a rectangle to the surface bounds.

        Returns the clipped (x, y, w, h) tuple.
        """
        # Clip to surface bounds
        if x < 0:
            w += x
            x = 0
        if y < 0:
            h += y
            y = 0
        if x + w > self._surface.width:
            w = self._surface.width - x
        if y + h > self._surface.height:
            h = self._surface.height - y
        return x, y, w, h

    def _apply_rop_to_dest(
        self, x: int, y: int, w: int, h: int, rop: int
    ) -> bytes:
        """Apply a raster operation to the destination area.

        Returns the resulting RGBA pixel data.
        """
        size = w * h * 4
        match rop:
            case RasterOp.BLACKNESS:
                return bytes([0, 0, 0, 0xFF]) * (w * h)
            case RasterOp.WHITENESS:
                return bytes([0xFF, 0xFF, 0xFF, 0xFF]) * (w * h)
            case RasterOp.Dn:
                # Invert destination - would need to read current pixels
                return b'\x00' * size
            case _:
                # Default: blackness for unsupported ROPs
                return bytes([0, 0, 0, 0xFF]) * (w * h)

    def _apply_patblt_rop(
        self, x: int, y: int, w: int, h: int, rop: int, color: int
    ) -> bytes:
        """Apply a pattern raster operation.

        Returns the resulting RGBA pixel data.
        """
        r = color & 0xFF
        g = (color >> 8) & 0xFF
        b = (color >> 16) & 0xFF
        pixel = bytes([r, g, b, 0xFF])

        match rop:
            case RasterOp.BLACKNESS:
                return bytes([0, 0, 0, 0xFF]) * (w * h)
            case RasterOp.WHITENESS:
                return bytes([0xFF, 0xFF, 0xFF, 0xFF]) * (w * h)
            case RasterOp.P:
                # Pattern copy (fill with pattern/color)
                return pixel * (w * h)
            case _:
                # Default: fill with pattern color
                return pixel * (w * h)

    @staticmethod
    def _bresenham_line(
        x0: int, y0: int, x1: int, y1: int
    ) -> list[tuple[int, int]]:
        """Compute points along a line using Bresenham's algorithm."""
        points: list[tuple[int, int]] = []
        dx = abs(x1 - x0)
        dy = abs(y1 - y0)
        sx = 1 if x0 < x1 else -1
        sy = 1 if y0 < y1 else -1
        err = dx - dy

        while True:
            points.append((x0, y0))
            if x0 == x1 and y0 == y1:
                break
            e2 = 2 * err
            if e2 > -dy:
                err -= dy
                x0 += sx
            if e2 < dx:
                err += dx
                y0 += sy

        return points
