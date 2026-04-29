"""Tests for GDI drawing order processor.

Tests cover:
- OpaqueRect fills surface correctly
- MemBlt reads from cache
- Delta encoding state persistence
- Secondary order cache management
- Alternate secondary order dispatch
"""

from __future__ import annotations

import asyncio

import pytest

from arrdipi.graphics.gdi import (
    AlternateSecondaryOrderType,
    GdiOrderProcessor,
    GlyphEntry,
    OrderState,
    PrimaryOrderType,
    RasterOp,
    SecondaryOrderType,
)
from arrdipi.graphics.surface import GraphicsSurface
from arrdipi.pdu.graphics_pdu import (
    BitmapRectangle,
    BitmapUpdatePdu,
    OrderEntry,
    OrderFlags,
    OrderUpdatePdu,
    UpdateType,
)


@pytest.fixture
def surface() -> GraphicsSurface:
    """Create a 100x100 test surface."""
    return GraphicsSurface(100, 100)


@pytest.fixture
def gdi(surface: GraphicsSurface) -> GdiOrderProcessor:
    """Create a GDI order processor with a test surface."""
    return GdiOrderProcessor(surface)


# --- OpaqueRect Tests ---


class TestOpaqueRect:
    """Test OpaqueRect fills surface correctly."""

    @pytest.mark.asyncio
    async def test_opaque_rect_fills_with_solid_color(
        self, gdi: GdiOrderProcessor, surface: GraphicsSurface
    ) -> None:
        """OpaqueRect should fill the specified rectangle with a solid color."""
        # Color 0xFF0000 in RDP format is R=0x00, G=0x00, B=0xFF (BGR)
        # But our implementation stores as R | (G << 8) | (B << 16)
        # So color=0x00FF00 means R=0x00, G=0xFF, B=0x00
        color = 0x00FF00  # Green: R=0, G=255, B=0
        fields = {
            'x': 10,
            'y': 10,
            'width': 5,
            'height': 5,
            'fg_color': color,
        }
        await gdi.process_primary_order(PrimaryOrderType.OPAQUE_RECT, fields)

        # Read back the pixels
        pixels = await surface.read_pixels(10, 10, 5, 5)
        # Each pixel should be [R=0, G=255, B=0, A=255]
        expected_pixel = bytes([0x00, 0xFF, 0x00, 0xFF])
        for i in range(25):
            offset = i * 4
            assert pixels[offset:offset + 4] == expected_pixel, (
                f"Pixel {i} mismatch: got {pixels[offset:offset+4].hex()}"
            )

    @pytest.mark.asyncio
    async def test_opaque_rect_red_color(
        self, gdi: GdiOrderProcessor, surface: GraphicsSurface
    ) -> None:
        """OpaqueRect with red color fills correctly."""
        color = 0x0000FF  # R=255, G=0, B=0 (stored as R | G<<8 | B<<16)
        # Wait, the color format: color & 0xFF = R, (color >> 8) & 0xFF = G, (color >> 16) & 0xFF = B
        # So color = 0x0000FF means R=0xFF, G=0x00, B=0x00
        color = 0x0000FF  # R=0xFF
        fields = {
            'x': 0,
            'y': 0,
            'width': 2,
            'height': 2,
            'fg_color': color,
        }
        await gdi.process_primary_order(PrimaryOrderType.OPAQUE_RECT, fields)

        pixels = await surface.read_pixels(0, 0, 2, 2)
        expected_pixel = bytes([0xFF, 0x00, 0x00, 0xFF])
        for i in range(4):
            offset = i * 4
            assert pixels[offset:offset + 4] == expected_pixel

    @pytest.mark.asyncio
    async def test_opaque_rect_clipped_to_surface(
        self, gdi: GdiOrderProcessor, surface: GraphicsSurface
    ) -> None:
        """OpaqueRect that extends beyond surface bounds is clipped."""
        fields = {
            'x': 95,
            'y': 95,
            'width': 10,
            'height': 10,
            'fg_color': 0xFFFFFF,
        }
        await gdi.process_primary_order(PrimaryOrderType.OPAQUE_RECT, fields)

        # Should have written to the clipped area (95,95) to (99,99) = 5x5
        pixels = await surface.read_pixels(95, 95, 5, 5)
        expected_pixel = bytes([0xFF, 0xFF, 0xFF, 0xFF])
        for i in range(25):
            offset = i * 4
            assert pixels[offset:offset + 4] == expected_pixel

    @pytest.mark.asyncio
    async def test_opaque_rect_zero_size_no_op(
        self, gdi: GdiOrderProcessor, surface: GraphicsSurface
    ) -> None:
        """OpaqueRect with zero width or height should be a no-op."""
        fields = {
            'x': 10,
            'y': 10,
            'width': 0,
            'height': 5,
            'fg_color': 0xFF0000,
        }
        # Should not raise
        await gdi.process_primary_order(PrimaryOrderType.OPAQUE_RECT, fields)


# --- MemBlt Tests ---


class TestMemBlt:
    """Test MemBlt reads from bitmap cache."""

    @pytest.mark.asyncio
    async def test_memblt_reads_from_cache(
        self, gdi: GdiOrderProcessor, surface: GraphicsSurface
    ) -> None:
        """MemBlt should copy cached bitmap data to the surface."""
        # Store a 3x3 red bitmap in cache
        red_pixel = bytes([0xFF, 0x00, 0x00, 0xFF])
        bitmap_data = red_pixel * 9  # 3x3 pixels
        gdi.store_bitmap(0, 1, bitmap_data)

        fields = {
            'x': 20,
            'y': 20,
            'width': 3,
            'height': 3,
            'cache_id': 0,
            'cache_index': 1,
        }
        await gdi.process_primary_order(PrimaryOrderType.MEMBLT, fields)

        # Verify the pixels were written
        pixels = await surface.read_pixels(20, 20, 3, 3)
        assert pixels == bitmap_data

    @pytest.mark.asyncio
    async def test_memblt_cache_miss_no_op(
        self, gdi: GdiOrderProcessor, surface: GraphicsSurface
    ) -> None:
        """MemBlt with missing cache entry should be a no-op."""
        fields = {
            'x': 0,
            'y': 0,
            'width': 5,
            'height': 5,
            'cache_id': 99,
            'cache_index': 99,
        }
        # Should not raise
        await gdi.process_primary_order(PrimaryOrderType.MEMBLT, fields)

        # Surface should still be all zeros
        pixels = await surface.read_pixels(0, 0, 5, 5)
        assert pixels == b'\x00' * (5 * 5 * 4)

    @pytest.mark.asyncio
    async def test_memblt_multiple_cache_entries(
        self, gdi: GdiOrderProcessor, surface: GraphicsSurface
    ) -> None:
        """MemBlt should correctly use different cache entries."""
        # Store two different bitmaps
        blue_pixel = bytes([0x00, 0x00, 0xFF, 0xFF])
        green_pixel = bytes([0x00, 0xFF, 0x00, 0xFF])
        gdi.store_bitmap(0, 0, blue_pixel * 4)  # 2x2 blue
        gdi.store_bitmap(0, 1, green_pixel * 4)  # 2x2 green

        # Draw blue at (0,0)
        await gdi.process_primary_order(PrimaryOrderType.MEMBLT, {
            'x': 0, 'y': 0, 'width': 2, 'height': 2,
            'cache_id': 0, 'cache_index': 0,
        })
        # Draw green at (5,5)
        await gdi.process_primary_order(PrimaryOrderType.MEMBLT, {
            'x': 5, 'y': 5, 'width': 2, 'height': 2,
            'cache_id': 0, 'cache_index': 1,
        })

        blue_pixels = await surface.read_pixels(0, 0, 2, 2)
        green_pixels = await surface.read_pixels(5, 5, 2, 2)
        assert blue_pixels == blue_pixel * 4
        assert green_pixels == green_pixel * 4


# --- Delta Encoding State Persistence Tests ---


class TestDeltaEncoding:
    """Test that drawing order state persists across consecutive orders."""

    @pytest.mark.asyncio
    async def test_state_persists_across_orders(
        self, gdi: GdiOrderProcessor, surface: GraphicsSurface
    ) -> None:
        """Fields not present in a new order retain their previous values."""
        # First order sets all fields
        fields1 = {
            'x': 10,
            'y': 10,
            'width': 5,
            'height': 5,
            'fg_color': 0xFF0000,  # Blue
        }
        await gdi.process_primary_order(PrimaryOrderType.OPAQUE_RECT, fields1)

        # Second order only changes position, color persists
        fields2 = {
            'x': 30,
            'y': 30,
        }
        await gdi.process_primary_order(PrimaryOrderType.OPAQUE_RECT, fields2)

        # Verify the second rectangle used the persisted color and size
        pixels = await surface.read_pixels(30, 30, 5, 5)
        expected_pixel = bytes([0x00, 0x00, 0xFF, 0xFF])  # Blue from previous
        for i in range(25):
            offset = i * 4
            assert pixels[offset:offset + 4] == expected_pixel

    @pytest.mark.asyncio
    async def test_state_width_height_persist(
        self, gdi: GdiOrderProcessor, surface: GraphicsSurface
    ) -> None:
        """Width and height persist from previous order."""
        # Set initial dimensions
        await gdi.process_primary_order(PrimaryOrderType.OPAQUE_RECT, {
            'x': 0, 'y': 0, 'width': 3, 'height': 3, 'fg_color': 0x00FF00,
        })

        # Only change color, dimensions should persist
        await gdi.process_primary_order(PrimaryOrderType.OPAQUE_RECT, {
            'x': 50, 'y': 50, 'fg_color': 0xFF0000,
        })

        # Verify 3x3 rectangle at (50,50) with new color
        pixels = await surface.read_pixels(50, 50, 3, 3)
        expected_pixel = bytes([0x00, 0x00, 0xFF, 0xFF])
        for i in range(9):
            offset = i * 4
            assert pixels[offset:offset + 4] == expected_pixel

    @pytest.mark.asyncio
    async def test_state_independent_per_field(
        self, gdi: GdiOrderProcessor
    ) -> None:
        """Each field is independently persisted."""
        # Set x and y
        await gdi.process_primary_order(PrimaryOrderType.OPAQUE_RECT, {
            'x': 5, 'y': 10, 'width': 2, 'height': 2, 'fg_color': 0,
        })
        assert gdi.state.x == 5
        assert gdi.state.y == 10

        # Update only x
        await gdi.process_primary_order(PrimaryOrderType.OPAQUE_RECT, {
            'x': 20,
        })
        assert gdi.state.x == 20
        assert gdi.state.y == 10  # y persists

    @pytest.mark.asyncio
    async def test_order_state_initial_values(self, gdi: GdiOrderProcessor) -> None:
        """OrderState should have sensible initial values."""
        state = gdi.state
        assert state.x == 0
        assert state.y == 0
        assert state.width == 0
        assert state.height == 0
        assert state.fg_color == 0
        assert state.bg_color == 0
        assert state.rop == 0


# --- Secondary Order Tests ---


class TestSecondaryOrders:
    """Test secondary drawing orders (cache management)."""

    @pytest.mark.asyncio
    async def test_cache_bitmap_stores_data(
        self, gdi: GdiOrderProcessor
    ) -> None:
        """CacheBitmap should store bitmap data in the cache."""
        # Construct a minimal cache bitmap order
        # Format: cache_id(1) + pad(1) + width(1) + height(1) + bpp(1) + data_len(2) + cache_index(2) + data
        import struct
        cache_id = 0
        width = 2
        height = 2
        bpp = 32
        pixel_data = bytes([0xFF, 0x00, 0x00, 0xFF]) * 4  # 2x2 red
        data = struct.pack('<BBBBBHH', cache_id, 0, width, height, bpp,
                          len(pixel_data), 5) + pixel_data

        await gdi.process_secondary_order(
            SecondaryOrderType.CACHE_BITMAP_UNCOMPRESSED, data
        )

        # Verify the bitmap was cached
        cached = gdi.get_bitmap(cache_id, 5)
        assert cached == pixel_data

    @pytest.mark.asyncio
    async def test_cache_glyph_stores_entry(
        self, gdi: GdiOrderProcessor
    ) -> None:
        """CacheGlyph should store glyph entries in the cache."""
        # Construct a minimal cache glyph order
        import struct
        cache_id = 1
        glyph_index = 3
        gx, gy, gw, gh = 0, 0, 8, 8
        glyph_data = bytes(8)  # 8x8 glyph = 8 bytes (1 bit per pixel, 8 wide)
        data = struct.pack('<BB', cache_id, 1)  # 1 glyph
        data += struct.pack('<HHHHH', glyph_index, gx, gy, gw, gh)
        data += glyph_data

        await gdi.process_secondary_order(SecondaryOrderType.CACHE_GLYPH, data)

        # Verify the glyph was cached
        entry = gdi.get_glyph(cache_id, glyph_index)
        assert entry is not None
        assert entry.width == gw
        assert entry.height == gh
        assert entry.data == glyph_data

    @pytest.mark.asyncio
    async def test_cache_color_table(self, gdi: GdiOrderProcessor) -> None:
        """CacheColorTable should store color entries."""
        import struct
        cache_index = 0
        num_entries = 2
        data = struct.pack('<BH', cache_index, num_entries)
        # Two colors: red and green (BGRA format in table)
        data += bytes([0x00, 0x00, 0xFF, 0x00])  # Red (B=0, G=0, R=255)
        data += bytes([0x00, 0xFF, 0x00, 0x00])  # Green (B=0, G=255, R=0)

        await gdi.process_secondary_order(
            SecondaryOrderType.CACHE_COLOR_TABLE, data
        )

        # Verify color table was cached
        assert cache_index in gdi._color_table_cache
        assert len(gdi._color_table_cache[cache_index]) == 2


# --- Alternate Secondary Order Tests ---


class TestAlternateSecondaryOrders:
    """Test alternate secondary drawing order dispatch."""

    @pytest.mark.asyncio
    async def test_alternate_secondary_dispatch(
        self, gdi: GdiOrderProcessor
    ) -> None:
        """Alternate secondary orders should be dispatched without error."""
        # Frame marker order
        await gdi.process_alternate_secondary_order(
            AlternateSecondaryOrderType.FRAME_MARKER, b'\x00\x00\x00\x00'
        )

    @pytest.mark.asyncio
    async def test_unknown_alternate_secondary_ignored(
        self, gdi: GdiOrderProcessor
    ) -> None:
        """Unknown alternate secondary order types should be silently ignored."""
        await gdi.process_alternate_secondary_order(0xFF, b'\x00\x00')


# --- DstBlt Tests ---


class TestDstBlt:
    """Test DstBlt order."""

    @pytest.mark.asyncio
    async def test_dstblt_blackness(
        self, gdi: GdiOrderProcessor, surface: GraphicsSurface
    ) -> None:
        """DstBlt with BLACKNESS rop fills with black."""
        fields = {
            'x': 0,
            'y': 0,
            'width': 3,
            'height': 3,
            'rop': RasterOp.BLACKNESS,
        }
        await gdi.process_primary_order(PrimaryOrderType.DSTBLT, fields)

        pixels = await surface.read_pixels(0, 0, 3, 3)
        expected = bytes([0, 0, 0, 0xFF]) * 9
        assert pixels == expected


# --- ScrBlt Tests ---


class TestScrBlt:
    """Test ScrBlt order."""

    @pytest.mark.asyncio
    async def test_scrblt_copies_pixels(
        self, gdi: GdiOrderProcessor, surface: GraphicsSurface
    ) -> None:
        """ScrBlt should copy pixels from source to destination."""
        # First write some pixels to the source area
        red_pixel = bytes([0xFF, 0x00, 0x00, 0xFF])
        source_data = red_pixel * 4  # 2x2
        await surface.write_pixels(0, 0, 2, 2, source_data)

        # Copy from (0,0) to (50,50)
        fields = {
            'x': 50,
            'y': 50,
            'width': 2,
            'height': 2,
            'src_x': 0,
            'src_y': 0,
        }
        await gdi.process_primary_order(PrimaryOrderType.SCRBLT, fields)

        # Verify the copy
        dest_pixels = await surface.read_pixels(50, 50, 2, 2)
        assert dest_pixels == source_data


# --- PatBlt Tests ---


class TestPatBlt:
    """Test PatBlt order."""

    @pytest.mark.asyncio
    async def test_patblt_pattern_copy(
        self, gdi: GdiOrderProcessor, surface: GraphicsSurface
    ) -> None:
        """PatBlt with P (pattern copy) rop fills with the pattern color."""
        fields = {
            'x': 0,
            'y': 0,
            'width': 2,
            'height': 2,
            'rop': RasterOp.P,
            'fg_color': 0x00FFFF,  # R=0xFF, G=0xFF, B=0x00 (yellow)
        }
        await gdi.process_primary_order(PrimaryOrderType.PATBLT, fields)

        pixels = await surface.read_pixels(0, 0, 2, 2)
        expected_pixel = bytes([0xFF, 0xFF, 0x00, 0xFF])
        for i in range(4):
            offset = i * 4
            assert pixels[offset:offset + 4] == expected_pixel


# --- BitmapUpdatePdu Tests ---


class TestBitmapUpdatePdu:
    """Test BitmapUpdatePdu parse/serialize."""

    def test_parse_single_rectangle(self) -> None:
        """Parse a bitmap update with a single rectangle."""
        import struct
        # Build test data: 1 rectangle
        bitmap_data = b'\xAA' * 16
        data = struct.pack('<H', 1)  # num_rects
        data += struct.pack('<HHHHHHHH',
                           0, 0, 9, 9,  # dest coords
                           10, 10,  # width, height
                           32,  # bpp
                           0x0001)  # flags (compressed)
        data += struct.pack('<H', len(bitmap_data))
        data += bitmap_data

        pdu = BitmapUpdatePdu.parse(data)
        assert len(pdu.rectangles) == 1
        rect = pdu.rectangles[0]
        assert rect.dest_left == 0
        assert rect.dest_top == 0
        assert rect.width == 10
        assert rect.height == 10
        assert rect.bpp == 32
        assert rect.compressed is True
        assert rect.data == bitmap_data

    def test_round_trip(self) -> None:
        """BitmapUpdatePdu should round-trip through serialize/parse."""
        pdu = BitmapUpdatePdu(rectangles=[
            BitmapRectangle(
                dest_left=5, dest_top=10, dest_right=15, dest_bottom=20,
                width=10, height=10, bpp=16, compressed=False,
                data=b'\x00' * 20,
            ),
        ])
        serialized = pdu.serialize()
        parsed = BitmapUpdatePdu.parse(serialized)
        assert len(parsed.rectangles) == 1
        assert parsed.rectangles[0].dest_left == 5
        assert parsed.rectangles[0].width == 10
        assert parsed.rectangles[0].data == b'\x00' * 20


# --- OrderUpdatePdu Tests ---


class TestOrderUpdatePdu:
    """Test OrderUpdatePdu parse."""

    def test_parse_empty_orders(self) -> None:
        """Parse an order update with zero orders."""
        import struct
        data = struct.pack('<H', 0)  # num_orders = 0
        pdu = OrderUpdatePdu.parse(data)
        assert len(pdu.orders) == 0

    def test_serialize_basic(self) -> None:
        """OrderUpdatePdu serialization produces valid output."""
        pdu = OrderUpdatePdu(orders=[])
        serialized = pdu.serialize()
        assert len(serialized) == 2  # Just the count


# --- LineTo Tests ---


class TestLineTo:
    """Test LineTo order."""

    @pytest.mark.asyncio
    async def test_lineto_draws_pixels(
        self, gdi: GdiOrderProcessor, surface: GraphicsSurface
    ) -> None:
        """LineTo should draw pixels along the line."""
        fields = {
            'line_start_x': 0,
            'line_start_y': 0,
            'line_end_x': 4,
            'line_end_y': 0,
            'line_fg_color': 0x0000FF,  # Red
        }
        await gdi.process_primary_order(PrimaryOrderType.LINETO, fields)

        # Check that pixels along the horizontal line are set
        for x in range(5):
            pixel = await surface.read_pixels(x, 0, 1, 1)
            assert pixel == bytes([0xFF, 0x00, 0x00, 0xFF])


# --- MultiOpaqueRect Tests ---


class TestMultiOpaqueRect:
    """Test MultiOpaqueRect order."""

    @pytest.mark.asyncio
    async def test_multi_opaque_rect_fills_multiple(
        self, gdi: GdiOrderProcessor, surface: GraphicsSurface
    ) -> None:
        """MultiOpaqueRect should fill multiple rectangles."""
        fields = {
            'fg_color': 0x00FF00,  # Green
            'rects': [
                {'x': 0, 'y': 0, 'w': 2, 'h': 2},
                {'x': 10, 'y': 10, 'w': 2, 'h': 2},
            ],
        }
        await gdi.process_primary_order(
            PrimaryOrderType.MULTI_OPAQUE_RECT, fields
        )

        expected_pixel = bytes([0x00, 0xFF, 0x00, 0xFF])

        pixels1 = await surface.read_pixels(0, 0, 2, 2)
        for i in range(4):
            assert pixels1[i*4:(i+1)*4] == expected_pixel

        pixels2 = await surface.read_pixels(10, 10, 2, 2)
        for i in range(4):
            assert pixels2[i*4:(i+1)*4] == expected_pixel


# --- Bitmap Cache API Tests ---


class TestBitmapCache:
    """Test bitmap cache dict store."""

    def test_store_and_retrieve(self, gdi: GdiOrderProcessor) -> None:
        """Bitmap cache should store and retrieve data correctly."""
        data = b'\xFF' * 100
        gdi.store_bitmap(1, 2, data)
        assert gdi.get_bitmap(1, 2) == data

    def test_cache_miss_returns_none(self, gdi: GdiOrderProcessor) -> None:
        """Cache miss should return None."""
        assert gdi.get_bitmap(0, 0) is None

    def test_overwrite_cache_entry(self, gdi: GdiOrderProcessor) -> None:
        """Storing to the same key should overwrite."""
        gdi.store_bitmap(0, 0, b'\x00' * 10)
        gdi.store_bitmap(0, 0, b'\xFF' * 10)
        assert gdi.get_bitmap(0, 0) == b'\xFF' * 10


# --- Glyph Cache API Tests ---


class TestGlyphCache:
    """Test glyph cache dict store."""

    def test_store_and_retrieve(self, gdi: GdiOrderProcessor) -> None:
        """Glyph cache should store and retrieve entries correctly."""
        entry = GlyphEntry(x=0, y=0, width=8, height=8, data=b'\x00' * 8)
        gdi.store_glyph(0, 1, entry)
        assert gdi.get_glyph(0, 1) == entry

    def test_cache_miss_returns_none(self, gdi: GdiOrderProcessor) -> None:
        """Glyph cache miss should return None."""
        assert gdi.get_glyph(0, 0) is None
