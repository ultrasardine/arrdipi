"""Tests for arrdipi.graphics.surface — RGBA framebuffer."""

import asyncio

import pytest

from arrdipi.graphics.surface import GraphicsSurface, Rect


# --- Rect dataclass tests ---


class TestRect:
    def test_rect_creation(self) -> None:
        r = Rect(10, 20, 100, 200)
        assert r.x == 10
        assert r.y == 20
        assert r.w == 100
        assert r.h == 200

    def test_rect_is_frozen(self) -> None:
        r = Rect(0, 0, 1, 1)
        with pytest.raises(AttributeError):
            r.x = 5  # type: ignore[misc]

    def test_rect_equality(self) -> None:
        assert Rect(1, 2, 3, 4) == Rect(1, 2, 3, 4)
        assert Rect(1, 2, 3, 4) != Rect(0, 2, 3, 4)


# --- GraphicsSurface construction tests ---


class TestSurfaceConstruction:
    def test_valid_dimensions(self) -> None:
        surface = GraphicsSurface(1920, 1080)
        assert surface.width == 1920
        assert surface.height == 1080

    def test_buffer_size(self) -> None:
        surface = GraphicsSurface(100, 50)
        buf = surface.get_buffer()
        assert len(buf) == 100 * 50 * 4

    def test_buffer_initialized_to_zero(self) -> None:
        surface = GraphicsSurface(10, 10)
        buf = surface.get_buffer()
        assert all(b == 0 for b in buf)

    def test_invalid_zero_width(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            GraphicsSurface(0, 100)

    def test_invalid_zero_height(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            GraphicsSurface(100, 0)

    def test_invalid_negative_dimensions(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            GraphicsSurface(-1, 100)


# --- Write/Read round-trip tests ---


class TestWriteReadRoundTrip:
    @pytest.fixture
    def surface(self) -> GraphicsSurface:
        return GraphicsSurface(100, 100)

    @pytest.mark.asyncio
    async def test_write_read_single_pixel(self, surface: GraphicsSurface) -> None:
        pixel = bytes([255, 0, 0, 255])  # Red, fully opaque
        await surface.write_pixels(0, 0, 1, 1, pixel)
        result = await surface.read_pixels(0, 0, 1, 1)
        assert result == pixel

    @pytest.mark.asyncio
    async def test_write_read_block(self, surface: GraphicsSurface) -> None:
        w, h = 10, 5
        pixels = bytes(range(256)) * ((w * h * 4) // 256) + bytes(range((w * h * 4) % 256))
        # Generate exactly w*h*4 bytes
        pixels = bytes([i % 256 for i in range(w * h * 4)])
        await surface.write_pixels(5, 5, w, h, pixels)
        result = await surface.read_pixels(5, 5, w, h)
        assert result == pixels

    @pytest.mark.asyncio
    async def test_write_at_edge(self, surface: GraphicsSurface) -> None:
        """Write a block at the bottom-right corner."""
        w, h = 10, 10
        pixels = bytes([128] * (w * h * 4))
        await surface.write_pixels(90, 90, w, h, pixels)
        result = await surface.read_pixels(90, 90, w, h)
        assert result == pixels

    @pytest.mark.asyncio
    async def test_write_full_surface(self, surface: GraphicsSurface) -> None:
        """Write the entire surface."""
        pixels = bytes([42] * (100 * 100 * 4))
        await surface.write_pixels(0, 0, 100, 100, pixels)
        result = await surface.read_pixels(0, 0, 100, 100)
        assert result == pixels

    @pytest.mark.asyncio
    async def test_multiple_writes_non_overlapping(self, surface: GraphicsSurface) -> None:
        red = bytes([255, 0, 0, 255]) * 4  # 2x2 red
        blue = bytes([0, 0, 255, 255]) * 4  # 2x2 blue
        await surface.write_pixels(0, 0, 2, 2, red)
        await surface.write_pixels(50, 50, 2, 2, blue)
        assert await surface.read_pixels(0, 0, 2, 2) == red
        assert await surface.read_pixels(50, 50, 2, 2) == blue

    @pytest.mark.asyncio
    async def test_overwrite_region(self, surface: GraphicsSurface) -> None:
        """Overwriting a region replaces the old data."""
        first = bytes([100] * 16)  # 2x2
        second = bytes([200] * 16)  # 2x2
        await surface.write_pixels(10, 10, 2, 2, first)
        await surface.write_pixels(10, 10, 2, 2, second)
        result = await surface.read_pixels(10, 10, 2, 2)
        assert result == second


# --- Bounds checking tests ---


class TestBoundsChecking:
    @pytest.fixture
    def surface(self) -> GraphicsSurface:
        return GraphicsSurface(100, 100)

    @pytest.mark.asyncio
    async def test_write_exceeds_width(self, surface: GraphicsSurface) -> None:
        pixels = bytes([0] * (20 * 10 * 4))
        with pytest.raises(ValueError, match="exceeds surface bounds"):
            await surface.write_pixels(90, 0, 20, 10, pixels)

    @pytest.mark.asyncio
    async def test_write_exceeds_height(self, surface: GraphicsSurface) -> None:
        pixels = bytes([0] * (10 * 20 * 4))
        with pytest.raises(ValueError, match="exceeds surface bounds"):
            await surface.write_pixels(0, 90, 10, 20, pixels)

    @pytest.mark.asyncio
    async def test_write_negative_x(self, surface: GraphicsSurface) -> None:
        with pytest.raises(ValueError, match="Invalid write region"):
            await surface.write_pixels(-1, 0, 1, 1, bytes([0, 0, 0, 0]))

    @pytest.mark.asyncio
    async def test_write_negative_y(self, surface: GraphicsSurface) -> None:
        with pytest.raises(ValueError, match="Invalid write region"):
            await surface.write_pixels(0, -1, 1, 1, bytes([0, 0, 0, 0]))

    @pytest.mark.asyncio
    async def test_write_zero_width(self, surface: GraphicsSurface) -> None:
        with pytest.raises(ValueError, match="Invalid write region"):
            await surface.write_pixels(0, 0, 0, 1, b"")

    @pytest.mark.asyncio
    async def test_write_zero_height(self, surface: GraphicsSurface) -> None:
        with pytest.raises(ValueError, match="Invalid write region"):
            await surface.write_pixels(0, 0, 1, 0, b"")

    @pytest.mark.asyncio
    async def test_write_wrong_pixel_size(self, surface: GraphicsSurface) -> None:
        with pytest.raises(ValueError, match="Pixel data size mismatch"):
            await surface.write_pixels(0, 0, 2, 2, bytes([0] * 10))

    @pytest.mark.asyncio
    async def test_read_exceeds_width(self, surface: GraphicsSurface) -> None:
        with pytest.raises(ValueError, match="exceeds surface bounds"):
            await surface.read_pixels(90, 0, 20, 10)

    @pytest.mark.asyncio
    async def test_read_exceeds_height(self, surface: GraphicsSurface) -> None:
        with pytest.raises(ValueError, match="exceeds surface bounds"):
            await surface.read_pixels(0, 90, 10, 20)

    @pytest.mark.asyncio
    async def test_read_negative_x(self, surface: GraphicsSurface) -> None:
        with pytest.raises(ValueError, match="Invalid read region"):
            await surface.read_pixels(-1, 0, 1, 1)

    @pytest.mark.asyncio
    async def test_read_zero_dimensions(self, surface: GraphicsSurface) -> None:
        with pytest.raises(ValueError, match="Invalid read region"):
            await surface.read_pixels(0, 0, 0, 1)


# --- Dirty rect tracking tests ---


class TestDirtyRectTracking:
    @pytest.fixture
    def surface(self) -> GraphicsSurface:
        return GraphicsSurface(100, 100)

    def test_no_dirty_rects_initially(self, surface: GraphicsSurface) -> None:
        assert surface.get_dirty_rects() == []

    @pytest.mark.asyncio
    async def test_write_adds_dirty_rect(self, surface: GraphicsSurface) -> None:
        await surface.write_pixels(10, 20, 30, 40, bytes([0] * (30 * 40 * 4)))
        rects = surface.get_dirty_rects()
        assert len(rects) == 1
        assert rects[0] == Rect(10, 20, 30, 40)

    @pytest.mark.asyncio
    async def test_multiple_writes_accumulate_rects(self, surface: GraphicsSurface) -> None:
        await surface.write_pixels(0, 0, 5, 5, bytes([0] * (5 * 5 * 4)))
        await surface.write_pixels(50, 50, 10, 10, bytes([0] * (10 * 10 * 4)))
        rects = surface.get_dirty_rects()
        assert len(rects) == 2
        assert rects[0] == Rect(0, 0, 5, 5)
        assert rects[1] == Rect(50, 50, 10, 10)

    @pytest.mark.asyncio
    async def test_get_dirty_rects_clears_list(self, surface: GraphicsSurface) -> None:
        await surface.write_pixels(0, 0, 1, 1, bytes([0, 0, 0, 0]))
        rects = surface.get_dirty_rects()
        assert len(rects) == 1
        # Second call should return empty
        assert surface.get_dirty_rects() == []

    @pytest.mark.asyncio
    async def test_dirty_rects_after_clear_and_new_write(self, surface: GraphicsSurface) -> None:
        await surface.write_pixels(0, 0, 1, 1, bytes([0, 0, 0, 0]))
        surface.get_dirty_rects()  # Clear
        await surface.write_pixels(5, 5, 2, 2, bytes([0] * (2 * 2 * 4)))
        rects = surface.get_dirty_rects()
        assert len(rects) == 1
        assert rects[0] == Rect(5, 5, 2, 2)


# --- get_buffer tests ---


class TestGetBuffer:
    def test_buffer_is_readonly(self) -> None:
        surface = GraphicsSurface(10, 10)
        buf = surface.get_buffer()
        assert buf.readonly

    def test_buffer_reflects_writes(self) -> None:
        surface = GraphicsSurface(10, 10)
        pixel = bytes([255, 128, 64, 255])
        asyncio.run(surface.write_pixels(0, 0, 1, 1, pixel))
        buf = surface.get_buffer()
        assert bytes(buf[0:4]) == pixel

    def test_buffer_correct_size(self) -> None:
        surface = GraphicsSurface(320, 240)
        buf = surface.get_buffer()
        assert len(buf) == 320 * 240 * 4


# --- Concurrency safety test ---


class TestConcurrency:
    @pytest.mark.asyncio
    async def test_concurrent_writes_do_not_corrupt(self) -> None:
        """Multiple concurrent writes should not corrupt the buffer."""
        surface = GraphicsSurface(100, 100)

        async def write_region(x: int, y: int, value: int) -> None:
            pixels = bytes([value] * (10 * 10 * 4))
            await surface.write_pixels(x, y, 10, 10, pixels)

        # Write to non-overlapping regions concurrently
        await asyncio.gather(
            write_region(0, 0, 100),
            write_region(10, 0, 150),
            write_region(20, 0, 200),
            write_region(30, 0, 250),
        )

        # Verify each region has the correct value
        r1 = await surface.read_pixels(0, 0, 10, 10)
        r2 = await surface.read_pixels(10, 0, 10, 10)
        r3 = await surface.read_pixels(20, 0, 10, 10)
        r4 = await surface.read_pixels(30, 0, 10, 10)

        assert all(b == 100 for b in r1)
        assert all(b == 150 for b in r2)
        assert all(b == 200 for b in r3)
        assert all(b == 250 for b in r4)
