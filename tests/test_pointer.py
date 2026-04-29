"""Tests for pointer/cursor handler and pointer PDU dataclasses.

Tests cover:
- PDU parse/serialize round-trip for all pointer update types
- Pointer cache store and retrieve
- Position update handling
- System pointer (default/hidden) handling
- XOR/AND mask decoding for color, new, and large pointers
- Cached pointer retrieval
"""

from __future__ import annotations

import pytest

from arrdipi.graphics.pointer import (
    PointerHandler,
    PointerImage,
    _decode_xor_and_masks,
)
from arrdipi.pdu.pointer_pdu import (
    SYSTEM_POINTER_DEFAULT,
    SYSTEM_POINTER_NULL,
    CachedPointerUpdate,
    ColorPointerUpdate,
    LargePointerUpdate,
    NewPointerUpdate,
    PointerPositionUpdate,
    SystemPointerUpdate,
)


# ============================================================================
# PDU Round-Trip Tests
# ============================================================================


class TestPointerPositionUpdatePdu:
    """Tests for PointerPositionUpdate parse/serialize."""

    def test_round_trip(self) -> None:
        pdu = PointerPositionUpdate(x=100, y=200)
        data = pdu.serialize()
        parsed = PointerPositionUpdate.parse(data)
        assert parsed == pdu

    def test_parse_known_data(self) -> None:
        # x=0x0064 (100), y=0x00C8 (200) in little-endian
        data = b"\x64\x00\xC8\x00"
        pdu = PointerPositionUpdate.parse(data)
        assert pdu.x == 100
        assert pdu.y == 200

    def test_serialize_known_data(self) -> None:
        pdu = PointerPositionUpdate(x=100, y=200)
        assert pdu.serialize() == b"\x64\x00\xC8\x00"


class TestSystemPointerUpdatePdu:
    """Tests for SystemPointerUpdate parse/serialize."""

    def test_round_trip_default(self) -> None:
        pdu = SystemPointerUpdate(system_pointer_type=SYSTEM_POINTER_DEFAULT)
        data = pdu.serialize()
        parsed = SystemPointerUpdate.parse(data)
        assert parsed == pdu

    def test_round_trip_null(self) -> None:
        pdu = SystemPointerUpdate(system_pointer_type=SYSTEM_POINTER_NULL)
        data = pdu.serialize()
        parsed = SystemPointerUpdate.parse(data)
        assert parsed == pdu

    def test_parse_default_pointer(self) -> None:
        # 0x7F00 in little-endian u32
        data = b"\x00\x7F\x00\x00"
        pdu = SystemPointerUpdate.parse(data)
        assert pdu.system_pointer_type == SYSTEM_POINTER_DEFAULT

    def test_parse_null_pointer(self) -> None:
        # 0x0000 in little-endian u32
        data = b"\x00\x00\x00\x00"
        pdu = SystemPointerUpdate.parse(data)
        assert pdu.system_pointer_type == SYSTEM_POINTER_NULL


class TestColorPointerUpdatePdu:
    """Tests for ColorPointerUpdate parse/serialize."""

    def test_round_trip(self) -> None:
        pdu = ColorPointerUpdate(
            cache_index=5,
            hotspot_x=3,
            hotspot_y=4,
            width=2,
            height=2,
            and_mask_data=b"\xC0\x00" * 2,  # 2 rows, 2-byte aligned
            xor_mask_data=b"\xFF\x00\x00\x00\xFF\x00" * 2,  # 2 pixels per row, 24bpp
        )
        data = pdu.serialize()
        parsed = ColorPointerUpdate.parse(data)
        assert parsed == pdu

    def test_empty_masks(self) -> None:
        pdu = ColorPointerUpdate(
            cache_index=0,
            hotspot_x=0,
            hotspot_y=0,
            width=0,
            height=0,
            and_mask_data=b"",
            xor_mask_data=b"",
        )
        data = pdu.serialize()
        parsed = ColorPointerUpdate.parse(data)
        assert parsed == pdu


class TestNewPointerUpdatePdu:
    """Tests for NewPointerUpdate parse/serialize."""

    def test_round_trip_24bpp(self) -> None:
        pdu = NewPointerUpdate(
            xor_bpp=24,
            cache_index=10,
            hotspot_x=1,
            hotspot_y=2,
            width=2,
            height=2,
            and_mask_data=b"\x00\x00" * 2,
            xor_mask_data=b"\xFF\x00\x00\x00\xFF\x00" * 2,
        )
        data = pdu.serialize()
        parsed = NewPointerUpdate.parse(data)
        assert parsed == pdu

    def test_round_trip_32bpp(self) -> None:
        pdu = NewPointerUpdate(
            xor_bpp=32,
            cache_index=7,
            hotspot_x=16,
            hotspot_y=16,
            width=2,
            height=1,
            and_mask_data=b"\x00\x00",
            xor_mask_data=b"\xFF\x00\x00\xFF\x00\xFF\x00\xFF",
        )
        data = pdu.serialize()
        parsed = NewPointerUpdate.parse(data)
        assert parsed == pdu


class TestCachedPointerUpdatePdu:
    """Tests for CachedPointerUpdate parse/serialize."""

    def test_round_trip(self) -> None:
        pdu = CachedPointerUpdate(cache_index=42)
        data = pdu.serialize()
        parsed = CachedPointerUpdate.parse(data)
        assert parsed == pdu

    def test_parse_known_data(self) -> None:
        # cache_index=0x002A (42) in little-endian
        data = b"\x2A\x00"
        pdu = CachedPointerUpdate.parse(data)
        assert pdu.cache_index == 42


class TestLargePointerUpdatePdu:
    """Tests for LargePointerUpdate parse/serialize."""

    def test_round_trip(self) -> None:
        pdu = LargePointerUpdate(
            xor_bpp=32,
            cache_index=0,
            hotspot_x=192,
            hotspot_y=192,
            width=384,
            height=384,
            and_mask_data=b"\x00" * 48 * 384,  # 384 pixels wide, 1-bit, padded
            xor_mask_data=b"\xFF" * 384 * 384 * 4,  # 32bpp
        )
        data = pdu.serialize()
        parsed = LargePointerUpdate.parse(data)
        assert parsed == pdu

    def test_round_trip_small(self) -> None:
        pdu = LargePointerUpdate(
            xor_bpp=24,
            cache_index=3,
            hotspot_x=0,
            hotspot_y=0,
            width=2,
            height=2,
            and_mask_data=b"\x00\x00" * 2,
            xor_mask_data=b"\xFF\x00\x00\x00\xFF\x00" * 2,
        )
        data = pdu.serialize()
        parsed = LargePointerUpdate.parse(data)
        assert parsed == pdu


# ============================================================================
# PointerHandler Tests
# ============================================================================


class TestPointerHandlerPosition:
    """Tests for position update handling."""

    def test_initial_position(self) -> None:
        handler = PointerHandler()
        assert handler.position == (0, 0)

    def test_position_update(self) -> None:
        handler = PointerHandler()
        handler.handle_position_update(150, 300)
        assert handler.position == (150, 300)

    def test_multiple_position_updates(self) -> None:
        handler = PointerHandler()
        handler.handle_position_update(10, 20)
        handler.handle_position_update(500, 600)
        assert handler.position == (500, 600)


class TestPointerHandlerSystemPointer:
    """Tests for system pointer handling."""

    def test_default_pointer_visible(self) -> None:
        handler = PointerHandler()
        handler.handle_system_pointer(SYSTEM_POINTER_DEFAULT)
        assert handler.visible is True
        assert handler.active_pointer is not None

    def test_null_pointer_hidden(self) -> None:
        handler = PointerHandler()
        handler.handle_system_pointer(SYSTEM_POINTER_NULL)
        assert handler.visible is False
        assert handler.active_pointer is None

    def test_toggle_visibility(self) -> None:
        handler = PointerHandler()
        handler.handle_system_pointer(SYSTEM_POINTER_NULL)
        assert handler.visible is False
        handler.handle_system_pointer(SYSTEM_POINTER_DEFAULT)
        assert handler.visible is True


class TestPointerHandlerCache:
    """Tests for pointer cache store and retrieve."""

    def test_color_pointer_cached(self) -> None:
        handler = PointerHandler()
        # Create a 2x2 24-bit color pointer
        # XOR mask: 2 pixels per row, 24bpp BGR, row stride = 6 bytes (padded to 6)
        xor_mask = b"\xFF\x00\x00" b"\x00\xFF\x00" b"\x00\x00\xFF" b"\xFF\xFF\x00"
        # AND mask: 2 pixels per row, 1-bit, padded to 2 bytes per row
        and_mask = b"\x00\x00" b"\x00\x00"

        update = ColorPointerUpdate(
            cache_index=5,
            hotspot_x=1,
            hotspot_y=1,
            width=2,
            height=2,
            and_mask_data=and_mask,
            xor_mask_data=xor_mask,
        )
        handler.handle_color_pointer(update)

        assert 5 in handler.cache
        pointer = handler.cache[5]
        assert pointer.width == 2
        assert pointer.height == 2
        assert pointer.hotspot_x == 1
        assert pointer.hotspot_y == 1
        assert len(pointer.rgba_data) == 2 * 2 * 4

    def test_new_pointer_cached(self) -> None:
        handler = PointerHandler()
        # 2x2 32-bit pointer: BGRA
        xor_mask = b"\xFF\x00\x00\xFF" b"\x00\xFF\x00\xFF" b"\x00\x00\xFF\xFF" b"\xFF\xFF\xFF\xFF"
        and_mask = b"\x00\x00" b"\x00\x00"

        update = NewPointerUpdate(
            xor_bpp=32,
            cache_index=10,
            hotspot_x=0,
            hotspot_y=0,
            width=2,
            height=2,
            and_mask_data=and_mask,
            xor_mask_data=xor_mask,
        )
        handler.handle_new_pointer(update)

        assert 10 in handler.cache
        pointer = handler.cache[10]
        assert pointer.width == 2
        assert pointer.height == 2
        assert len(pointer.rgba_data) == 2 * 2 * 4

    def test_cached_pointer_retrieval(self) -> None:
        handler = PointerHandler()
        # First cache a pointer
        xor_mask = b"\xFF\x00\x00\xFF" * 4
        and_mask = b"\x00\x00" * 2

        update = NewPointerUpdate(
            xor_bpp=32,
            cache_index=3,
            hotspot_x=5,
            hotspot_y=5,
            width=2,
            height=2,
            and_mask_data=and_mask,
            xor_mask_data=xor_mask,
        )
        handler.handle_new_pointer(update)

        # Switch to system pointer
        handler.handle_system_pointer(SYSTEM_POINTER_DEFAULT)

        # Now retrieve from cache
        handler.handle_cached_pointer(3)
        assert handler.active_pointer == handler.cache[3]
        assert handler.visible is True

    def test_cached_pointer_not_found(self) -> None:
        handler = PointerHandler()
        with pytest.raises(KeyError, match="Pointer cache index 99 not found"):
            handler.handle_cached_pointer(99)

    def test_large_pointer_cached(self) -> None:
        handler = PointerHandler()
        # Small "large" pointer for testing (4x4, 32bpp)
        width, height = 4, 4
        xor_mask = b"\xFF\x00\x00\xFF" * (width * height)
        and_mask = b"\x00\x00" * height  # 4 pixels = 1 byte, padded to 2

        update = LargePointerUpdate(
            xor_bpp=32,
            cache_index=0,
            hotspot_x=2,
            hotspot_y=2,
            width=width,
            height=height,
            and_mask_data=and_mask,
            xor_mask_data=xor_mask,
        )
        handler.handle_large_pointer(update)

        assert 0 in handler.cache
        pointer = handler.cache[0]
        assert pointer.width == 4
        assert pointer.height == 4
        assert len(pointer.rgba_data) == 4 * 4 * 4


# ============================================================================
# XOR/AND Mask Decoding Tests
# ============================================================================


class TestXorAndMaskDecoding:
    """Tests for XOR/AND mask decoding logic."""

    def test_fully_opaque_24bpp(self) -> None:
        """All AND bits 0 → all pixels opaque."""
        width, height = 2, 1
        # 24bpp BGR: blue pixel, red pixel
        # Row stride for 2 pixels at 24bpp = 6 bytes (already 2-byte aligned)
        xor_mask = b"\xFF\x00\x00" b"\x00\x00\xFF"
        # AND mask: all zeros (opaque), 2 pixels = 1 byte, padded to 2
        and_mask = b"\x00\x00"

        rgba = _decode_xor_and_masks(xor_mask, and_mask, width, height, 24)
        assert len(rgba) == 2 * 1 * 4

        # Bottom-up to top-down: row 0 in wire = bottom row
        # Since height=1, no flip needed
        # Pixel 0: BGR(FF,00,00) → RGB(00,00,FF) = blue, alpha=FF
        assert rgba[0:4] == bytes([0x00, 0x00, 0xFF, 0xFF])
        # Pixel 1: BGR(00,00,FF) → RGB(FF,00,00) = red, alpha=FF
        assert rgba[4:8] == bytes([0xFF, 0x00, 0x00, 0xFF])

    def test_fully_transparent(self) -> None:
        """All AND bits 1 + XOR all zeros → all pixels transparent."""
        width, height = 2, 1
        xor_mask = b"\x00\x00\x00" b"\x00\x00\x00"
        # AND mask: all ones (0xC0 = bits 7,6 set for 2 pixels)
        and_mask = b"\xC0\x00"

        rgba = _decode_xor_and_masks(xor_mask, and_mask, width, height, 24)
        # All pixels should be transparent
        for i in range(2):
            offset = i * 4
            assert rgba[offset + 3] == 0  # alpha = 0

    def test_mixed_opaque_transparent(self) -> None:
        """Mix of opaque and transparent pixels."""
        width, height = 2, 1
        # Pixel 0: white, Pixel 1: black
        xor_mask = b"\xFF\xFF\xFF" b"\x00\x00\x00"
        # AND mask: bit 0 = 0 (opaque), bit 1 = 1 (transparent since XOR=0)
        and_mask = b"\x40\x00"  # 0b01000000 → pixel 0 AND=0, pixel 1 AND=1

        rgba = _decode_xor_and_masks(xor_mask, and_mask, width, height, 24)
        # Pixel 0: opaque white
        assert rgba[0:4] == bytes([0xFF, 0xFF, 0xFF, 0xFF])
        # Pixel 1: transparent (AND=1, XOR=0)
        assert rgba[4:8] == bytes([0x00, 0x00, 0x00, 0x00])

    def test_32bpp_decoding(self) -> None:
        """32-bit BGRA XOR mask decoding."""
        width, height = 1, 1
        # BGRA: blue=0xFF, green=0x00, red=0x00, alpha=0xFF
        xor_mask = b"\xFF\x00\x00\xFF"
        and_mask = b"\x00\x00"  # opaque

        rgba = _decode_xor_and_masks(xor_mask, and_mask, width, height, 32)
        # RGB should be (0x00, 0x00, 0xFF) = blue
        assert rgba[0:4] == bytes([0x00, 0x00, 0xFF, 0xFF])

    def test_16bpp_decoding(self) -> None:
        """16-bit RGB555 XOR mask decoding."""
        width, height = 1, 1
        # RGB555: all ones = white (0x7FFF)
        xor_mask = b"\xFF\x7F"
        and_mask = b"\x00\x00"

        rgba = _decode_xor_and_masks(xor_mask, and_mask, width, height, 16)
        # Should be white (255, 255, 255)
        assert rgba[0] == 255
        assert rgba[1] == 255
        assert rgba[2] == 255
        assert rgba[3] == 255

    def test_1bpp_decoding(self) -> None:
        """1-bit monochrome XOR mask decoding."""
        width, height = 8, 1
        # XOR: alternating bits (0xAA = 10101010)
        xor_mask = b"\xAA\x00"  # padded to 2 bytes
        # AND: all zeros (opaque)
        and_mask = b"\x00\x00"

        rgba = _decode_xor_and_masks(xor_mask, and_mask, width, height, 1)
        assert len(rgba) == 8 * 4
        # Pixel 0: bit 7 of 0xAA = 1 → white
        assert rgba[0:4] == bytes([0xFF, 0xFF, 0xFF, 0xFF])
        # Pixel 1: bit 6 of 0xAA = 0 → black
        assert rgba[4:8] == bytes([0x00, 0x00, 0x00, 0xFF])

    def test_empty_cursor(self) -> None:
        """Zero-size cursor returns empty bytes."""
        rgba = _decode_xor_and_masks(b"", b"", 0, 0, 24)
        assert rgba == b""

    def test_bottom_up_flip(self) -> None:
        """Verify bottom-up to top-down row flip."""
        width, height = 1, 2
        # Row 0 (bottom in wire): red pixel BGR(00,00,FF)
        # Row 1 (top in wire): blue pixel BGR(FF,00,00)
        # 24bpp row stride for 1 pixel = 3 bytes, padded to 4? No, padded to 2-byte = 4
        # Actually ((1*3 + 1)//2)*2 = 4
        xor_mask = b"\x00\x00\xFF\x00" b"\xFF\x00\x00\x00"
        and_mask = b"\x00\x00" b"\x00\x00"

        rgba = _decode_xor_and_masks(xor_mask, and_mask, width, height, 24)
        # After flip: top row should be wire row 1 (blue), bottom row should be wire row 0 (red)
        # Output row 0 = wire row 1 (top in display) = blue BGR(FF,00,00) → RGB(00,00,FF)
        assert rgba[0:4] == bytes([0x00, 0x00, 0xFF, 0xFF])
        # Output row 1 = wire row 0 (bottom in display) = red BGR(00,00,FF) → RGB(FF,00,00)
        assert rgba[4:8] == bytes([0xFF, 0x00, 0x00, 0xFF])
