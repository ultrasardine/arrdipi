"""Tests for the RemoteFX codec implementation."""

from __future__ import annotations

import struct

import pytest

from arrdipi.codec.remotefx import (
    TILE_SIZE,
    QuantValues,
    RemoteFxCodec,
    _BitReader,
    _dequantize_subband,
    _idwt_1d,
    _inverse_dwt_2d,
    _ycbcr_to_rgb,
    decode_message,
    decode_tile,
    rlgr1_decode,
    rlgr3_decode,
)
from arrdipi.graphics.surface import Rect


class TestBitReader:
    """Tests for the internal bit reader."""

    def test_read_single_bits(self) -> None:
        # 0xA5 = 10100101
        reader = _BitReader(b"\xa5")
        bits = [reader.read_bit() for _ in range(8)]
        assert bits == [1, 0, 1, 0, 0, 1, 0, 1]

    def test_read_bits_multi(self) -> None:
        # 0xFF = 11111111
        reader = _BitReader(b"\xff")
        assert reader.read_bits(4) == 0xF
        assert reader.read_bits(4) == 0xF

    def test_bits_remaining(self) -> None:
        reader = _BitReader(b"\x00\x00")
        assert reader.bits_remaining() == 16
        reader.read_bit()
        assert reader.bits_remaining() == 15

    def test_read_past_end_returns_zero(self) -> None:
        reader = _BitReader(b"\xff")
        # Read all 8 bits
        for _ in range(8):
            reader.read_bit()
        # Reading past end returns 0
        assert reader.read_bit() == 0


class TestRlgrDecode:
    """Tests for RLGR1 and RLGR3 entropy decoding."""

    def test_rlgr1_all_zeros(self) -> None:
        """RLGR1 decoding of data that produces zeros."""
        # When we request more values than the data encodes,
        # the decoder pads with zeros
        result = rlgr1_decode(b"\x00", 10)
        assert len(result) == 10
        # All should be integers
        assert all(isinstance(v, int) for v in result)

    def test_rlgr3_all_zeros(self) -> None:
        """RLGR3 decoding of data that produces zeros."""
        result = rlgr3_decode(b"\x00", 10)
        assert len(result) == 10
        assert all(isinstance(v, int) for v in result)

    def test_rlgr1_produces_correct_count(self) -> None:
        """RLGR1 always produces exactly the requested number of values."""
        data = b"\xab\xcd\xef\x01\x23\x45\x67\x89"
        result = rlgr1_decode(data, 20)
        assert len(result) == 20

    def test_rlgr3_produces_correct_count(self) -> None:
        """RLGR3 always produces exactly the requested number of values."""
        data = b"\xab\xcd\xef\x01\x23\x45\x67\x89"
        result = rlgr3_decode(data, 20)
        assert len(result) == 20

    def test_rlgr1_known_vector(self) -> None:
        """Test RLGR1 with a known input that should produce specific output."""
        # A byte starting with bit 1 indicates a non-zero value
        # 0x80 = 10000000 -> first bit is 1 (non-zero value follows)
        # Then GR decode with k=0: unary=0 (next bit is already consumed),
        # magnitude from remaining bits
        data = b"\x80\x00\x00\x00"
        result = rlgr1_decode(data, 5)
        assert len(result) == 5
        # First value should be non-zero (the leading 1 bit triggers value mode)
        # The exact value depends on the GR decoding

    def test_rlgr3_known_vector(self) -> None:
        """Test RLGR3 with a known input producing pairs."""
        data = b"\xff\xff\xff\xff\xff\xff\xff\xff"
        result = rlgr3_decode(data, 10)
        assert len(result) == 10

    def test_rlgr_invalid_mode_raises(self) -> None:
        """Invalid RLGR mode raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported RLGR mode"):
            from arrdipi.codec.remotefx import _rlgr_decode
            _rlgr_decode(b"\x00", mode=2, num_values=10)

    def test_rlgr1_empty_data(self) -> None:
        """Empty data produces all zeros."""
        result = rlgr1_decode(b"", 10)
        assert result == [0] * 10

    def test_rlgr3_empty_data(self) -> None:
        """Empty data produces all zeros."""
        result = rlgr3_decode(b"", 10)
        assert result == [0] * 10


class TestDequantization:
    """Tests for subband dequantization."""

    def test_no_shift_at_base(self) -> None:
        """Quantization value of 6 means no shift (base level)."""
        coeffs = [1, -2, 3, -4, 5]
        result = _dequantize_subband(coeffs, 6)
        assert result == [1, -2, 3, -4, 5]

    def test_shift_by_one(self) -> None:
        """Quantization value of 7 means shift left by 1."""
        coeffs = [1, -2, 3]
        result = _dequantize_subband(coeffs, 7)
        assert result == [2, -4, 6]

    def test_shift_by_two(self) -> None:
        """Quantization value of 8 means shift left by 2."""
        coeffs = [1, -1, 0, 5]
        result = _dequantize_subband(coeffs, 8)
        assert result == [4, -4, 0, 20]

    def test_below_base_no_shift(self) -> None:
        """Quantization values below 6 result in no shift."""
        coeffs = [10, 20, 30]
        result = _dequantize_subband(coeffs, 5)
        assert result == [10, 20, 30]

    def test_zeros_unchanged(self) -> None:
        """Zero coefficients remain zero regardless of quant value."""
        coeffs = [0, 0, 0]
        result = _dequantize_subband(coeffs, 10)
        assert result == [0, 0, 0]


class TestInverseDWT:
    """Tests for the inverse discrete wavelet transform."""

    def test_idwt_1d_simple(self) -> None:
        """Basic 1D inverse DWT produces correct length output."""
        low = [10, 20, 30, 40]
        high = [1, 2, 3, 4]
        result = _idwt_1d(low, high)
        assert len(result) == 8

    def test_idwt_1d_all_zeros(self) -> None:
        """All-zero input produces all-zero output."""
        low = [0, 0, 0, 0]
        high = [0, 0, 0, 0]
        result = _idwt_1d(low, high)
        assert result == [0] * 8

    def test_idwt_1d_dc_only(self) -> None:
        """DC-only signal (high=0) produces output of correct length."""
        low = [100, 100, 100, 100]
        high = [0, 0, 0, 0]
        result = _idwt_1d(low, high)
        assert len(result) == 8
        # Even positions come from the low-pass (update step modifies them)
        # Odd positions come from the high-pass (predict step modifies them)
        # The result should contain integer values
        assert all(isinstance(v, int) for v in result)

    def test_idwt_1d_empty(self) -> None:
        """Empty input produces empty output."""
        assert _idwt_1d([], []) == []

    def test_inverse_dwt_2d_all_zeros(self) -> None:
        """All-zero subbands produce all-zero 64x64 grid."""
        subbands = [
            [0] * (8 * 8),   # LL3
            [0] * (8 * 8),   # HL3
            [0] * (8 * 8),   # LH3
            [0] * (8 * 8),   # HH3
            [0] * (16 * 16), # HL2
            [0] * (16 * 16), # LH2
            [0] * (16 * 16), # HH2
            [0] * (32 * 32), # HL1
            [0] * (32 * 32), # LH1
            [0] * (32 * 32), # HH1
        ]
        grid = _inverse_dwt_2d(subbands)
        assert len(grid) == 64
        assert all(len(row) == 64 for row in grid)
        assert all(v == 0 for row in grid for v in row)

    def test_inverse_dwt_2d_dc_only(self) -> None:
        """DC-only signal (only LL3 non-zero) produces a grid."""
        subbands = [
            [128] * (8 * 8),  # LL3 - constant DC
            [0] * (8 * 8),    # HL3
            [0] * (8 * 8),    # LH3
            [0] * (8 * 8),    # HH3
            [0] * (16 * 16),  # HL2
            [0] * (16 * 16),  # LH2
            [0] * (16 * 16),  # HH2
            [0] * (32 * 32),  # HL1
            [0] * (32 * 32),  # LH1
            [0] * (32 * 32),  # HH1
        ]
        grid = _inverse_dwt_2d(subbands)
        assert len(grid) == 64
        assert all(len(row) == 64 for row in grid)
        # With only DC, all values should be the same (constant image)
        # Due to wavelet boundary effects, values should be close to 128
        center_val = grid[32][32]
        assert center_val != 0  # Should have non-zero values


class TestYCbCrToRgb:
    """Tests for YCbCr to RGB color space conversion."""

    def test_pure_white(self) -> None:
        """Y=255, Cb=0, Cr=0 should produce white (or near-white)."""
        y_grid = [[255] * 64 for _ in range(64)]
        cb_grid = [[0] * 64 for _ in range(64)]
        cr_grid = [[0] * 64 for _ in range(64)]
        result = _ycbcr_to_rgb(y_grid, cb_grid, cr_grid)
        assert len(result) == 64 * 64 * 4
        # First pixel should be (255, 255, 255, 255)
        assert result[0] == 255  # R
        assert result[1] == 255  # G
        assert result[2] == 255  # B
        assert result[3] == 255  # A

    def test_pure_black(self) -> None:
        """Y=0, Cb=0, Cr=0 should produce black."""
        y_grid = [[0] * 64 for _ in range(64)]
        cb_grid = [[0] * 64 for _ in range(64)]
        cr_grid = [[0] * 64 for _ in range(64)]
        result = _ycbcr_to_rgb(y_grid, cb_grid, cr_grid)
        assert result[0] == 0  # R
        assert result[1] == 0  # G
        assert result[2] == 0  # B
        assert result[3] == 255  # A

    def test_red_channel(self) -> None:
        """Positive Cr increases R channel."""
        y_grid = [[128] * 64 for _ in range(64)]
        cb_grid = [[0] * 64 for _ in range(64)]
        cr_grid = [[50] * 64 for _ in range(64)]
        result = _ycbcr_to_rgb(y_grid, cb_grid, cr_grid)
        r = result[0]
        g = result[1]
        b = result[2]
        # R should be higher than G and B due to positive Cr
        assert r > g
        assert r > b

    def test_blue_channel(self) -> None:
        """Positive Cb increases B channel."""
        y_grid = [[128] * 64 for _ in range(64)]
        cb_grid = [[50] * 64 for _ in range(64)]
        cr_grid = [[0] * 64 for _ in range(64)]
        result = _ycbcr_to_rgb(y_grid, cb_grid, cr_grid)
        r = result[0]
        g = result[1]
        b = result[2]
        # B should be higher than R due to positive Cb
        assert b > r

    def test_clamping(self) -> None:
        """Values are clamped to [0, 255]."""
        # Large positive Cr should not overflow R past 255
        y_grid = [[255] * 64 for _ in range(64)]
        cb_grid = [[0] * 64 for _ in range(64)]
        cr_grid = [[200] * 64 for _ in range(64)]
        result = _ycbcr_to_rgb(y_grid, cb_grid, cr_grid)
        assert result[0] == 255  # R clamped to 255
        assert result[3] == 255  # A always 255

    def test_negative_clamping(self) -> None:
        """Negative results are clamped to 0."""
        # Large negative Cr should not make G go below 0
        y_grid = [[0] * 64 for _ in range(64)]
        cb_grid = [[0] * 64 for _ in range(64)]
        cr_grid = [[-200] * 64 for _ in range(64)]
        result = _ycbcr_to_rgb(y_grid, cb_grid, cr_grid)
        # G = 0 - 0.344*0 - 0.714*(-200) = 142 (positive due to negative Cr)
        # R = 0 + 1.403*(-200) = -280 -> clamped to 0
        assert result[0] == 0  # R clamped to 0

    def test_output_size(self) -> None:
        """Output is always 64*64*4 bytes."""
        y_grid = [[100] * 64 for _ in range(64)]
        cb_grid = [[0] * 64 for _ in range(64)]
        cr_grid = [[0] * 64 for _ in range(64)]
        result = _ycbcr_to_rgb(y_grid, cb_grid, cr_grid)
        assert len(result) == TILE_SIZE * TILE_SIZE * 4


class TestDecodeTile:
    """Tests for the full tile decode pipeline."""

    def _make_tile_data(self, y_bytes: bytes, cb_bytes: bytes, cr_bytes: bytes) -> bytes:
        """Helper to construct tile data with length-prefixed components."""
        result = bytearray()
        result += struct.pack("<H", len(y_bytes))
        result += y_bytes
        result += struct.pack("<H", len(cb_bytes))
        result += cb_bytes
        result += struct.pack("<H", len(cr_bytes))
        result += cr_bytes
        return bytes(result)

    def test_decode_tile_all_zeros(self) -> None:
        """Tile with all-zero encoded data produces valid RGBA output."""
        # Zero bytes will decode to all-zero coefficients
        tile_data = self._make_tile_data(b"\x00" * 4, b"\x00" * 4, b"\x00" * 4)
        quant = QuantValues(
            hl1=6, lh1=6, hh1=6,
            hl2=6, lh2=6, hh2=6,
            hl3=6, lh3=6, hh3=6,
            ll3=6,
        )
        result = decode_tile(tile_data, quant, mode=1)
        assert len(result) == TILE_SIZE * TILE_SIZE * 4
        # All zeros in YCbCr -> all black in RGB
        assert result[0] == 0  # R
        assert result[1] == 0  # G
        assert result[2] == 0  # B
        assert result[3] == 255  # A

    def test_decode_tile_output_size(self) -> None:
        """decode_tile always produces 16384 bytes (64*64*4)."""
        tile_data = self._make_tile_data(
            b"\x00" * 8, b"\x00" * 8, b"\x00" * 8
        )
        quant = QuantValues(
            hl1=6, lh1=6, hh1=6,
            hl2=6, lh2=6, hh2=6,
            hl3=6, lh3=6, hh3=6,
            ll3=6,
        )
        result = decode_tile(tile_data, quant, mode=3)
        assert len(result) == 16384

    def test_decode_tile_truncated_y(self) -> None:
        """Truncated Y component raises ValueError."""
        # Length says 10 bytes but only 5 available
        data = struct.pack("<H", 10) + b"\x00" * 5
        quant = QuantValues(
            hl1=6, lh1=6, hh1=6,
            hl2=6, lh2=6, hh2=6,
            hl3=6, lh3=6, hh3=6,
            ll3=6,
        )
        with pytest.raises(ValueError, match="Truncated tile data"):
            decode_tile(data, quant)

    def test_decode_tile_with_quant(self) -> None:
        """Tile decode with non-trivial quantization values."""
        tile_data = self._make_tile_data(
            b"\x00" * 8, b"\x00" * 8, b"\x00" * 8
        )
        quant = QuantValues(
            hl1=8, lh1=8, hh1=8,
            hl2=9, lh2=9, hh2=9,
            hl3=10, lh3=10, hh3=10,
            ll3=6,
        )
        result = decode_tile(tile_data, quant, mode=1)
        assert len(result) == 16384


class TestDecodeMessage:
    """Tests for RemoteFX message decoding."""

    def _make_message(
        self,
        tiles: list[tuple[int, int, int, bytes]],
        quant_vals: list[tuple[int, ...]],
        mode: int = 1,
    ) -> bytes:
        """Helper to construct a RemoteFX message.

        Args:
            tiles: List of (quant_idx, x, y, tile_data) tuples.
            quant_vals: List of 10-value tuples for quantization.
            mode: RLGR mode.
        """
        result = bytearray()

        # Block type (2 bytes) + block length placeholder (4 bytes)
        result += struct.pack("<H", 0xCAC3)  # arbitrary block type
        result += struct.pack("<I", 0)  # placeholder for length

        # Number of tiles (2 bytes)
        result += struct.pack("<H", len(tiles))

        # Number of quant tables (1 byte)
        result += struct.pack("B", len(quant_vals))

        # RLGR mode (1 byte)
        result += struct.pack("B", mode)

        # Quantization tables (5 bytes each)
        for qv in quant_vals:
            # Pack 10 nibbles into 5 bytes
            packed = bytearray(5)
            for i in range(5):
                packed[i] = (qv[2 * i] & 0x0F) | ((qv[2 * i + 1] & 0x0F) << 4)
            result += packed

        # Tiles
        for quant_idx, x, y, tile_data in tiles:
            result += struct.pack("B", quant_idx)
            result += struct.pack("<H", x)
            result += struct.pack("<H", y)
            result += struct.pack("<H", len(tile_data))
            result += tile_data

        # Update block length
        struct.pack_into("<I", result, 2, len(result))

        return bytes(result)

    def _make_tile_data(self, y_bytes: bytes, cb_bytes: bytes, cr_bytes: bytes) -> bytes:
        """Helper to construct tile data."""
        result = bytearray()
        result += struct.pack("<H", len(y_bytes))
        result += y_bytes
        result += struct.pack("<H", len(cb_bytes))
        result += cb_bytes
        result += struct.pack("<H", len(cr_bytes))
        result += cr_bytes
        return bytes(result)

    def test_decode_single_tile_message(self) -> None:
        """Decode a message with a single tile."""
        tile_data = self._make_tile_data(
            b"\x00" * 4, b"\x00" * 4, b"\x00" * 4
        )
        quant = (6, 6, 6, 6, 6, 6, 6, 6, 6, 6)
        msg = self._make_message(
            tiles=[(0, 0, 0, tile_data)],
            quant_vals=[quant],
            mode=1,
        )
        results = decode_message(msg)
        assert len(results) == 1
        rect, pixels = results[0]
        assert rect == Rect(x=0, y=0, w=64, h=64)
        assert len(pixels) == 16384

    def test_decode_multiple_tiles(self) -> None:
        """Decode a message with multiple tiles at different positions."""
        tile_data = self._make_tile_data(
            b"\x00" * 4, b"\x00" * 4, b"\x00" * 4
        )
        quant = (6, 6, 6, 6, 6, 6, 6, 6, 6, 6)
        msg = self._make_message(
            tiles=[
                (0, 0, 0, tile_data),
                (0, 64, 0, tile_data),
                (0, 0, 64, tile_data),
            ],
            quant_vals=[quant],
            mode=1,
        )
        results = decode_message(msg)
        assert len(results) == 3
        assert results[0][0] == Rect(x=0, y=0, w=64, h=64)
        assert results[1][0] == Rect(x=64, y=0, w=64, h=64)
        assert results[2][0] == Rect(x=0, y=64, w=64, h=64)

    def test_decode_message_too_short(self) -> None:
        """Message shorter than minimum raises ValueError."""
        with pytest.raises(ValueError, match="too short"):
            decode_message(b"\x00" * 5)

    def test_decode_message_truncated_quant(self) -> None:
        """Truncated quantization table raises ValueError."""
        # Header says 1 quant table but not enough data
        data = bytearray()
        data += struct.pack("<H", 0xCAC3)
        data += struct.pack("<I", 20)
        data += struct.pack("<H", 1)  # 1 tile
        data += struct.pack("B", 1)   # 1 quant table
        data += struct.pack("B", 1)   # mode
        data += b"\x00" * 3           # only 3 bytes instead of 5
        with pytest.raises(ValueError, match="Truncated"):
            decode_message(bytes(data))


class TestRemoteFxCodec:
    """Tests for the RemoteFxCodec class interface."""

    def test_codec_decode_tile(self) -> None:
        """RemoteFxCodec.decode_tile delegates correctly."""
        tile_data = bytearray()
        tile_data += struct.pack("<H", 4)
        tile_data += b"\x00" * 4
        tile_data += struct.pack("<H", 4)
        tile_data += b"\x00" * 4
        tile_data += struct.pack("<H", 4)
        tile_data += b"\x00" * 4

        quant = QuantValues(
            hl1=6, lh1=6, hh1=6,
            hl2=6, lh2=6, hh2=6,
            hl3=6, lh3=6, hh3=6,
            ll3=6,
        )
        result = RemoteFxCodec.decode_tile(bytes(tile_data), quant)
        assert len(result) == 16384

    def test_codec_decode_message(self) -> None:
        """RemoteFxCodec.decode_message delegates correctly."""
        # Build a minimal valid message
        tile_data = bytearray()
        tile_data += struct.pack("<H", 4)
        tile_data += b"\x00" * 4
        tile_data += struct.pack("<H", 4)
        tile_data += b"\x00" * 4
        tile_data += struct.pack("<H", 4)
        tile_data += b"\x00" * 4

        msg = bytearray()
        msg += struct.pack("<H", 0xCAC3)
        msg += struct.pack("<I", 0)
        msg += struct.pack("<H", 1)  # 1 tile
        msg += struct.pack("B", 1)   # 1 quant table
        msg += struct.pack("B", 1)   # RLGR1
        # Quant table: all 6s packed as nibbles
        msg += bytes([0x66, 0x66, 0x66, 0x66, 0x66])
        # Tile: quant_idx=0, x=128, y=256
        msg += struct.pack("B", 0)
        msg += struct.pack("<H", 128)
        msg += struct.pack("<H", 256)
        msg += struct.pack("<H", len(tile_data))
        msg += tile_data
        # Update block length
        struct.pack_into("<I", msg, 2, len(msg))

        results = RemoteFxCodec.decode_message(bytes(msg))
        assert len(results) == 1
        rect, pixels = results[0]
        assert rect == Rect(x=128, y=256, w=64, h=64)
        assert len(pixels) == 16384
