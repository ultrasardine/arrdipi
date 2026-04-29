"""Tests for the NSCodec decompression codec."""

from __future__ import annotations

import struct

import pytest

from arrdipi.codec.nscodec import NsCodec, NsCodecError, _decode_plane


class TestDecodePlane:
    """Tests for the internal plane RLE decoder."""

    def test_uncompressed_plane(self) -> None:
        """When data length equals expected size, return as-is."""
        data = bytes(range(16))
        result = _decode_plane(data, 16)
        assert result == data

    def test_single_literal_bytes(self) -> None:
        """Alternating bytes are treated as literals."""
        # Alternating values: no two consecutive bytes are the same
        data = bytes([0x10, 0x20, 0x30, 0x40])
        result = _decode_plane(data, 4)
        assert result == data

    def test_run_length_encoding(self) -> None:
        """Two identical bytes followed by a count produce a run."""
        # value=0xAA, duplicate=0xAA, count=3 -> run of 5 (3+2)
        data = bytes([0xAA, 0xAA, 0x03])
        result = _decode_plane(data, 5)
        assert result == bytes([0xAA] * 5)

    def test_run_of_two(self) -> None:
        """Two identical bytes at end of data produce a run of 2."""
        # value=0x55, duplicate=0x55, no count byte (end of data) -> run of 2
        data = bytes([0x55, 0x55])
        result = _decode_plane(data, 2)
        assert result == bytes([0x55, 0x55])

    def test_mixed_literals_and_runs(self) -> None:
        """Mix of literal bytes and runs."""
        # Literal 0x10, then run of 0xFF * 4 (count=2 -> 2+2=4)
        data = bytes([0x10, 0xFF, 0xFF, 0x02])
        result = _decode_plane(data, 5)
        assert result == bytes([0x10, 0xFF, 0xFF, 0xFF, 0xFF])

    def test_zero_run(self) -> None:
        """Run with count=0 produces a run of 2."""
        data = bytes([0xBB, 0xBB, 0x00])
        result = _decode_plane(data, 2)
        assert result == bytes([0xBB, 0xBB])

    def test_large_run(self) -> None:
        """Run with count=253 produces a run of 255."""
        data = bytes([0x42, 0x42, 253])
        result = _decode_plane(data, 255)
        assert result == bytes([0x42] * 255)


class TestNsCodecDecode:
    """Tests for the NsCodec.decode static method."""

    def _build_nscodec_data(
        self,
        luma: bytes,
        orange_chroma: bytes,
        green_chroma: bytes,
        alpha: bytes,
        color_loss_level: int = 0,
        chroma_subsampling: int = 0,
        dynamic_fidelity: int = 0,
    ) -> bytes:
        """Build a valid NSCodec data stream with header."""
        header = struct.pack(
            "<IIIIBBBB",
            len(luma),
            len(orange_chroma),
            len(green_chroma),
            len(alpha),
            color_loss_level,
            chroma_subsampling,
            dynamic_fidelity,
            0,  # reserved
        )
        return header + luma + orange_chroma + green_chroma + alpha

    def test_decode_single_pixel_lossless(self) -> None:
        """Decode a single pixel in lossless mode."""
        # 1x1 pixel: R=0x80, G=0x40, B=0x20, A=0xFF
        # Planes: luma(G)=0x40, orange_chroma(R)=0x80, green_chroma(B)=0x20, alpha=0xFF
        data = self._build_nscodec_data(
            luma=bytes([0x40]),
            orange_chroma=bytes([0x80]),
            green_chroma=bytes([0x20]),
            alpha=bytes([0xFF]),
        )
        result = NsCodec.decode(data, width=1, height=1, bpp=32, lossy=False)
        # Output is RGBA
        assert result == bytes([0x80, 0x40, 0x20, 0xFF])

    def test_decode_2x2_lossless(self) -> None:
        """Decode a 2x2 image in lossless mode."""
        # 4 pixels, all same color: R=0xFF, G=0x00, B=0x00, A=0xFF (red)
        pixel_count = 4
        data = self._build_nscodec_data(
            luma=bytes([0x00] * pixel_count),  # G=0
            orange_chroma=bytes([0xFF] * pixel_count),  # R=0xFF
            green_chroma=bytes([0x00] * pixel_count),  # B=0
            alpha=bytes([0xFF] * pixel_count),  # A=0xFF
        )
        result = NsCodec.decode(data, width=2, height=2, bpp=32, lossy=False)
        assert len(result) == 16  # 4 pixels * 4 bytes
        # Each pixel should be (R=0xFF, G=0x00, B=0x00, A=0xFF)
        for i in range(4):
            assert result[i * 4 : i * 4 + 4] == bytes([0xFF, 0x00, 0x00, 0xFF])

    def test_decode_with_rle_compressed_planes(self) -> None:
        """Decode with RLE-compressed plane data."""
        # 4x4 = 16 pixels, all same value per plane
        # RLE: value, value, count -> run of count+2
        width, height = 4, 4
        pixel_count = 16

        # Encode each plane as a run: value, value, 14 (= 14+2 = 16 pixels)
        g_rle = bytes([0x80, 0x80, 14])  # G=0x80
        r_rle = bytes([0x40, 0x40, 14])  # R=0x40
        b_rle = bytes([0xC0, 0xC0, 14])  # B=0xC0
        a_rle = bytes([0xFF, 0xFF, 14])  # A=0xFF

        data = self._build_nscodec_data(
            luma=g_rle,
            orange_chroma=r_rle,
            green_chroma=b_rle,
            alpha=a_rle,
        )
        result = NsCodec.decode(data, width=width, height=height, bpp=32, lossy=False)
        assert len(result) == pixel_count * 4
        for i in range(pixel_count):
            assert result[i * 4 : i * 4 + 4] == bytes([0x40, 0x80, 0xC0, 0xFF])

    def test_decode_lossy_mode(self) -> None:
        """Decode in lossy mode applies chroma subsampling."""
        # 2x2 image with varying R and B values
        # R plane: [100, 200, 50, 150] -> average = (100+200+50+150)/4 = 125
        # B plane: [10, 20, 30, 40] -> average = (10+20+30+40)/4 = 25
        width, height = 2, 2
        pixel_count = 4

        r_values = bytes([100, 200, 50, 150])
        g_values = bytes([80, 80, 80, 80])
        b_values = bytes([10, 20, 30, 40])
        a_values = bytes([255, 255, 255, 255])

        data = self._build_nscodec_data(
            luma=g_values,
            orange_chroma=r_values,
            green_chroma=b_values,
            alpha=a_values,
        )
        result = NsCodec.decode(data, width=width, height=height, bpp=32, lossy=True)
        assert len(result) == pixel_count * 4

        # In lossy mode, R and B are averaged across the 2x2 block
        r_avg = (100 + 200 + 50 + 150) >> 2  # 125
        b_avg = (10 + 20 + 30 + 40) >> 2  # 25

        for i in range(pixel_count):
            assert result[i * 4] == r_avg  # R
            assert result[i * 4 + 1] == 80  # G unchanged
            assert result[i * 4 + 2] == b_avg  # B
            assert result[i * 4 + 3] == 255  # A unchanged

    def test_decode_lossy_via_header_flag(self) -> None:
        """Lossy mode triggered by chroma_subsampling_level in header."""
        width, height = 2, 2
        pixel_count = 4

        r_values = bytes([100, 200, 50, 150])
        g_values = bytes([80, 80, 80, 80])
        b_values = bytes([10, 20, 30, 40])
        a_values = bytes([255, 255, 255, 255])

        data = self._build_nscodec_data(
            luma=g_values,
            orange_chroma=r_values,
            green_chroma=b_values,
            alpha=a_values,
            chroma_subsampling=1,  # Triggers lossy mode
        )
        # Even with lossy=False, header flag triggers lossy
        result = NsCodec.decode(data, width=width, height=height, bpp=32, lossy=False)

        r_avg = (100 + 200 + 50 + 150) >> 2
        b_avg = (10 + 20 + 30 + 40) >> 2

        for i in range(pixel_count):
            assert result[i * 4] == r_avg
            assert result[i * 4 + 2] == b_avg

    def test_decode_lossless_preserves_exact_values(self) -> None:
        """Lossless mode preserves exact pixel values without modification."""
        width, height = 2, 2
        pixel_count = 4

        r_values = bytes([100, 200, 50, 150])
        g_values = bytes([10, 20, 30, 40])
        b_values = bytes([60, 70, 80, 90])
        a_values = bytes([255, 128, 64, 0])

        data = self._build_nscodec_data(
            luma=g_values,
            orange_chroma=r_values,
            green_chroma=b_values,
            alpha=a_values,
        )
        result = NsCodec.decode(data, width=width, height=height, bpp=32, lossy=False)

        for i in range(pixel_count):
            assert result[i * 4] == r_values[i]
            assert result[i * 4 + 1] == g_values[i]
            assert result[i * 4 + 2] == b_values[i]
            assert result[i * 4 + 3] == a_values[i]

    def test_decode_larger_image(self) -> None:
        """Decode a larger image (8x8) with RLE compression."""
        width, height = 8, 8
        pixel_count = 64

        # All white pixels: R=G=B=A=255
        # RLE: 0xFF, 0xFF, 62 -> run of 64
        plane_rle = bytes([0xFF, 0xFF, 62])

        data = self._build_nscodec_data(
            luma=plane_rle,
            orange_chroma=plane_rle,
            green_chroma=plane_rle,
            alpha=plane_rle,
        )
        result = NsCodec.decode(data, width=width, height=height, bpp=32, lossy=False)
        assert len(result) == pixel_count * 4
        assert result == bytes([0xFF] * pixel_count * 4)

    def test_decode_all_black_with_alpha(self) -> None:
        """Decode all-black image with full alpha."""
        width, height = 4, 4
        pixel_count = 16

        black_rle = bytes([0x00, 0x00, 14])  # 16 zeros
        alpha_rle = bytes([0xFF, 0xFF, 14])  # 16 x 0xFF

        data = self._build_nscodec_data(
            luma=black_rle,
            orange_chroma=black_rle,
            green_chroma=black_rle,
            alpha=alpha_rle,
        )
        result = NsCodec.decode(data, width=width, height=height, bpp=32, lossy=False)
        for i in range(pixel_count):
            assert result[i * 4 : i * 4 + 4] == bytes([0x00, 0x00, 0x00, 0xFF])


class TestNsCodecErrors:
    """Tests for NSCodec error handling."""

    def test_data_too_short_for_header(self) -> None:
        """Raise error when data is shorter than the 20-byte header."""
        with pytest.raises(NsCodecError, match="Data too short for NSCodec header"):
            NsCodec.decode(b"\x00" * 10, width=1, height=1)

    def test_data_too_short_for_planes(self) -> None:
        """Raise error when plane data is truncated."""
        # Header claims 100 bytes of plane data but only provides 10
        header = struct.pack("<IIIIBBBB", 50, 20, 20, 10, 0, 0, 0, 0)
        data = header + b"\x00" * 10  # Only 10 bytes of plane data
        with pytest.raises(NsCodecError, match="Data too short for plane data"):
            NsCodec.decode(data, width=10, height=10)

    def test_invalid_dimensions_zero_width(self) -> None:
        """Raise error for zero width."""
        with pytest.raises(NsCodecError, match="Invalid dimensions"):
            NsCodec.decode(b"\x00" * 20, width=0, height=1)

    def test_invalid_dimensions_zero_height(self) -> None:
        """Raise error for zero height."""
        with pytest.raises(NsCodecError, match="Invalid dimensions"):
            NsCodec.decode(b"\x00" * 20, width=1, height=0)

    def test_invalid_dimensions_negative(self) -> None:
        """Raise error for negative dimensions."""
        with pytest.raises(NsCodecError, match="Invalid dimensions"):
            NsCodec.decode(b"\x00" * 20, width=-1, height=1)
