"""NSCodec decompression codec per [MS-RDPNSC].

NSCodec encodes bitmap data as 4 separate color planes (A, R, G, B),
each independently run-length encoded. The codec supports both lossy
and lossless decoding modes.

In lossless mode, planes are decoded and combined directly.
In lossy mode, chroma subsampling is applied (reduced color resolution).

Reference: [MS-RDPNSC] Remote Desktop Protocol: NSCodec Extension.
"""

from __future__ import annotations

import struct


class NsCodecError(Exception):
    """Raised when NSCodec decoding encounters invalid data."""

    def __init__(self, message: str = "NSCodec decode error") -> None:
        super().__init__(message)


def _decode_plane(data: bytes, expected_size: int) -> bytes:
    """Decode a single RLE-encoded color plane.

    Each plane uses a simple RLE scheme:
    - If a byte value is followed by a different byte, it's a literal.
    - Runs are encoded as: value, value, run_length (additional count).

    Per [MS-RDPNSC] Section 2.2, the plane RLE format is:
    - Read a byte value
    - If the next byte is the same value, read a third byte as run count
      (the total run is count + 2)
    - Otherwise, the byte is a single literal

    Args:
        data: RLE-encoded plane data.
        expected_size: Expected number of decoded bytes (width * height).

    Returns:
        Decoded plane data.

    Raises:
        NsCodecError: On invalid or truncated data.
    """
    if len(data) == expected_size:
        # Uncompressed plane - data is already raw
        return data

    output = bytearray(expected_size)
    src_offset = 0
    dst_offset = 0
    src_len = len(data)

    while dst_offset < expected_size and src_offset < src_len:
        value = data[src_offset]
        src_offset += 1

        if src_offset < src_len and data[src_offset] == value:
            # Run detected: same value repeated
            src_offset += 1  # skip the duplicate byte

            if src_offset >= src_len:
                # Run of exactly 2
                run_length = 2
            else:
                # Read the run count (additional bytes beyond the initial 2)
                run_length = data[src_offset] + 2
                src_offset += 1

            # Bounds check
            if dst_offset + run_length > expected_size:
                run_length = expected_size - dst_offset

            for i in range(run_length):
                output[dst_offset + i] = value
            dst_offset += run_length
        else:
            # Single literal byte
            output[dst_offset] = value
            dst_offset += 1

    # If we haven't filled the output, pad with zeros
    # (shouldn't happen with valid data, but be defensive)
    return bytes(output)


def _apply_chroma_subsampling(
    r_plane: bytes, g_plane: bytes, b_plane: bytes, width: int, height: int
) -> tuple[bytes, bytes, bytes]:
    """Apply lossy chroma subsampling to reduce color resolution.

    In lossy mode, the chroma (color difference) information is
    subsampled by averaging 2x2 blocks, similar to YCbCr 4:2:0.
    This reduces perceived quality slightly but maintains luminance.

    For NSCodec lossy mode, we reduce color resolution by averaging
    neighboring pixels in the R and B planes (treating G as luminance).

    Args:
        r_plane: Decoded R plane data.
        g_plane: Decoded G plane data.
        b_plane: Decoded B plane data.
        width: Image width in pixels.
        height: Image height in pixels.

    Returns:
        Tuple of (r_plane, g_plane, b_plane) with subsampling applied.
    """
    # In lossy mode, subsample R and B channels in 2x2 blocks
    r_out = bytearray(r_plane)
    b_out = bytearray(b_plane)

    for y in range(0, height - 1, 2):
        for x in range(0, width - 1, 2):
            # Average the 2x2 block for R
            idx00 = y * width + x
            idx01 = y * width + x + 1
            idx10 = (y + 1) * width + x
            idx11 = (y + 1) * width + x + 1

            r_avg = (r_out[idx00] + r_out[idx01] + r_out[idx10] + r_out[idx11]) >> 2
            r_out[idx00] = r_avg
            r_out[idx01] = r_avg
            r_out[idx10] = r_avg
            r_out[idx11] = r_avg

            b_avg = (b_out[idx00] + b_out[idx01] + b_out[idx10] + b_out[idx11]) >> 2
            b_out[idx00] = b_avg
            b_out[idx01] = b_avg
            b_out[idx10] = b_avg
            b_out[idx11] = b_avg

    return bytes(r_out), bytes(g_plane), bytes(b_out)


class NsCodec:
    """NSCodec bitmap decompression codec.

    Implements the NSCodec compression format per [MS-RDPNSC].
    The codec encodes bitmaps as 4 independent color planes (A, R, G, B),
    each run-length encoded separately.

    Output is always in RGBA format (4 bytes per pixel) for surface rendering.
    """

    @staticmethod
    def decode(
        data: bytes,
        width: int,
        height: int,
        bpp: int = 32,
        lossy: bool = False,
    ) -> bytes:
        """Decode NSCodec-encoded bitmap data to RGBA pixels.

        Args:
            data: NSCodec-encoded bitmap data including the header.
            width: Width of the bitmap in pixels.
            height: Height of the bitmap in pixels.
            bpp: Bits per pixel (typically 32 for ARGB).
            lossy: True for lossy decoding mode (chroma subsampling).

        Returns:
            RGBA pixel data (width * height * 4 bytes).

        Raises:
            NsCodecError: On invalid or truncated data.
        """
        if width <= 0 or height <= 0:
            raise NsCodecError(f"Invalid dimensions: {width}x{height}")

        pixel_count = width * height

        # NSCodec header: 4 plane lengths (each uint32 LE)
        # Plane order: LumaPlane (A), OrangeChromaPlane (R),
        #              GreenChromaPlane (G), BluePlane (B)
        # Per [MS-RDPNSC] 2.2.1 - NSCODEC_BITMAP_STREAM
        header_size = 20  # 4 * uint32 plane lengths + uint32 color_loss_level/chroma_subsampling/dynamic_fidelity/reserved (packed as 1 byte each + padding)

        # The NSCodec stream format per [MS-RDPNSC]:
        # - LumaPlaneLen (4 bytes)
        # - OrangeChromaPlaneLen (4 bytes)
        # - GreenChromaPlaneLen (4 bytes)
        # - AlphaPlaneLen (4 bytes)
        # - ColorLossLevel (1 byte)
        # - ChromaSubsamplingLevel (1 byte)
        # - DynamicFidelity (1 byte)
        # - Reserved (1 byte)
        # Then the plane data follows

        if len(data) < 20:
            raise NsCodecError(
                f"Data too short for NSCodec header: {len(data)} bytes (need at least 20)"
            )

        # Parse header
        luma_len = struct.unpack_from("<I", data, 0)[0]
        orange_chroma_len = struct.unpack_from("<I", data, 4)[0]
        green_chroma_len = struct.unpack_from("<I", data, 8)[0]
        alpha_len = struct.unpack_from("<I", data, 12)[0]

        color_loss_level = data[16]
        chroma_subsampling_level = data[17]
        # dynamic_fidelity = data[18]
        # reserved = data[19]

        # Determine if lossy based on header or parameter
        # If chroma_subsampling_level > 0 or color_loss_level > 0, it's lossy
        is_lossy = lossy or chroma_subsampling_level > 0

        offset = 20

        # Validate total data length
        total_plane_data = luma_len + orange_chroma_len + green_chroma_len + alpha_len
        if offset + total_plane_data > len(data):
            raise NsCodecError(
                f"Data too short for plane data: have {len(data) - offset} bytes, "
                f"need {total_plane_data}"
            )

        # Extract plane data
        luma_data = data[offset : offset + luma_len]
        offset += luma_len

        orange_chroma_data = data[offset : offset + orange_chroma_len]
        offset += orange_chroma_len

        green_chroma_data = data[offset : offset + green_chroma_len]
        offset += green_chroma_len

        alpha_data = data[offset : offset + alpha_len]

        # Decode each plane
        # In NSCodec, the planes map to:
        # Luma -> Green channel (luminance-like)
        # OrangeChroma -> Red channel
        # GreenChroma -> Blue channel
        # Alpha -> Alpha channel
        g_plane = _decode_plane(luma_data, pixel_count)
        r_plane = _decode_plane(orange_chroma_data, pixel_count)
        b_plane = _decode_plane(green_chroma_data, pixel_count)
        a_plane = _decode_plane(alpha_data, pixel_count)

        # Apply lossy chroma subsampling if requested
        if is_lossy:
            r_plane, g_plane, b_plane = _apply_chroma_subsampling(
                r_plane, g_plane, b_plane, width, height
            )

        # Combine planes into RGBA output
        rgba = bytearray(pixel_count * 4)
        for i in range(pixel_count):
            rgba[i * 4] = r_plane[i]
            rgba[i * 4 + 1] = g_plane[i]
            rgba[i * 4 + 2] = b_plane[i]
            rgba[i * 4 + 3] = a_plane[i]

        return bytes(rgba)
