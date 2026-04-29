"""RemoteFX (RFX) wavelet-based image codec per [MS-RDPRFX].

Decoding pipeline: RLGR entropy decode -> dequantize -> inverse DWT -> YCbCr to RGB.
Tiles are 64x64 pixels.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from arrdipi.graphics.surface import Rect


# --- Constants ---
TILE_SIZE = 64


# --- Bit reader for RLGR decoding ---

class _BitReader:
    """Reads bits from a byte buffer, MSB first."""

    __slots__ = ("_data", "_pos", "_bit_pos", "_length")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0
        self._bit_pos = 0
        self._length = len(data)

    def read_bit(self) -> int:
        """Read a single bit."""
        if self._pos >= self._length:
            return 0
        bit = (self._data[self._pos] >> (7 - self._bit_pos)) & 1
        self._bit_pos += 1
        if self._bit_pos == 8:
            self._bit_pos = 0
            self._pos += 1
        return bit

    def read_bits(self, n: int) -> int:
        """Read n bits and return as an integer."""
        value = 0
        for _ in range(n):
            value = (value << 1) | self.read_bit()
        return value

    def bits_remaining(self) -> int:
        """Return the number of bits remaining."""
        return (self._length - self._pos) * 8 - self._bit_pos


# --- RLGR entropy decoding ---

def _rlgr_decode(data: bytes, mode: int, num_values: int) -> list[int]:
    """Decode RLGR1 or RLGR3 encoded data.

    Args:
        data: Encoded byte data.
        mode: 1 for RLGR1, 3 for RLGR3.
        num_values: Number of coefficients to decode.

    Returns:
        List of decoded integer coefficients.
    """
    if mode not in (1, 3):
        raise ValueError(f"Unsupported RLGR mode: {mode}")

    reader = _BitReader(data)
    output: list[int] = []

    # Adaptive parameters
    k_rp = 1  # Run/Literal parameter for run-length
    k_r = 0   # Golomb-Rice parameter for runs
    kr_p = 1  # Parameter for GR coding
    k = 0     # Golomb-Rice parameter for values

    while len(output) < num_values:
        if reader.bits_remaining() <= 0:
            # Pad with zeros if we run out of data
            output.extend([0] * (num_values - len(output)))
            break

        # Check if this is a run or a value
        bit = reader.read_bit()

        if bit == 0:
            # Run of zeros
            # Read unary-coded run length
            run_length = 0
            # The run length is encoded in Golomb-Rice with parameter k_r
            # Read the unary prefix
            unary = 0
            while reader.bits_remaining() > 0:
                b = reader.read_bit()
                if b == 0:
                    unary += 1
                else:
                    break

            # Read k_r remainder bits
            remainder = 0
            if k_r > 0:
                remainder = reader.read_bits(k_r)

            run_length = (unary << k_r) | remainder

            # Output run_length zeros
            for _ in range(run_length):
                if len(output) >= num_values:
                    break
                output.append(0)

            # After a run, output a non-zero value (unless we've filled output)
            if len(output) < num_values:
                # Decode a non-zero value using GR coding
                val = _decode_gr_value(reader, k)
                output.append(val)

            # Update k_r adaptively
            if run_length == 0:
                k_rp = max(k_rp - 2, 0)
            else:
                k_rp = min(k_rp + (run_length > (1 << k_r)), 62)
            k_r = k_rp >> 1

        else:
            # Non-zero value(s)
            if mode == 1:
                # RLGR1: single value
                val = _decode_gr_value(reader, k)
                output.append(val)
                # Update k adaptively
                if val == 0:
                    kr_p = max(kr_p - 2, 0)
                else:
                    kr_p = min(kr_p + 4, 62)
                k = kr_p >> 1
            else:
                # RLGR3: pair of values
                val1 = _decode_gr_value(reader, k)
                output.append(val1)
                if len(output) < num_values:
                    val2 = _decode_gr_value(reader, k)
                    output.append(val2)
                # Update k adaptively
                if val1 == 0:
                    kr_p = max(kr_p - 2, 0)
                else:
                    kr_p = min(kr_p + 4, 62)
                k = kr_p >> 1

    return output[:num_values]


def _decode_gr_value(reader: _BitReader, k: int) -> int:
    """Decode a single Golomb-Rice coded value with sign."""
    # Read unary prefix (number of zeros before a 1)
    unary = 0
    while reader.bits_remaining() > 0:
        b = reader.read_bit()
        if b == 0:
            unary += 1
        else:
            break

    # Read k remainder bits
    remainder = 0
    if k > 0:
        remainder = reader.read_bits(k)

    magnitude = (unary << k) | remainder

    # Convert from magnitude to signed value
    # Even magnitudes are positive, odd are negative
    if magnitude == 0:
        return 0
    elif magnitude & 1:
        return -((magnitude + 1) >> 1)
    else:
        return magnitude >> 1


def rlgr1_decode(data: bytes, num_values: int) -> list[int]:
    """Decode RLGR1 encoded data.

    Args:
        data: RLGR1 encoded byte data.
        num_values: Number of coefficients to decode.

    Returns:
        List of decoded integer coefficients.
    """
    return _rlgr_decode(data, mode=1, num_values=num_values)


def rlgr3_decode(data: bytes, num_values: int) -> list[int]:
    """Decode RLGR3 encoded data.

    Args:
        data: RLGR3 encoded byte data.
        num_values: Number of coefficients to decode.

    Returns:
        List of decoded integer coefficients.
    """
    return _rlgr_decode(data, mode=3, num_values=num_values)


# --- Dequantization ---

# Subband order: HL1, LH1, HH1, HL2, LH2, HH2, HL3, LH3, HH3, LL3
# Each subband has a quantization value (shift amount)

# Subband regions in the 64x64 coefficient grid after DWT decomposition:
# Level 1 subbands are 32x32
# Level 2 subbands are 16x16
# Level 3 subbands are 8x8

@dataclass(frozen=True, slots=True)
class QuantValues:
    """Per-subband quantization values for RemoteFX tile decoding.

    Order: HL1, LH1, HH1, HL2, LH2, HH2, HL3, LH3, HH3, LL3
    """
    hl1: int
    lh1: int
    hh1: int
    hl2: int
    lh2: int
    hh2: int
    hl3: int
    lh3: int
    hh3: int
    ll3: int


def _dequantize_subband(coeffs: list[int], quant_val: int) -> list[int]:
    """Dequantize a subband by left-shifting coefficients.

    The quantization value represents the number of bits to shift left.
    A value of 6 means the original was divided by 2^(6-6)=1 (no shift for base).
    The actual shift is quant_val - 6 for detail subbands, quant_val - 6 for LL.
    Per [MS-RDPRFX], the shift is simply quant_val - 6 (minimum 0).
    """
    shift = max(0, quant_val - 6)
    if shift == 0:
        return coeffs
    return [c << shift for c in coeffs]


def _dequantize_tile(
    coeffs: list[int], quant: QuantValues
) -> list[list[int]]:
    """Dequantize a 64x64 tile's wavelet coefficients.

    The coefficients are stored in a linearized order matching the subband layout.
    Returns a 64x64 grid as a list of 4096 values.
    """
    # The coefficients come in subband order from RLGR decoding.
    # Layout in the 64x64 grid:
    # LL3 (8x8) | HL3 (8x8)
    # LH3 (8x8) | HH3 (8x8)
    # --- forms 16x16 ---
    # HL2 (16x16) next to the 16x16 block
    # LH2 (16x16) below the 16x16 block
    # HH2 (16x16) diagonal
    # --- forms 32x32 ---
    # HL1 (32x32) next to the 32x32 block
    # LH1 (32x32) below the 32x32 block
    # HH1 (32x32) diagonal

    # Subband sizes
    # Level 3: 8x8 each (LL3, HL3, LH3, HH3)
    # Level 2: 16x16 each (HL2, LH2, HH2)
    # Level 1: 32x32 each (HL1, LH1, HH1)

    # Total coefficients: 8*8*4 + 16*16*3 + 32*32*3 = 256 + 768 + 3072 = 4096

    # The RLGR stream produces coefficients in a specific subband order.
    # Per [MS-RDPRFX] 3.1.8.1.3, the order is:
    # LL3, HL3, LH3, HH3, HL2, LH2, HH2, HL1, LH1, HH1

    idx = 0
    ll3_size = 8 * 8
    l3_size = 8 * 8
    l2_size = 16 * 16
    l1_size = 32 * 32

    ll3 = _dequantize_subband(coeffs[idx:idx + ll3_size], quant.ll3)
    idx += ll3_size
    hl3 = _dequantize_subband(coeffs[idx:idx + l3_size], quant.hl3)
    idx += l3_size
    lh3 = _dequantize_subband(coeffs[idx:idx + l3_size], quant.lh3)
    idx += l3_size
    hh3 = _dequantize_subband(coeffs[idx:idx + l3_size], quant.hh3)
    idx += l3_size
    hl2 = _dequantize_subband(coeffs[idx:idx + l2_size], quant.hl2)
    idx += l2_size
    lh2 = _dequantize_subband(coeffs[idx:idx + l2_size], quant.lh2)
    idx += l2_size
    hh2 = _dequantize_subband(coeffs[idx:idx + l2_size], quant.hh2)
    idx += l2_size
    hl1 = _dequantize_subband(coeffs[idx:idx + l1_size], quant.hl1)
    idx += l1_size
    lh1 = _dequantize_subband(coeffs[idx:idx + l1_size], quant.lh1)
    idx += l1_size
    hh1 = _dequantize_subband(coeffs[idx:idx + l1_size], quant.hh1)

    return [ll3, hl3, lh3, hh3, hl2, lh2, hh2, hl1, lh1, hh1]


# --- Inverse DWT (5/3 Le Gall integer wavelet) ---

def _idwt_1d(low: list[int], high: list[int]) -> list[int]:
    """Perform 1D inverse DWT using the 5/3 Le Gall wavelet.

    The 5/3 wavelet lifting steps (inverse):
    1. s[n] = s[n] - floor((d[n-1] + d[n]) / 2)  (update step, inverse)
    2. d[n] = d[n] + floor((s[n] + s[n+1] + 1) / 2)  (predict step, inverse)

    Then interleave: output[2n] = s[n], output[2n+1] = d[n]
    """
    n = len(low)
    if n == 0:
        return []

    s = list(low)  # even samples (low-pass)
    d = list(high)  # odd samples (high-pass)

    # Inverse update: s[n] += floor((d[n-1] + d[n]) / 2)
    for i in range(n):
        d_left = d[i - 1] if i > 0 else d[0]
        d_right = d[i] if i < len(d) else d[-1]
        s[i] = s[i] + ((d_left + d_right) // 2)

    # Inverse predict: d[n] -= floor((s[n] + s[n+1] + 1) / 2)
    for i in range(len(d)):
        s_left = s[i]
        s_right = s[i + 1] if i + 1 < n else s[-1]
        d[i] = d[i] - ((s_left + s_right + 1) // 2)

    # Interleave
    output = [0] * (n + len(d))
    for i in range(n):
        output[2 * i] = s[i]
    for i in range(len(d)):
        output[2 * i + 1] = d[i]

    return output


def _subband_to_grid(ll: list[int], hl: list[int], lh: list[int], hh: list[int], size: int) -> list[list[int]]:
    """Reconstruct a 2D grid from subbands using inverse 2D DWT.

    Args:
        ll: Low-low subband (size x size).
        hl: High-low subband (size x size).
        lh: Low-high subband (size x size).
        hh: High-high subband (size x size).
        size: Size of each subband (output will be 2*size x 2*size).

    Returns:
        2D grid as list of rows, each row is a list of ints.
    """
    out_size = size * 2

    # First, apply inverse DWT on columns
    # For each column j in [0, size):
    #   low column = ll[:, j] and lh[:, j]
    #   high column = hl[:, j] and hh[:, j]
    # This gives us intermediate rows

    # Build intermediate grid (out_size rows x size columns for left half,
    # out_size rows x size columns for right half)
    left_cols: list[list[int]] = []  # out_size rows, size cols
    right_cols: list[list[int]] = []  # out_size rows, size cols

    for j in range(size):
        # Left half column: inverse DWT of ll column and lh column
        low_col = [ll[i * size + j] for i in range(size)]
        high_col = [lh[i * size + j] for i in range(size)]
        col_result = _idwt_1d(low_col, high_col)
        left_cols.append(col_result)

        # Right half column: inverse DWT of hl column and hh column
        low_col2 = [hl[i * size + j] for i in range(size)]
        high_col2 = [hh[i * size + j] for i in range(size)]
        col_result2 = _idwt_1d(low_col2, high_col2)
        right_cols.append(col_result2)

    # Now apply inverse DWT on rows
    grid: list[list[int]] = []
    for i in range(out_size):
        low_row = [left_cols[j][i] for j in range(size)]
        high_row = [right_cols[j][i] for j in range(size)]
        row = _idwt_1d(low_row, high_row)
        grid.append(row)

    return grid


def _inverse_dwt_2d(subbands: list[list[int]]) -> list[list[int]]:
    """Perform full 3-level inverse 2D DWT to reconstruct a 64x64 tile.

    Args:
        subbands: [LL3, HL3, LH3, HH3, HL2, LH2, HH2, HL1, LH1, HH1]
                  Each is a flat list of coefficients for that subband.

    Returns:
        64x64 grid as list of 64 rows, each row is a list of 64 ints.
    """
    ll3, hl3, lh3, hh3, hl2, lh2, hh2, hl1, lh1, hh1 = subbands

    # Level 3: 8x8 subbands -> 16x16
    grid_16 = _subband_to_grid(ll3, hl3, lh3, hh3, 8)

    # Flatten grid_16 to use as LL2
    ll2 = []
    for row in grid_16:
        ll2.extend(row)

    # Level 2: 16x16 subbands -> 32x32
    grid_32 = _subband_to_grid(ll2, hl2, lh2, hh2, 16)

    # Flatten grid_32 to use as LL1
    ll1 = []
    for row in grid_32:
        ll1.extend(row)

    # Level 1: 32x32 subbands -> 64x64
    grid_64 = _subband_to_grid(ll1, hl1, lh1, hh1, 32)

    return grid_64


# --- YCbCr to RGB conversion ---

def _ycbcr_to_rgb(
    y_grid: list[list[int]],
    cb_grid: list[list[int]],
    cr_grid: list[list[int]],
) -> bytes:
    """Convert YCbCr pixel grids to RGBA byte data.

    Conversion formulas:
        R = Y + 1.403 * Cr
        G = Y - 0.344 * Cb - 0.714 * Cr
        B = Y + 1.770 * Cb

    Args:
        y_grid: 64x64 Y component grid.
        cb_grid: 64x64 Cb component grid.
        cr_grid: 64x64 Cr component grid.

    Returns:
        RGBA pixel data as bytes (64*64*4 = 16384 bytes).
    """
    result = bytearray(TILE_SIZE * TILE_SIZE * 4)
    idx = 0

    for row in range(TILE_SIZE):
        for col in range(TILE_SIZE):
            y_val = y_grid[row][col]
            cb_val = cb_grid[row][col]
            cr_val = cr_grid[row][col]

            r = y_val + int(1.403 * cr_val)
            g = y_val - int(0.344 * cb_val) - int(0.714 * cr_val)
            b = y_val + int(1.770 * cb_val)

            # Clamp to [0, 255]
            r = max(0, min(255, r))
            g = max(0, min(255, g))
            b = max(0, min(255, b))

            result[idx] = r
            result[idx + 1] = g
            result[idx + 2] = b
            result[idx + 3] = 255  # Alpha
            idx += 4

    return bytes(result)


# --- Public API ---

def decode_tile(data: bytes, quant_vals: QuantValues, mode: int = 1) -> bytes:
    """Decode a single RemoteFX tile from encoded data.

    The decoding pipeline:
    1. RLGR entropy decode (produces 4096 coefficients per component)
    2. Dequantize with per-subband quantization values
    3. Inverse DWT (3-level 5/3 wavelet)
    4. YCbCr to RGB color space conversion

    Args:
        data: Encoded tile data containing Y, Cb, Cr components.
        quant_vals: Per-subband quantization values (same for all components
                    or can be extended to per-component quant).
        mode: RLGR mode (1 or 3).

    Returns:
        RGBA pixel data as bytes (64*64*4 = 16384 bytes).
    """
    num_coeffs = TILE_SIZE * TILE_SIZE  # 4096

    # The tile data contains three component streams (Y, Cb, Cr)
    # Each stream is preceded by a 2-byte length
    offset = 0

    # Parse Y component
    if offset + 2 > len(data):
        raise ValueError("Truncated tile data: missing Y length")
    y_len = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    if offset + y_len > len(data):
        raise ValueError("Truncated tile data: Y component")
    y_data = data[offset:offset + y_len]
    offset += y_len

    # Parse Cb component
    if offset + 2 > len(data):
        raise ValueError("Truncated tile data: missing Cb length")
    cb_len = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    if offset + cb_len > len(data):
        raise ValueError("Truncated tile data: Cb component")
    cb_data = data[offset:offset + cb_len]
    offset += cb_len

    # Parse Cr component
    if offset + 2 > len(data):
        raise ValueError("Truncated tile data: missing Cr length")
    cr_len = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    if offset + cr_len > len(data):
        raise ValueError("Truncated tile data: Cr component")
    cr_data = data[offset:offset + cr_len]

    # Step 1: RLGR entropy decode
    y_coeffs = _rlgr_decode(y_data, mode, num_coeffs)
    cb_coeffs = _rlgr_decode(cb_data, mode, num_coeffs)
    cr_coeffs = _rlgr_decode(cr_data, mode, num_coeffs)

    # Step 2: Dequantize
    y_subbands = _dequantize_tile(y_coeffs, quant_vals)
    cb_subbands = _dequantize_tile(cb_coeffs, quant_vals)
    cr_subbands = _dequantize_tile(cr_coeffs, quant_vals)

    # Step 3: Inverse DWT
    y_grid = _inverse_dwt_2d(y_subbands)
    cb_grid = _inverse_dwt_2d(cb_subbands)
    cr_grid = _inverse_dwt_2d(cr_subbands)

    # Step 4: YCbCr to RGB
    return _ycbcr_to_rgb(y_grid, cb_grid, cr_grid)


def decode_message(data: bytes) -> list[tuple[Rect, bytes]]:
    """Decode a RemoteFX message containing one or more tiles.

    Parses the RFX message structure per [MS-RDPRFX] and decodes each tile.

    Args:
        data: Raw RemoteFX message data.

    Returns:
        List of (Rect, pixel_data) tuples, one per tile.
    """
    results: list[tuple[Rect, bytes]] = []
    offset = 0

    if len(data) < 12:
        raise ValueError("RemoteFX message too short")

    # Parse message header
    # Block type (2 bytes) + block length (4 bytes)
    block_type = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    block_len = struct.unpack_from("<I", data, offset)[0]
    offset += 4

    # Number of tiles (2 bytes)
    if offset + 2 > len(data):
        raise ValueError("Truncated RemoteFX message: missing tile count")
    num_tiles = struct.unpack_from("<H", data, offset)[0]
    offset += 2

    # Quantization values count (1 byte)
    if offset + 1 > len(data):
        raise ValueError("Truncated RemoteFX message: missing quant count")
    num_quants = data[offset]
    offset += 1

    # RLGR mode (1 byte): 1 = RLGR1, 3 = RLGR3
    if offset + 1 > len(data):
        raise ValueError("Truncated RemoteFX message: missing mode")
    rlgr_mode = data[offset]
    offset += 1

    # Parse quantization tables (5 bytes each, packed as nibbles)
    quant_tables: list[QuantValues] = []
    for _ in range(num_quants):
        if offset + 5 > len(data):
            raise ValueError("Truncated RemoteFX message: quant table")
        # 5 bytes = 10 nibbles for 10 subband quant values
        # Each byte contains two 4-bit values
        raw = data[offset:offset + 5]
        vals = []
        for b in raw:
            vals.append(b & 0x0F)
            vals.append((b >> 4) & 0x0F)
        quant_tables.append(QuantValues(
            hl1=vals[0], lh1=vals[1], hh1=vals[2],
            hl2=vals[3], lh2=vals[4], hh2=vals[5],
            hl3=vals[6], lh3=vals[7], hh3=vals[8],
            ll3=vals[9],
        ))
        offset += 5

    # Parse tiles
    for _ in range(num_tiles):
        if offset + 6 > len(data):
            raise ValueError("Truncated RemoteFX message: tile header")

        # Tile header: quant_idx (1 byte), x (2 bytes), y (2 bytes), tile_data_len (2 bytes)
        quant_idx = data[offset]
        offset += 1
        tile_x = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        tile_y = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        tile_data_len = struct.unpack_from("<H", data, offset)[0]
        offset += 2

        if offset + tile_data_len > len(data):
            raise ValueError("Truncated RemoteFX message: tile data")

        tile_data = data[offset:offset + tile_data_len]
        offset += tile_data_len

        quant = quant_tables[quant_idx] if quant_idx < len(quant_tables) else quant_tables[0]
        pixels = decode_tile(tile_data, quant, rlgr_mode)
        rect = Rect(x=tile_x, y=tile_y, w=TILE_SIZE, h=TILE_SIZE)
        results.append((rect, pixels))

    return results


class RemoteFxCodec:
    """RemoteFX codec for decoding RFX-encoded bitmap data.

    Implements the full decoding pipeline per [MS-RDPRFX]:
    - RLGR1/RLGR3 entropy decoding
    - Per-subband dequantization
    - 3-level inverse DWT (5/3 Le Gall wavelet)
    - YCbCr to RGB color space conversion
    """

    @staticmethod
    def decode_tile(data: bytes, quant_vals: QuantValues, mode: int = 1) -> bytes:
        """Decode a single 64x64 RemoteFX tile.

        Args:
            data: Encoded tile data with Y/Cb/Cr component streams.
            quant_vals: Per-subband quantization values.
            mode: RLGR mode (1 or 3).

        Returns:
            RGBA pixel data (16384 bytes).
        """
        return decode_tile(data, quant_vals, mode)

    @staticmethod
    def decode_message(data: bytes) -> list[tuple[Rect, bytes]]:
        """Decode a RemoteFX message with multiple tiles.

        Args:
            data: Raw RemoteFX message data.

        Returns:
            List of (Rect, RGBA pixels) tuples.
        """
        return decode_message(data)
