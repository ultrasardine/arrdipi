"""MPPC-based bulk data compression and decompression.

Implements the MPPC compression algorithm (RFC 2118 variant) as used by
RDP 5.0 with a 64KB sliding window history buffer per [MS-RDPBCGR] Section 3.1.8.

The compressor maintains a stateful sliding window that both sides share.
Compression uses LZ77-style matching with offset/length pairs encoded as
variable-length bit sequences.
"""

from __future__ import annotations

import struct

from arrdipi.errors import DecompressionError

# Compression flags as defined in [MS-RDPBCGR] 3.1.8.2.1
PACKET_COMPRESSED = 0x20
PACKET_AT_FRONT = 0x40
PACKET_FLUSHED = 0x80
PACKET_COMPR_TYPE_MASK = 0x0F
PACKET_COMPR_TYPE_RDP5 = 0x01  # RDP 5.0 64K history

# History buffer size for RDP 5.0
HISTORY_SIZE = 65536  # 64KB


class _BitWriter:
    """Writes individual bits to a byte buffer (MSB first)."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._current_byte = 0
        self._bit_count = 0

    def write_bits(self, value: int, num_bits: int) -> None:
        """Write `num_bits` bits from `value` (MSB first)."""
        for i in range(num_bits - 1, -1, -1):
            bit = (value >> i) & 1
            self._current_byte = (self._current_byte << 1) | bit
            self._bit_count += 1
            if self._bit_count == 8:
                self._buffer.append(self._current_byte)
                self._current_byte = 0
                self._bit_count = 0

    def flush(self) -> bytes:
        """Flush remaining bits (pad with zeros) and return the buffer."""
        if self._bit_count > 0:
            self._current_byte <<= (8 - self._bit_count)
            self._buffer.append(self._current_byte)
            self._current_byte = 0
            self._bit_count = 0
        return bytes(self._buffer)


class _BitReader:
    """Reads individual bits from a byte buffer (MSB first)."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._byte_index = 0
        self._bit_index = 7  # Start at MSB

    def read_bit(self) -> int:
        """Read a single bit. Raises DecompressionError if exhausted."""
        if self._byte_index >= len(self._data):
            raise DecompressionError("Unexpected end of compressed data")
        bit = (self._data[self._byte_index] >> self._bit_index) & 1
        self._bit_index -= 1
        if self._bit_index < 0:
            self._bit_index = 7
            self._byte_index += 1
        return bit

    def read_bits(self, num_bits: int) -> int:
        """Read `num_bits` bits and return as an integer (MSB first)."""
        value = 0
        for _ in range(num_bits):
            value = (value << 1) | self.read_bit()
        return value

    @property
    def bits_remaining(self) -> int:
        """Return the number of bits remaining to read."""
        remaining_bytes = len(self._data) - self._byte_index
        if remaining_bytes <= 0:
            return 0
        return (remaining_bytes - 1) * 8 + self._bit_index + 1


class MppcCompressor:
    """MPPC-based bulk data compressor/decompressor (RFC 2118 variant).

    Uses a 64KB sliding window history buffer as specified for RDP 5.0
    in [MS-RDPBCGR] Section 3.1.8.

    Each direction of communication maintains its own MppcCompressor instance.
    The history buffer is shared state between compressor and decompressor
    on the same side.
    """

    def __init__(self) -> None:
        self._history: bytearray = bytearray(HISTORY_SIZE)
        self._history_offset: int = 0

    def compress(self, data: bytes) -> tuple[bytes, int]:
        """Compress data using MPPC with the sliding window history.

        Args:
            data: The uncompressed data to compress.

        Returns:
            A tuple of (compressed_data, flags) where flags indicate
            the compression state (PACKET_COMPRESSED, PACKET_AT_FRONT, etc.).
        """
        if not data:
            return b"", 0

        flags = PACKET_COMPR_TYPE_RDP5

        # Check if we need to wrap around the history buffer
        if self._history_offset + len(data) > HISTORY_SIZE:
            # Reset to front of buffer
            self._history = bytearray(HISTORY_SIZE)
            self._history_offset = 0
            flags |= PACKET_FLUSHED

        writer = _BitWriter()
        src_offset = 0
        history_start = self._history_offset

        # Copy all data into history first so we can reference it during search
        self._history[history_start:history_start + len(data)] = data

        while src_offset < len(data):
            # Current position in the history buffer
            cur_pos = history_start + src_offset

            # Try to find a match in the history (before current position)
            best_offset = 0
            best_length = 0

            # Maximum match length is limited by remaining data
            max_match = min(len(data) - src_offset, 4095)

            # Search window: from the earliest available position to just before current
            search_start = max(0, cur_pos - HISTORY_SIZE + 1)

            # Only search if there's history before current position
            # (either from previous calls or earlier in this data)
            if cur_pos > 0:
                # Search backwards from current position for best match
                # Limit search to avoid excessive CPU usage
                search_begin = max(search_start, cur_pos - min(cur_pos, 8192))

                for search_pos in range(cur_pos - 1, search_begin - 1, -1):
                    length = 0
                    while length < max_match:
                        # For overlapping matches (search_pos + length >= cur_pos),
                        # the byte is the same as what was already copied
                        # (run-length encoding behavior)
                        if self._history[search_pos + length] != data[src_offset + length]:
                            break
                        length += 1

                    if length > best_length and length >= 3:
                        best_length = length
                        best_offset = cur_pos - search_pos
                        # Early exit for good enough matches
                        if best_length >= 64:
                            break

            if best_length >= 3:
                # Encode offset/length pair
                self._encode_match(writer, best_offset, best_length)
                src_offset += best_length
            else:
                # Encode literal byte
                self._encode_literal(writer, data[src_offset])
                src_offset += 1

        compressed = writer.flush()
        self._history_offset += len(data)

        # Only use compression if it actually saves space
        if len(compressed) < len(data):
            flags |= PACKET_COMPRESSED
            if history_start == 0 and not (flags & PACKET_FLUSHED):
                flags |= PACKET_AT_FRONT
            return compressed, flags
        else:
            # Compression didn't help, send uncompressed
            return data, flags & ~PACKET_COMPRESSED

    def decompress(self, data: bytes, flags: int) -> bytes:
        """Decompress data using the sliding window history.

        Args:
            data: The compressed (or uncompressed) data.
            flags: Compression flags from the PDU header.

        Returns:
            The decompressed data.

        Raises:
            DecompressionError: If the compressed data is corrupted.
        """
        try:
            return self._decompress_inner(data, flags)
        except DecompressionError:
            self.reset()
            raise
        except (IndexError, ValueError, struct.error) as e:
            self.reset()
            raise DecompressionError(f"Corrupted compressed data: {e}") from e

    def _decompress_inner(self, data: bytes, flags: int) -> bytes:
        """Internal decompression logic."""
        if flags & PACKET_FLUSHED:
            # Server signals history reset
            self._history = bytearray(HISTORY_SIZE)
            self._history_offset = 0

        if not (flags & PACKET_COMPRESSED):
            # Data is not compressed, just copy to history
            if self._history_offset + len(data) > HISTORY_SIZE:
                raise DecompressionError(
                    "Uncompressed data exceeds history buffer capacity"
                )
            self._history[self._history_offset:self._history_offset + len(data)] = data
            self._history_offset += len(data)
            return data

        if flags & PACKET_AT_FRONT:
            self._history_offset = 0

        # Decompress the data
        reader = _BitReader(data)
        output = bytearray()

        while reader.bits_remaining > 0:
            # Try to decode - if we can't get a full token, we're done
            try:
                bit = reader.read_bit()
            except DecompressionError:
                break

            if bit == 0:
                # Literal byte: 0 + 8 bits
                if reader.bits_remaining < 8:
                    break
                byte = reader.read_bits(8)
                if self._history_offset >= HISTORY_SIZE:
                    raise DecompressionError("History buffer overflow during decompression")
                self._history[self._history_offset] = byte
                self._history_offset += 1
                output.append(byte)
            else:
                # Match: decode offset and length
                # If we can't read a complete match token, we've hit
                # the padding bits at the end of the stream.
                try:
                    offset = self._decode_offset(reader)
                    length = self._decode_length(reader)
                except DecompressionError as e:
                    if "Unexpected end" in str(e):
                        # Ran out of bits — this is just padding at end of stream
                        break
                    raise

                if offset == 0:
                    raise DecompressionError("Invalid zero offset in compressed data")

                # Copy from history
                src_pos = self._history_offset - offset
                if src_pos < 0:
                    raise DecompressionError(
                        f"Offset {offset} exceeds available history "
                        f"(current position: {self._history_offset})"
                    )

                for _ in range(length):
                    if self._history_offset >= HISTORY_SIZE:
                        raise DecompressionError(
                            "History buffer overflow during decompression"
                        )
                    byte = self._history[src_pos]
                    self._history[self._history_offset] = byte
                    self._history_offset += 1
                    output.append(byte)
                    src_pos += 1

        return bytes(output)

    def reset(self) -> None:
        """Reset the history buffer to allow recovery from corruption.

        This clears the entire sliding window and resets the write position
        to the beginning of the buffer.
        """
        self._history = bytearray(HISTORY_SIZE)
        self._history_offset = 0

    def _encode_literal(self, writer: _BitWriter, byte: int) -> None:
        """Encode a literal byte: 0 prefix + 8-bit value."""
        writer.write_bits(0, 1)
        writer.write_bits(byte, 8)

    def _encode_match(self, writer: _BitWriter, offset: int, length: int) -> None:
        """Encode an offset/length match pair.

        The match indicator (1 bit = 1) is written first, then the offset
        and length are encoded.

        Copy-offset encoding for RDP 5.0 (64KB window) per [MS-RDPBCGR] 3.1.8.4.2:
        After the match indicator bit (1):
          11 + 6 bits:    offset 0-63
          10 + 8 bits:    offset 64-319
          0 + 13 bits:    offset 320-8191
          (offsets > 8191 use 0 + 13 bits with value - 320, max 8191+320=8511)

        For the full 64K range we extend:
          0 + 16 bits:    offset 320-65535

        Actually per the spec, for TYPE_64K:
          11 + 6 bits:    offset 0-63
          10 + 8 bits:    offset 64-319
          0 + 16 bits:    offset 320-65535

        Length encoding:
          0:                length = 3
          10 + 2 bits:      length 4-7
          110 + 3 bits:     length 8-15
          1110 + 4 bits:    length 16-31
          11110 + 5 bits:   length 32-63
          111110 + 6 bits:  length 64-127
          1111110 + 7 bits: length 128-255
          11111110 + 8 bits: length 256-511
          111111110 + 9 bits: length 512-1023
          1111111110 + 10 bits: length 1024-2047
          11111111110 + 11 bits: length 2048-4095
        """
        # Match indicator bit
        writer.write_bits(1, 1)

        # Encode offset
        if offset <= 63:
            writer.write_bits(0b11, 2)
            writer.write_bits(offset, 6)
        elif offset <= 319:
            writer.write_bits(0b10, 2)
            writer.write_bits(offset - 64, 8)
        else:
            writer.write_bits(0, 1)
            writer.write_bits(offset - 320, 16)

        # Encode length
        self._encode_length(writer, length)

    def _encode_length(self, writer: _BitWriter, length: int) -> None:
        """Encode match length using variable-length prefix codes.

        The encoding uses a unary prefix of 1s terminated by a 0,
        followed by value bits. The last category (2048-4095) uses
        10 ones as prefix (no terminating 0 needed since it's the
        maximum category).
        """
        if length == 3:
            writer.write_bits(0, 1)
        elif length <= 7:
            writer.write_bits(0b10, 2)
            writer.write_bits(length - 4, 2)
        elif length <= 15:
            writer.write_bits(0b110, 3)
            writer.write_bits(length - 8, 3)
        elif length <= 31:
            writer.write_bits(0b1110, 4)
            writer.write_bits(length - 16, 4)
        elif length <= 63:
            writer.write_bits(0b11110, 5)
            writer.write_bits(length - 32, 5)
        elif length <= 127:
            writer.write_bits(0b111110, 6)
            writer.write_bits(length - 64, 6)
        elif length <= 255:
            writer.write_bits(0b1111110, 7)
            writer.write_bits(length - 128, 7)
        elif length <= 511:
            writer.write_bits(0b11111110, 8)
            writer.write_bits(length - 256, 8)
        elif length <= 1023:
            writer.write_bits(0b111111110, 9)
            writer.write_bits(length - 512, 9)
        elif length <= 2047:
            writer.write_bits(0b1111111110, 10)
            writer.write_bits(length - 1024, 10)
        else:
            # Last category: 10 ones (no terminating 0)
            writer.write_bits(0b1111111111, 10)
            writer.write_bits(length - 2048, 11)

    def _decode_offset(self, reader: _BitReader) -> int:
        """Decode an offset value from the bit stream.

        The match indicator bit (1) has already been consumed by the caller.
        Copy-offset encoding for RDP 5.0 (64KB):
          11 + 6 bits:   offset 0-63
          10 + 8 bits:   offset 64-319
          0 + 16 bits:   offset 320-65535
        """
        bit1 = reader.read_bit()
        if bit1 == 0:
            # 0 + 16 bits -> offset 320-65535
            return reader.read_bits(16) + 320
        # bit1 == 1
        bit2 = reader.read_bit()
        if bit2 == 1:
            # 11 + 6 bits -> offset 0-63
            return reader.read_bits(6)
        else:
            # 10 + 8 bits -> offset 64-319
            return reader.read_bits(8) + 64

    def _decode_length(self, reader: _BitReader) -> int:
        """Decode a match length from the bit stream.

        Length encoding:
          0:                length = 3
          10 + 2 bits:      length = value + 4 (4-7)
          110 + 3 bits:     length = value + 8 (8-15)
          1110 + 4 bits:    length = value + 16 (16-31)
          11110 + 5 bits:   length = value + 32 (32-63)
          111110 + 6 bits:  length = value + 64 (64-127)
          1111110 + 7 bits: length = value + 128 (128-255)
          11111110 + 8 bits: length = value + 256 (256-511)
          111111110 + 9 bits: length = value + 512 (512-1023)
          1111111110 + 10 bits: length = value + 1024 (1024-2047)
          11111111110 + 11 bits: length = value + 2048 (2048-4095)
        """
        bit = reader.read_bit()
        if bit == 0:
            return 3

        bit = reader.read_bit()
        if bit == 0:
            return reader.read_bits(2) + 4

        bit = reader.read_bit()
        if bit == 0:
            return reader.read_bits(3) + 8

        bit = reader.read_bit()
        if bit == 0:
            return reader.read_bits(4) + 16

        bit = reader.read_bit()
        if bit == 0:
            return reader.read_bits(5) + 32

        bit = reader.read_bit()
        if bit == 0:
            return reader.read_bits(6) + 64

        bit = reader.read_bit()
        if bit == 0:
            return reader.read_bits(7) + 128

        bit = reader.read_bit()
        if bit == 0:
            return reader.read_bits(8) + 256

        bit = reader.read_bit()
        if bit == 0:
            return reader.read_bits(9) + 512

        bit = reader.read_bit()
        if bit == 0:
            return reader.read_bits(10) + 1024

        # 11111111110 + 11 bits
        return reader.read_bits(11) + 2048
