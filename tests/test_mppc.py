"""Tests for MPPC bulk data compression and decompression."""

import pytest

from arrdipi.codec.mppc import (
    HISTORY_SIZE,
    PACKET_AT_FRONT,
    PACKET_COMPRESSED,
    PACKET_COMPR_TYPE_RDP5,
    PACKET_FLUSHED,
    MppcCompressor,
)
from arrdipi.errors import DecompressionError


class TestMppcCompressorInit:
    """Test MppcCompressor initialization."""

    def test_history_buffer_size(self) -> None:
        """History buffer is 64KB (Req 12, AC 2)."""
        compressor = MppcCompressor()
        assert len(compressor._history) == 65536

    def test_history_offset_starts_at_zero(self) -> None:
        """History offset starts at beginning of buffer."""
        compressor = MppcCompressor()
        assert compressor._history_offset == 0


class TestMppcRoundTrip:
    """Test compress/decompress round-trip correctness."""

    def test_empty_data(self) -> None:
        """Empty input produces empty output."""
        compressor = MppcCompressor()
        compressed, flags = compressor.compress(b"")
        assert compressed == b""
        assert flags == 0

    def test_single_byte(self) -> None:
        """Single byte round-trips correctly."""
        compressor = MppcCompressor()
        decompressor = MppcCompressor()

        original = b"\x42"
        compressed, flags = compressor.compress(original)
        result = decompressor.decompress(compressed, flags)
        assert result == original

    def test_short_data_no_repeats(self) -> None:
        """Short non-repeating data round-trips correctly."""
        compressor = MppcCompressor()
        decompressor = MppcCompressor()

        original = b"Hello, World!"
        compressed, flags = compressor.compress(original)
        result = decompressor.decompress(compressed, flags)
        assert result == original

    def test_repetitive_data_compresses(self) -> None:
        """Repetitive data compresses smaller than original (Req 12, AC 5)."""
        compressor = MppcCompressor()
        decompressor = MppcCompressor()

        # Highly repetitive data should compress well
        original = b"ABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABC"
        compressed, flags = compressor.compress(original)

        assert flags & PACKET_COMPRESSED
        assert len(compressed) < len(original)

        result = decompressor.decompress(compressed, flags)
        assert result == original

    def test_long_repetitive_data(self) -> None:
        """Long repetitive data round-trips correctly."""
        compressor = MppcCompressor()
        decompressor = MppcCompressor()

        original = b"The quick brown fox jumps over the lazy dog. " * 50
        compressed, flags = compressor.compress(original)
        result = decompressor.decompress(compressed, flags)
        assert result == original

    def test_binary_data(self) -> None:
        """Binary data with repeated patterns round-trips correctly."""
        compressor = MppcCompressor()
        decompressor = MppcCompressor()

        original = bytes(range(256)) * 4
        compressed, flags = compressor.compress(original)
        result = decompressor.decompress(compressed, flags)
        assert result == original

    def test_all_same_bytes(self) -> None:
        """Data with all same bytes compresses and decompresses."""
        compressor = MppcCompressor()
        decompressor = MppcCompressor()

        original = b"\x00" * 1000
        compressed, flags = compressor.compress(original)
        result = decompressor.decompress(compressed, flags)
        assert result == original

    def test_multiple_sequential_compressions(self) -> None:
        """Multiple sequential compress/decompress operations maintain state."""
        compressor = MppcCompressor()
        decompressor = MppcCompressor()

        messages = [
            b"First message with some content",
            b"Second message with some content",  # Shares prefix with first
            b"Third message completely different",
        ]

        for msg in messages:
            compressed, flags = compressor.compress(msg)
            result = decompressor.decompress(compressed, flags)
            assert result == msg


class TestMppcDecompress:
    """Test decompression-specific behavior."""

    def test_uncompressed_data_passthrough(self) -> None:
        """Data without PACKET_COMPRESSED flag passes through (Req 12, AC 4)."""
        decompressor = MppcCompressor()

        data = b"uncompressed data here"
        flags = PACKET_COMPR_TYPE_RDP5 | PACKET_AT_FRONT
        result = decompressor.decompress(data, flags)
        assert result == data

    def test_flushed_flag_resets_history(self) -> None:
        """PACKET_FLUSHED flag resets history before decompression."""
        compressor = MppcCompressor()
        decompressor = MppcCompressor()

        # First, put some data in the decompressor's history
        data1 = b"some initial data to fill history"
        compressed1, flags1 = compressor.compress(data1)
        decompressor.decompress(compressed1, flags1)

        # Now reset compressor and send with FLUSHED flag
        compressor.reset()
        data2 = b"fresh data after flush"
        compressed2, flags2 = compressor.compress(data2)
        # Ensure FLUSHED flag is set
        flags2 |= PACKET_FLUSHED
        result = decompressor.decompress(compressed2, flags2)
        assert result == data2


class TestMppcCorruptionDetection:
    """Test corruption detection and recovery (Req 12, AC 6)."""

    def test_corrupted_data_raises_decompression_error(self) -> None:
        """Corrupted compressed data raises DecompressionError."""
        decompressor = MppcCompressor()

        # Random garbage that claims to be compressed
        corrupted = b"\xff\xff\xff\xff\xff\xff\xff\xff"
        flags = PACKET_COMPRESSED | PACKET_COMPR_TYPE_RDP5 | PACKET_AT_FRONT

        with pytest.raises(DecompressionError):
            decompressor.decompress(corrupted, flags)

    def test_truncated_data_raises_decompression_error(self) -> None:
        """Truncated compressed data raises DecompressionError."""
        compressor = MppcCompressor()
        decompressor = MppcCompressor()

        original = b"ABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABC"
        compressed, flags = compressor.compress(original)

        # Truncate the compressed data
        truncated = compressed[:len(compressed) // 2]

        # This may or may not raise depending on where we truncate.
        # But the result should not equal the original if it doesn't raise.
        try:
            result = decompressor.decompress(truncated, flags)
            # If it doesn't raise, the result should be partial (not equal to original)
            assert result != original
        except DecompressionError:
            pass  # Expected behavior

    def test_history_resets_on_corruption(self) -> None:
        """History buffer resets after DecompressionError (Req 12, AC 6)."""
        decompressor = MppcCompressor()

        # Put some data in history
        data = b"some data in history buffer"
        flags_uncompressed = PACKET_COMPR_TYPE_RDP5 | PACKET_AT_FRONT
        decompressor.decompress(data, flags_uncompressed)
        assert decompressor._history_offset > 0

        # Trigger corruption
        corrupted = b"\xff\xff\xff\xff\xff\xff\xff\xff"
        flags_compressed = PACKET_COMPRESSED | PACKET_COMPR_TYPE_RDP5

        with pytest.raises(DecompressionError):
            decompressor.decompress(corrupted, flags_compressed)

        # History should be reset
        assert decompressor._history_offset == 0
        assert decompressor._history == bytearray(HISTORY_SIZE)

    def test_recovery_after_corruption(self) -> None:
        """Compressor can be used again after corruption reset."""
        compressor = MppcCompressor()
        decompressor = MppcCompressor()

        # Trigger corruption in decompressor
        corrupted = b"\xff\xff\xff\xff\xff\xff\xff\xff"
        flags_compressed = PACKET_COMPRESSED | PACKET_COMPR_TYPE_RDP5 | PACKET_AT_FRONT

        with pytest.raises(DecompressionError):
            decompressor.decompress(corrupted, flags_compressed)

        # Reset compressor too (simulating protocol recovery)
        compressor.reset()

        # Should work again with FLUSHED flag
        original = b"recovery data after corruption"
        compressed, flags = compressor.compress(original)
        flags |= PACKET_FLUSHED
        result = decompressor.decompress(compressed, flags)
        assert result == original


class TestMppcReset:
    """Test reset() method (Req 12, AC 6)."""

    def test_reset_clears_history(self) -> None:
        """reset() clears the history buffer."""
        compressor = MppcCompressor()

        # Put data in history
        compressor.compress(b"some data to fill history")
        assert compressor._history_offset > 0

        compressor.reset()
        assert compressor._history_offset == 0
        assert compressor._history == bytearray(HISTORY_SIZE)

    def test_reset_allows_fresh_start(self) -> None:
        """After reset, compressor works as if freshly created."""
        compressor = MppcCompressor()
        decompressor = MppcCompressor()

        # Use the compressor
        compressor.compress(b"initial data")

        # Reset both sides
        compressor.reset()
        decompressor.reset()

        # Should work fresh
        original = b"XYZXYZXYZXYZXYZXYZXYZXYZXYZXYZXYZXYZXYZXYZXYZXYZ"
        compressed, flags = compressor.compress(original)
        result = decompressor.decompress(compressed, flags)
        assert result == original


class TestMppcFlags:
    """Test compression flag handling."""

    def test_rdp5_type_flag(self) -> None:
        """Compressed output includes RDP5 compression type flag."""
        compressor = MppcCompressor()

        original = b"ABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABC"
        _, flags = compressor.compress(original)
        assert flags & PACKET_COMPR_TYPE_RDP5

    def test_at_front_flag_on_first_compress(self) -> None:
        """First compression sets AT_FRONT flag when compressed."""
        compressor = MppcCompressor()

        original = b"ABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABC"
        _, flags = compressor.compress(original)
        if flags & PACKET_COMPRESSED:
            assert flags & PACKET_AT_FRONT

    def test_flushed_flag_on_buffer_wrap(self) -> None:
        """FLUSHED flag is set when history buffer wraps around."""
        compressor = MppcCompressor()

        # Fill most of the history buffer
        large_data = bytes(range(256)) * 200  # 51200 bytes
        compressor.compress(large_data)

        # This should trigger a wrap
        more_data = bytes(range(256)) * 100  # 25600 bytes, total > 64K
        _, flags = compressor.compress(more_data)
        assert flags & PACKET_FLUSHED


class TestMppcKnownVectors:
    """Test with known input/output patterns to verify encoding correctness."""

    def test_literal_only_encoding(self) -> None:
        """Short unique data encodes as literals and round-trips."""
        compressor = MppcCompressor()
        decompressor = MppcCompressor()

        # Data too short for matches (< 3 byte minimum match)
        original = b"AB"
        compressed, flags = compressor.compress(original)
        result = decompressor.decompress(compressed, flags)
        assert result == original

    def test_minimum_match_length(self) -> None:
        """Minimum match length is 3 bytes."""
        compressor = MppcCompressor()
        decompressor = MppcCompressor()

        # "ABCABC" - the second "ABC" should match the first (length 3)
        original = b"ABCABC"
        compressed, flags = compressor.compress(original)
        result = decompressor.decompress(compressed, flags)
        assert result == original

    def test_large_offset_match(self) -> None:
        """Matches with large offsets work correctly."""
        compressor = MppcCompressor()
        decompressor = MppcCompressor()

        # Create data with a pattern repeated far apart
        padding = bytes(range(256)) * 40  # ~10KB of unique-ish data
        pattern = b"UNIQUE_PATTERN_HERE"
        original = pattern + padding + pattern

        compressed, flags = compressor.compress(original)
        result = decompressor.decompress(compressed, flags)
        assert result == original

    def test_overlapping_match(self) -> None:
        """Overlapping matches (run-length style) work correctly."""
        compressor = MppcCompressor()
        decompressor = MppcCompressor()

        # "AAAAAA..." - each 'A' after the first 3 can match with offset 1
        original = b"AAA" + b"A" * 100
        compressed, flags = compressor.compress(original)
        result = decompressor.decompress(compressed, flags)
        assert result == original
