"""Tests for the H.264 decoder wrapper."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def mock_av_module(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Mock the av module before importing h264 codec.

    This ensures tests don't require actual FFmpeg installation.
    """
    mock_av = MagicMock()
    mock_av.error.InvalidDataError = type("InvalidDataError", (Exception,), {})
    mock_av.error.EOFError = type("EOFError", (Exception,), {})
    monkeypatch.setitem(sys.modules, "av", mock_av)
    # Clear cached import of h264 module so it re-imports with mock
    if "arrdipi.codec.h264" in sys.modules:
        del sys.modules["arrdipi.codec.h264"]
    return mock_av


class TestH264CodecInit:
    """Tests for H264Codec initialization."""

    def test_creates_codec_context(self, mock_av_module: MagicMock) -> None:
        """Initialization creates an H.264 codec context in read mode."""
        from arrdipi.codec.h264 import H264Codec

        mock_ctx = MagicMock()
        mock_av_module.CodecContext.create.return_value = mock_ctx

        H264Codec()

        mock_av_module.CodecContext.create.assert_called_once_with("h264", "r")
        mock_ctx.open.assert_called_once()

    def test_codec_context_stored(self, mock_av_module: MagicMock) -> None:
        """The codec context is stored for reuse across decode calls."""
        from arrdipi.codec.h264 import H264Codec

        mock_ctx = MagicMock()
        mock_av_module.CodecContext.create.return_value = mock_ctx

        codec = H264Codec()

        assert codec._codec_context is mock_ctx


class TestH264DecodeFrame:
    """Tests for H264Codec.decode_frame."""

    def test_decode_frame_returns_rgba_pixels(self, mock_av_module: MagicMock) -> None:
        """decode_frame returns RGBA pixel data from a decoded frame."""
        from arrdipi.codec.h264 import H264Codec

        mock_ctx = MagicMock()
        mock_av_module.CodecContext.create.return_value = mock_ctx

        # Setup mock frame with RGBA data
        expected_pixels = bytes([255, 0, 0, 255] * 4)  # 4 red pixels
        mock_rgba_frame = MagicMock()
        mock_rgba_frame.planes = [expected_pixels]

        mock_frame = MagicMock()
        mock_frame.reformat.return_value = mock_rgba_frame

        # decode returns an iterable of frames
        mock_ctx.decode.return_value = [mock_frame]

        codec = H264Codec()
        result = codec.decode_frame(b"\x00\x00\x00\x01\x67")

        assert result == expected_pixels
        mock_frame.reformat.assert_called_once_with(format="rgba")

    def test_decode_frame_creates_packet(self, mock_av_module: MagicMock) -> None:
        """decode_frame wraps input data in an av.Packet."""
        from arrdipi.codec.h264 import H264Codec

        mock_ctx = MagicMock()
        mock_av_module.CodecContext.create.return_value = mock_ctx
        mock_ctx.decode.return_value = []

        codec = H264Codec()
        nal_data = b"\x00\x00\x00\x01\x65"
        codec.decode_frame(nal_data)

        mock_av_module.Packet.assert_called_once_with(nal_data)

    def test_decode_frame_no_frames_returns_empty(self, mock_av_module: MagicMock) -> None:
        """decode_frame returns empty bytes when no frames are produced."""
        from arrdipi.codec.h264 import H264Codec

        mock_ctx = MagicMock()
        mock_av_module.CodecContext.create.return_value = mock_ctx
        mock_ctx.decode.return_value = []  # No frames decoded

        codec = H264Codec()
        result = codec.decode_frame(b"\x00\x00\x00\x01\x67")

        assert result == b""

    def test_decode_frame_invalid_data_returns_empty(self, mock_av_module: MagicMock) -> None:
        """decode_frame returns empty bytes on InvalidDataError."""
        from arrdipi.codec.h264 import H264Codec

        mock_ctx = MagicMock()
        mock_av_module.CodecContext.create.return_value = mock_ctx

        # Simulate InvalidDataError
        mock_ctx.decode.side_effect = mock_av_module.error.InvalidDataError("corrupted")

        codec = H264Codec()
        result = codec.decode_frame(b"\xff\xff\xff")

        assert result == b""

    def test_decode_frame_eof_error_returns_empty(self, mock_av_module: MagicMock) -> None:
        """decode_frame returns empty bytes on EOFError."""
        from arrdipi.codec.h264 import H264Codec

        mock_ctx = MagicMock()
        mock_av_module.CodecContext.create.return_value = mock_ctx

        # Simulate EOFError
        mock_ctx.decode.side_effect = mock_av_module.error.EOFError("eof")

        codec = H264Codec()
        result = codec.decode_frame(b"\x00")

        assert result == b""

    def test_decode_frame_generic_error_returns_empty(self, mock_av_module: MagicMock) -> None:
        """decode_frame returns empty bytes on any unexpected exception."""
        from arrdipi.codec.h264 import H264Codec

        mock_ctx = MagicMock()
        mock_av_module.CodecContext.create.return_value = mock_ctx

        # Simulate generic error
        mock_ctx.decode.side_effect = RuntimeError("unexpected error")

        codec = H264Codec()
        result = codec.decode_frame(b"\x00\x01\x02")

        assert result == b""

    def test_decode_frame_logs_warning_on_error(
        self, mock_av_module: MagicMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        """decode_frame logs a warning when decoding fails."""
        import logging

        from arrdipi.codec.h264 import H264Codec

        mock_ctx = MagicMock()
        mock_av_module.CodecContext.create.return_value = mock_ctx
        mock_ctx.decode.side_effect = RuntimeError("bad frame")

        codec = H264Codec()

        with caplog.at_level(logging.WARNING, logger="arrdipi.codec.h264"):
            result = codec.decode_frame(b"\xff")

        assert result == b""
        assert "H.264 decode error" in caplog.text

    def test_decode_frame_returns_first_frame_only(self, mock_av_module: MagicMock) -> None:
        """decode_frame returns pixels from the first decoded frame only."""
        from arrdipi.codec.h264 import H264Codec

        mock_ctx = MagicMock()
        mock_av_module.CodecContext.create.return_value = mock_ctx

        # Two frames decoded - should return only the first
        first_pixels = bytes([1, 2, 3, 4])
        second_pixels = bytes([5, 6, 7, 8])

        mock_rgba_frame1 = MagicMock()
        mock_rgba_frame1.planes = [first_pixels]
        mock_frame1 = MagicMock()
        mock_frame1.reformat.return_value = mock_rgba_frame1

        mock_rgba_frame2 = MagicMock()
        mock_rgba_frame2.planes = [second_pixels]
        mock_frame2 = MagicMock()
        mock_frame2.reformat.return_value = mock_rgba_frame2

        mock_ctx.decode.return_value = [mock_frame1, mock_frame2]

        codec = H264Codec()
        result = codec.decode_frame(b"\x00\x00\x00\x01")

        assert result == first_pixels
