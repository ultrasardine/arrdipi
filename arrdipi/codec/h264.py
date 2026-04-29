"""H.264 decoder wrapper using PyAV (av) for NAL unit decoding.

Wraps av.CodecContext to decode H.264 NAL units into RGBA pixel data
for rendering on the graphics surface. Used by the RDPGFX pipeline
for H.264/AVC 444 encoded frames.

Reference: [MS-RDPEGFX] Remote Desktop Protocol: Graphics Pipeline Extension.
"""

from __future__ import annotations

import logging

import av

logger = logging.getLogger(__name__)


class H264Codec:
    """H.264 decoder wrapping PyAV's codec context.

    Provides a simple interface to decode raw H.264 NAL unit data
    into RGBA pixel bytes suitable for surface rendering.

    Usage:
        codec = H264Codec()
        rgba_pixels = codec.decode_frame(nal_unit_data)
    """

    def __init__(self) -> None:
        """Initialize the H.264 decoder context.

        Creates an av.CodecContext configured for H.264 decoding.
        """
        self._codec_context = av.CodecContext.create("h264", "r")
        self._codec_context.open()

    def decode_frame(self, data: bytes) -> bytes:
        """Decode an H.264 NAL unit into RGBA pixel data.

        Takes raw H.264 NAL unit bytes, decodes them through the
        codec context, and converts the resulting video frame to
        RGBA format.

        Args:
            data: Raw H.264 NAL unit bytes.

        Returns:
            RGBA pixel data as bytes (width * height * 4 bytes),
            or empty bytes if decoding fails or produces no frames.
        """
        try:
            packet = av.Packet(data)
            frames = self._codec_context.decode(packet)

            for frame in frames:
                # Convert frame to RGBA format
                rgba_frame = frame.reformat(format="rgba")
                # Return the raw pixel data from the first decoded frame
                return bytes(rgba_frame.planes[0])

            # No frames decoded (e.g., buffering B-frames)
            return b""

        except av.error.InvalidDataError as e:
            logger.warning("H.264 decode error (invalid data): %s", e)
            return b""
        except av.error.EOFError as e:
            logger.warning("H.264 decode error (EOF): %s", e)
            return b""
        except Exception as e:
            logger.warning("H.264 decode error: %s", e)
            return b""
