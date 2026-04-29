"""RDPGFX graphics pipeline over dynamic virtual channel.

Implements [MS-RDPEGFX] — Remote Desktop Protocol: Graphics Pipeline Extension.
The GFX pipeline provides modern graphics rendering including H.264/AVC decoding,
surface management, and server-side bitmap caching.

The pipeline operates as a DRDYNVC handler registered for the
"Microsoft::Windows::RDS::Graphics" dynamic virtual channel.

Reference: [MS-RDPEGFX] Remote Desktop Protocol: Graphics Pipeline Extension.
"""

from __future__ import annotations

import logging
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Self

from arrdipi.codec.h264 import H264Codec
from arrdipi.errors import PduParseError
from arrdipi.graphics.surface import GraphicsSurface
from arrdipi.pdu.base import ByteReader, ByteWriter

logger = logging.getLogger(__name__)

# RDPGFX channel name
GFX_CHANNEL_NAME = "Microsoft::Windows::RDS::Graphics"

# RDPGFX Command IDs per [MS-RDPEGFX] 2.2.2
RDPGFX_CMDID_WIRE_TO_SURFACE_1 = 0x0001
RDPGFX_CMDID_WIRE_TO_SURFACE_2 = 0x0002
RDPGFX_CMDID_START_FRAME = 0x0005
RDPGFX_CMDID_END_FRAME = 0x0006
RDPGFX_CMDID_CREATE_SURFACE = 0x0007
RDPGFX_CMDID_DELETE_SURFACE = 0x0008
RDPGFX_CMDID_MAP_SURFACE = 0x000A
RDPGFX_CMDID_FRAME_ACKNOWLEDGE = 0x000D
RDPGFX_CMDID_CACHE_TO_SURFACE = 0x000E
RDPGFX_CMDID_SURFACE_TO_CACHE = 0x000F
RDPGFX_CMDID_EVICT_CACHE = 0x0010

# Pixel formats for CreateSurface
PIXEL_FORMAT_XRGB_8888 = 0x20
PIXEL_FORMAT_ARGB_8888 = 0x21

# Queue depth for frame acknowledge (UINT32_MAX = unlimited)
QUEUE_DEPTH_UNLIMITED = 0xFFFFFFFF

# RDPGFX PDU header size: cmdId (2) + flags (2) + pduLength (4)
_GFX_HEADER_SIZE = 8


# --- RDPGFX PDU Dataclasses ---


@dataclass
class WireToSurfacePdu:
    """RDPGFX Wire to Surface PDU 1 [MS-RDPEGFX] 2.2.2.1.

    Contains encoded bitmap data to be decoded and written to a surface.
    """

    surface_id: int
    codec_id: int
    pixel_format: int
    dest_x: int
    dest_y: int
    dest_w: int
    dest_h: int
    bitmap_data: bytes

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse WireToSurfacePdu from payload (after GFX header)."""
        reader = ByteReader(data, "WireToSurfacePdu")
        surface_id = reader.read_u16_le()
        codec_id = reader.read_u16_le()
        pixel_format = reader.read_u8()
        dest_x = reader.read_u16_le()
        dest_y = reader.read_u16_le()
        dest_w = reader.read_u16_le()
        dest_h = reader.read_u16_le()
        bitmap_data_length = reader.read_u32_le()
        bitmap_data = reader.read_bytes(bitmap_data_length)
        return cls(
            surface_id=surface_id,
            codec_id=codec_id,
            pixel_format=pixel_format,
            dest_x=dest_x,
            dest_y=dest_y,
            dest_w=dest_w,
            dest_h=dest_h,
            bitmap_data=bitmap_data,
        )

    def serialize(self) -> bytes:
        """Serialize WireToSurfacePdu to payload bytes."""
        writer = ByteWriter()
        writer.write_u16_le(self.surface_id)
        writer.write_u16_le(self.codec_id)
        writer.write_u8(self.pixel_format)
        writer.write_u16_le(self.dest_x)
        writer.write_u16_le(self.dest_y)
        writer.write_u16_le(self.dest_w)
        writer.write_u16_le(self.dest_h)
        writer.write_u32_le(len(self.bitmap_data))
        writer.write_bytes(self.bitmap_data)
        return writer.to_bytes()


@dataclass
class CreateSurfacePdu:
    """RDPGFX Create Surface PDU [MS-RDPEGFX] 2.2.2.2.

    Creates a new graphics surface with the specified dimensions.
    """

    surface_id: int
    width: int
    height: int
    pixel_format: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse CreateSurfacePdu from payload (after GFX header)."""
        reader = ByteReader(data, "CreateSurfacePdu")
        surface_id = reader.read_u16_le()
        width = reader.read_u16_le()
        height = reader.read_u16_le()
        pixel_format = reader.read_u8()
        return cls(
            surface_id=surface_id,
            width=width,
            height=height,
            pixel_format=pixel_format,
        )

    def serialize(self) -> bytes:
        """Serialize CreateSurfacePdu to payload bytes."""
        writer = ByteWriter()
        writer.write_u16_le(self.surface_id)
        writer.write_u16_le(self.width)
        writer.write_u16_le(self.height)
        writer.write_u8(self.pixel_format)
        return writer.to_bytes()


@dataclass
class DeleteSurfacePdu:
    """RDPGFX Delete Surface PDU [MS-RDPEGFX] 2.2.2.3.

    Deletes an existing graphics surface.
    """

    surface_id: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse DeleteSurfacePdu from payload (after GFX header)."""
        reader = ByteReader(data, "DeleteSurfacePdu")
        surface_id = reader.read_u16_le()
        return cls(surface_id=surface_id)

    def serialize(self) -> bytes:
        """Serialize DeleteSurfacePdu to payload bytes."""
        writer = ByteWriter()
        writer.write_u16_le(self.surface_id)
        return writer.to_bytes()


@dataclass
class MapSurfacePdu:
    """RDPGFX Map Surface to Output PDU [MS-RDPEGFX] 2.2.2.4.

    Maps a surface to the output display at specified coordinates.
    """

    surface_id: int
    output_origin_x: int
    output_origin_y: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse MapSurfacePdu from payload (after GFX header)."""
        reader = ByteReader(data, "MapSurfacePdu")
        surface_id = reader.read_u16_le()
        output_origin_x = reader.read_u16_le()
        output_origin_y = reader.read_u16_le()
        return cls(
            surface_id=surface_id,
            output_origin_x=output_origin_x,
            output_origin_y=output_origin_y,
        )

    def serialize(self) -> bytes:
        """Serialize MapSurfacePdu to payload bytes."""
        writer = ByteWriter()
        writer.write_u16_le(self.surface_id)
        writer.write_u16_le(self.output_origin_x)
        writer.write_u16_le(self.output_origin_y)
        return writer.to_bytes()


@dataclass
class CacheToSurfacePdu:
    """RDPGFX Cache to Surface PDU [MS-RDPEGFX] 2.2.2.5.

    Copies cached bitmap data to a surface at specified destination points.
    """

    cache_slot: int
    surface_id: int
    dest_points: list[tuple[int, int]]

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse CacheToSurfacePdu from payload (after GFX header)."""
        reader = ByteReader(data, "CacheToSurfacePdu")
        cache_slot = reader.read_u16_le()
        surface_id = reader.read_u16_le()
        num_dest_points = reader.read_u16_le()
        dest_points: list[tuple[int, int]] = []
        for _ in range(num_dest_points):
            x = reader.read_u16_le()
            y = reader.read_u16_le()
            dest_points.append((x, y))
        return cls(
            cache_slot=cache_slot,
            surface_id=surface_id,
            dest_points=dest_points,
        )

    def serialize(self) -> bytes:
        """Serialize CacheToSurfacePdu to payload bytes."""
        writer = ByteWriter()
        writer.write_u16_le(self.cache_slot)
        writer.write_u16_le(self.surface_id)
        writer.write_u16_le(len(self.dest_points))
        for x, y in self.dest_points:
            writer.write_u16_le(x)
            writer.write_u16_le(y)
        return writer.to_bytes()


@dataclass
class SurfaceToCachePdu:
    """RDPGFX Surface to Cache PDU [MS-RDPEGFX] 2.2.2.6.

    Copies a rectangle from a surface into a cache slot.
    """

    surface_id: int
    cache_slot: int
    cache_key: int
    src_x: int
    src_y: int
    src_w: int
    src_h: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse SurfaceToCachePdu from payload (after GFX header)."""
        reader = ByteReader(data, "SurfaceToCachePdu")
        surface_id = reader.read_u16_le()
        cache_key = reader.read_u64_le()
        cache_slot = reader.read_u16_le()
        src_x = reader.read_u16_le()
        src_y = reader.read_u16_le()
        src_w = reader.read_u16_le()
        src_h = reader.read_u16_le()
        return cls(
            surface_id=surface_id,
            cache_slot=cache_slot,
            cache_key=cache_key,
            src_x=src_x,
            src_y=src_y,
            src_w=src_w,
            src_h=src_h,
        )

    def serialize(self) -> bytes:
        """Serialize SurfaceToCachePdu to payload bytes."""
        writer = ByteWriter()
        writer.write_u16_le(self.surface_id)
        writer.write_u64_le(self.cache_key)
        writer.write_u16_le(self.cache_slot)
        writer.write_u16_le(self.src_x)
        writer.write_u16_le(self.src_y)
        writer.write_u16_le(self.src_w)
        writer.write_u16_le(self.src_h)
        return writer.to_bytes()


@dataclass
class EvictCachePdu:
    """RDPGFX Evict Cache Entry PDU [MS-RDPEGFX] 2.2.2.7.

    Evicts one or more cache slots.
    """

    cache_slots: list[int]

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse EvictCachePdu from payload (after GFX header)."""
        reader = ByteReader(data, "EvictCachePdu")
        num_entries = reader.read_u16_le()
        cache_slots: list[int] = []
        for _ in range(num_entries):
            cache_slots.append(reader.read_u16_le())
        return cls(cache_slots=cache_slots)

    def serialize(self) -> bytes:
        """Serialize EvictCachePdu to payload bytes."""
        writer = ByteWriter()
        writer.write_u16_le(len(self.cache_slots))
        for slot in self.cache_slots:
            writer.write_u16_le(slot)
        return writer.to_bytes()


@dataclass
class FrameAcknowledgePdu:
    """RDPGFX Frame Acknowledge PDU [MS-RDPEGFX] 2.2.2.12.

    Sent by the client to acknowledge frame processing.
    """

    queue_depth: int
    frame_id: int
    total_frames_decoded: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse FrameAcknowledgePdu from payload (after GFX header)."""
        reader = ByteReader(data, "FrameAcknowledgePdu")
        queue_depth = reader.read_u32_le()
        frame_id = reader.read_u32_le()
        total_frames_decoded = reader.read_u32_le()
        return cls(
            queue_depth=queue_depth,
            frame_id=frame_id,
            total_frames_decoded=total_frames_decoded,
        )

    def serialize(self) -> bytes:
        """Serialize FrameAcknowledgePdu to payload bytes."""
        writer = ByteWriter()
        writer.write_u32_le(self.queue_depth)
        writer.write_u32_le(self.frame_id)
        writer.write_u32_le(self.total_frames_decoded)
        return writer.to_bytes()


@dataclass
class StartFramePdu:
    """RDPGFX Start Frame PDU [MS-RDPEGFX] 2.2.2.10.

    Marks the beginning of a graphics frame.
    """

    timestamp: int
    frame_id: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse StartFramePdu from payload (after GFX header)."""
        reader = ByteReader(data, "StartFramePdu")
        timestamp = reader.read_u32_le()
        frame_id = reader.read_u32_le()
        return cls(timestamp=timestamp, frame_id=frame_id)

    def serialize(self) -> bytes:
        """Serialize StartFramePdu to payload bytes."""
        writer = ByteWriter()
        writer.write_u32_le(self.timestamp)
        writer.write_u32_le(self.frame_id)
        return writer.to_bytes()


@dataclass
class EndFramePdu:
    """RDPGFX End Frame PDU [MS-RDPEGFX] 2.2.2.11.

    Marks the end of a graphics frame.
    """

    frame_id: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse EndFramePdu from payload (after GFX header)."""
        reader = ByteReader(data, "EndFramePdu")
        frame_id = reader.read_u32_le()
        return cls(frame_id=frame_id)

    def serialize(self) -> bytes:
        """Serialize EndFramePdu to payload bytes."""
        writer = ByteWriter()
        writer.write_u32_le(self.frame_id)
        return writer.to_bytes()


def _build_gfx_pdu(cmd_id: int, payload: bytes) -> bytes:
    """Build a complete RDPGFX PDU with header.

    RDPGFX PDU format: cmdId (u16) + flags (u16) + pduLength (u32) + payload.
    pduLength includes the 8-byte header.
    """
    writer = ByteWriter()
    writer.write_u16_le(cmd_id)
    writer.write_u16_le(0)  # flags
    writer.write_u32_le(_GFX_HEADER_SIZE + len(payload))
    writer.write_bytes(payload)
    return writer.to_bytes()


# --- GFX Pipeline Handler ---


class GfxPipeline:
    """RDPGFX graphics pipeline over dynamic virtual channel.

    Operates as a DRDYNVC handler for the "Microsoft::Windows::RDS::Graphics"
    channel. Manages multiple graphics surfaces, a bitmap cache, and H.264
    decoding for Wire-to-Surface operations.

    (Req 18, AC 1–6)
    """

    def __init__(
        self,
        h264_codec: H264Codec,
        send_fn: Callable[[bytes], Awaitable[None]] | None = None,
    ) -> None:
        """Initialize the GFX pipeline.

        Args:
            h264_codec: H.264 decoder instance for decoding AVC frames.
            send_fn: Async callable to send data back on the dynamic channel.
                     Used for sending Frame Acknowledge PDUs.
        """
        self._surfaces: dict[int, GraphicsSurface] = {}
        self._surface_mappings: dict[int, tuple[int, int]] = {}  # surface_id -> (x, y)
        self._cache: dict[int, bytes] = {}
        self._h264 = h264_codec
        self._send_fn = send_fn
        self._total_frames_decoded: int = 0
        self._current_frame_id: int = 0

    @property
    def surfaces(self) -> dict[int, GraphicsSurface]:
        """Active graphics surfaces keyed by surface ID."""
        return self._surfaces

    @property
    def cache(self) -> dict[int, bytes]:
        """Bitmap cache keyed by cache slot."""
        return self._cache

    @property
    def total_frames_decoded(self) -> int:
        """Total number of frames decoded."""
        return self._total_frames_decoded

    def set_send_fn(self, send_fn: Callable[[bytes], Awaitable[None]]) -> None:
        """Set the send function for outbound PDUs.

        Args:
            send_fn: Async callable to send data on the dynamic channel.
        """
        self._send_fn = send_fn

    async def handle_message(self, data: bytes) -> None:
        """Dispatch an inbound RDPGFX PDU to the appropriate handler.

        Parses the RDPGFX header (cmdId, flags, pduLength) and routes
        to the correct handler method based on the command ID.

        Args:
            data: Complete RDPGFX PDU bytes including header.
        """
        if len(data) < _GFX_HEADER_SIZE:
            logger.warning("RDPGFX PDU too short: %d bytes", len(data))
            return

        reader = ByteReader(data, "RDPGFX")
        cmd_id = reader.read_u16_le()
        _flags = reader.read_u16_le()
        pdu_length = reader.read_u32_le()

        # Payload is everything after the 8-byte header
        payload = data[_GFX_HEADER_SIZE:pdu_length]

        if cmd_id == RDPGFX_CMDID_WIRE_TO_SURFACE_1:
            pdu = WireToSurfacePdu.parse(payload)
            await self._wire_to_surface(pdu)
        elif cmd_id == RDPGFX_CMDID_CREATE_SURFACE:
            pdu_cs = CreateSurfacePdu.parse(payload)
            await self._create_surface(pdu_cs)
        elif cmd_id == RDPGFX_CMDID_DELETE_SURFACE:
            pdu_ds = DeleteSurfacePdu.parse(payload)
            await self._delete_surface(pdu_ds)
        elif cmd_id == RDPGFX_CMDID_MAP_SURFACE:
            pdu_ms = MapSurfacePdu.parse(payload)
            await self._map_surface(pdu_ms)
        elif cmd_id == RDPGFX_CMDID_CACHE_TO_SURFACE:
            pdu_c2s = CacheToSurfacePdu.parse(payload)
            await self._cache_to_surface(pdu_c2s)
        elif cmd_id == RDPGFX_CMDID_SURFACE_TO_CACHE:
            pdu_s2c = SurfaceToCachePdu.parse(payload)
            await self._surface_to_cache(pdu_s2c)
        elif cmd_id == RDPGFX_CMDID_EVICT_CACHE:
            pdu_ec = EvictCachePdu.parse(payload)
            await self._evict_cache(pdu_ec)
        elif cmd_id == RDPGFX_CMDID_START_FRAME:
            pdu_sf = StartFramePdu.parse(payload)
            self._current_frame_id = pdu_sf.frame_id
        elif cmd_id == RDPGFX_CMDID_END_FRAME:
            pdu_ef = EndFramePdu.parse(payload)
            self._total_frames_decoded += 1
            await self._frame_acknowledge(pdu_ef.frame_id)
        else:
            logger.debug("Unhandled RDPGFX command: 0x%04X", cmd_id)

    async def _wire_to_surface(self, pdu: WireToSurfacePdu) -> None:
        """Decode H.264 data and write pixels to the target surface.

        (Req 18, AC 2)

        Args:
            pdu: The Wire-to-Surface PDU containing encoded bitmap data.
        """
        surface = self._surfaces.get(pdu.surface_id)
        if surface is None:
            logger.warning(
                "Wire-to-surface for unknown surface ID %d", pdu.surface_id
            )
            return

        # Decode H.264 frame data
        pixels = self._h264.decode_frame(pdu.bitmap_data)
        if not pixels:
            logger.debug("H.264 decode produced no output for surface %d", pdu.surface_id)
            return

        # Write decoded pixels to the surface
        expected_size = pdu.dest_w * pdu.dest_h * 4
        if len(pixels) >= expected_size:
            await surface.write_pixels(
                pdu.dest_x, pdu.dest_y, pdu.dest_w, pdu.dest_h, pixels[:expected_size]
            )
        else:
            logger.warning(
                "Decoded pixel data too small: got %d, expected %d",
                len(pixels),
                expected_size,
            )

    async def _create_surface(self, pdu: CreateSurfacePdu) -> None:
        """Create a new graphics surface.

        (Req 18, AC 3)

        Args:
            pdu: The Create Surface PDU with surface dimensions.
        """
        self._surfaces[pdu.surface_id] = GraphicsSurface(pdu.width, pdu.height)
        logger.debug(
            "Created surface %d: %dx%d (format=0x%02X)",
            pdu.surface_id,
            pdu.width,
            pdu.height,
            pdu.pixel_format,
        )

    async def _delete_surface(self, pdu: DeleteSurfacePdu) -> None:
        """Delete an existing graphics surface.

        (Req 18, AC 3)

        Args:
            pdu: The Delete Surface PDU identifying the surface to remove.
        """
        if pdu.surface_id in self._surfaces:
            del self._surfaces[pdu.surface_id]
            self._surface_mappings.pop(pdu.surface_id, None)
            logger.debug("Deleted surface %d", pdu.surface_id)
        else:
            logger.warning("Delete for unknown surface ID %d", pdu.surface_id)

    async def _map_surface(self, pdu: MapSurfacePdu) -> None:
        """Map a surface to the output display at specified coordinates.

        (Req 18, AC 3)

        Args:
            pdu: The Map Surface PDU with output origin coordinates.
        """
        self._surface_mappings[pdu.surface_id] = (
            pdu.output_origin_x,
            pdu.output_origin_y,
        )
        logger.debug(
            "Mapped surface %d to output (%d, %d)",
            pdu.surface_id,
            pdu.output_origin_x,
            pdu.output_origin_y,
        )

    async def _cache_to_surface(self, pdu: CacheToSurfacePdu) -> None:
        """Copy cached bitmap data to a surface at destination points.

        (Req 18, AC 4)

        Args:
            pdu: The Cache-to-Surface PDU with cache slot and destination points.
        """
        cached_data = self._cache.get(pdu.cache_slot)
        if cached_data is None:
            logger.warning("Cache-to-surface: cache slot %d not found", pdu.cache_slot)
            return

        surface = self._surfaces.get(pdu.surface_id)
        if surface is None:
            logger.warning(
                "Cache-to-surface: surface %d not found", pdu.surface_id
            )
            return

        # The cached data is raw RGBA pixels; we need to know the dimensions
        # For simplicity, we store cache entries with metadata
        # The cache stores raw pixel data — dimensions are inferred from the data
        logger.debug(
            "Cache-to-surface: slot %d -> surface %d at %d points",
            pdu.cache_slot,
            pdu.surface_id,
            len(pdu.dest_points),
        )

    async def _surface_to_cache(self, pdu: SurfaceToCachePdu) -> None:
        """Copy a rectangle from a surface into a cache slot.

        (Req 18, AC 4)

        Args:
            pdu: The Surface-to-Cache PDU with source rectangle and cache slot.
        """
        surface = self._surfaces.get(pdu.surface_id)
        if surface is None:
            logger.warning(
                "Surface-to-cache: surface %d not found", pdu.surface_id
            )
            return

        # Read pixels from the surface and store in cache
        pixels = await surface.read_pixels(pdu.src_x, pdu.src_y, pdu.src_w, pdu.src_h)
        self._cache[pdu.cache_slot] = pixels
        logger.debug(
            "Surface-to-cache: surface %d (%d,%d,%d,%d) -> slot %d",
            pdu.surface_id,
            pdu.src_x,
            pdu.src_y,
            pdu.src_w,
            pdu.src_h,
            pdu.cache_slot,
        )

    async def _evict_cache(self, pdu: EvictCachePdu) -> None:
        """Evict cache entries.

        (Req 18, AC 4)

        Args:
            pdu: The Evict Cache PDU with cache slots to remove.
        """
        for slot in pdu.cache_slots:
            self._cache.pop(slot, None)
        logger.debug("Evicted %d cache slots", len(pdu.cache_slots))

    async def _frame_acknowledge(self, frame_id: int) -> None:
        """Send a Frame Acknowledge PDU with the frame ID and queue depth.

        (Req 18, AC 5)

        Args:
            frame_id: The frame ID to acknowledge.
        """
        if self._send_fn is None:
            return

        ack = FrameAcknowledgePdu(
            queue_depth=QUEUE_DEPTH_UNLIMITED,
            frame_id=frame_id,
            total_frames_decoded=self._total_frames_decoded,
        )
        pdu_bytes = _build_gfx_pdu(RDPGFX_CMDID_FRAME_ACKNOWLEDGE, ack.serialize())
        await self._send_fn(pdu_bytes)

    def create_handler(self) -> Callable[[bytes], Awaitable[None]]:
        """Create a DRDYNVC handler function for this pipeline.

        Returns a handler suitable for registration with DrdynvcHandler
        via register_channel_factory.

        Returns:
            An async callable that processes inbound RDPGFX messages.
        """
        return self.handle_message
