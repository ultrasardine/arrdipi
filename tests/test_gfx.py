"""Tests for the RDPGFX graphics pipeline.

Tests surface create/delete lifecycle, cache operations, frame acknowledge
construction, and PDU parsing/serialization.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from arrdipi.graphics.gfx import (
    QUEUE_DEPTH_UNLIMITED,
    RDPGFX_CMDID_CACHE_TO_SURFACE,
    RDPGFX_CMDID_CREATE_SURFACE,
    RDPGFX_CMDID_DELETE_SURFACE,
    RDPGFX_CMDID_END_FRAME,
    RDPGFX_CMDID_EVICT_CACHE,
    RDPGFX_CMDID_FRAME_ACKNOWLEDGE,
    RDPGFX_CMDID_MAP_SURFACE,
    RDPGFX_CMDID_START_FRAME,
    RDPGFX_CMDID_SURFACE_TO_CACHE,
    RDPGFX_CMDID_WIRE_TO_SURFACE_1,
    CacheToSurfacePdu,
    CreateSurfacePdu,
    DeleteSurfacePdu,
    EndFramePdu,
    EvictCachePdu,
    FrameAcknowledgePdu,
    GFX_CHANNEL_NAME,
    GfxPipeline,
    MapSurfacePdu,
    StartFramePdu,
    SurfaceToCachePdu,
    WireToSurfacePdu,
    _build_gfx_pdu,
    _GFX_HEADER_SIZE,
)
from arrdipi.pdu.base import ByteReader


# --- PDU Serialization/Parse Round-Trip Tests ---


class TestWireToSurfacePdu:
    """Tests for WireToSurfacePdu parse/serialize."""

    def test_round_trip(self):
        pdu = WireToSurfacePdu(
            surface_id=1,
            codec_id=0x0003,
            pixel_format=0x20,
            dest_x=10,
            dest_y=20,
            dest_w=100,
            dest_h=50,
            bitmap_data=b"\x00\x01\x02\x03",
        )
        data = pdu.serialize()
        parsed = WireToSurfacePdu.parse(data)
        assert parsed.surface_id == 1
        assert parsed.codec_id == 0x0003
        assert parsed.pixel_format == 0x20
        assert parsed.dest_x == 10
        assert parsed.dest_y == 20
        assert parsed.dest_w == 100
        assert parsed.dest_h == 50
        assert parsed.bitmap_data == b"\x00\x01\x02\x03"


class TestCreateSurfacePdu:
    """Tests for CreateSurfacePdu parse/serialize."""

    def test_round_trip(self):
        pdu = CreateSurfacePdu(
            surface_id=5, width=1920, height=1080, pixel_format=0x20
        )
        data = pdu.serialize()
        parsed = CreateSurfacePdu.parse(data)
        assert parsed.surface_id == 5
        assert parsed.width == 1920
        assert parsed.height == 1080
        assert parsed.pixel_format == 0x20


class TestDeleteSurfacePdu:
    """Tests for DeleteSurfacePdu parse/serialize."""

    def test_round_trip(self):
        pdu = DeleteSurfacePdu(surface_id=7)
        data = pdu.serialize()
        parsed = DeleteSurfacePdu.parse(data)
        assert parsed.surface_id == 7


class TestMapSurfacePdu:
    """Tests for MapSurfacePdu parse/serialize."""

    def test_round_trip(self):
        pdu = MapSurfacePdu(surface_id=3, output_origin_x=100, output_origin_y=200)
        data = pdu.serialize()
        parsed = MapSurfacePdu.parse(data)
        assert parsed.surface_id == 3
        assert parsed.output_origin_x == 100
        assert parsed.output_origin_y == 200


class TestCacheToSurfacePdu:
    """Tests for CacheToSurfacePdu parse/serialize."""

    def test_round_trip(self):
        pdu = CacheToSurfacePdu(
            cache_slot=10, surface_id=2, dest_points=[(50, 60), (70, 80)]
        )
        data = pdu.serialize()
        parsed = CacheToSurfacePdu.parse(data)
        assert parsed.cache_slot == 10
        assert parsed.surface_id == 2
        assert parsed.dest_points == [(50, 60), (70, 80)]

    def test_empty_dest_points(self):
        pdu = CacheToSurfacePdu(cache_slot=0, surface_id=1, dest_points=[])
        data = pdu.serialize()
        parsed = CacheToSurfacePdu.parse(data)
        assert parsed.dest_points == []


class TestSurfaceToCachePdu:
    """Tests for SurfaceToCachePdu parse/serialize."""

    def test_round_trip(self):
        pdu = SurfaceToCachePdu(
            surface_id=1,
            cache_slot=5,
            cache_key=0x123456789ABCDEF0,
            src_x=10,
            src_y=20,
            src_w=64,
            src_h=64,
        )
        data = pdu.serialize()
        parsed = SurfaceToCachePdu.parse(data)
        assert parsed.surface_id == 1
        assert parsed.cache_slot == 5
        assert parsed.cache_key == 0x123456789ABCDEF0
        assert parsed.src_x == 10
        assert parsed.src_y == 20
        assert parsed.src_w == 64
        assert parsed.src_h == 64


class TestEvictCachePdu:
    """Tests for EvictCachePdu parse/serialize."""

    def test_round_trip(self):
        pdu = EvictCachePdu(cache_slots=[1, 5, 10, 255])
        data = pdu.serialize()
        parsed = EvictCachePdu.parse(data)
        assert parsed.cache_slots == [1, 5, 10, 255]

    def test_single_slot(self):
        pdu = EvictCachePdu(cache_slots=[42])
        data = pdu.serialize()
        parsed = EvictCachePdu.parse(data)
        assert parsed.cache_slots == [42]


class TestFrameAcknowledgePdu:
    """Tests for FrameAcknowledgePdu parse/serialize."""

    def test_round_trip(self):
        pdu = FrameAcknowledgePdu(
            queue_depth=QUEUE_DEPTH_UNLIMITED,
            frame_id=100,
            total_frames_decoded=50,
        )
        data = pdu.serialize()
        parsed = FrameAcknowledgePdu.parse(data)
        assert parsed.queue_depth == QUEUE_DEPTH_UNLIMITED
        assert parsed.frame_id == 100
        assert parsed.total_frames_decoded == 50


class TestStartFramePdu:
    """Tests for StartFramePdu parse/serialize."""

    def test_round_trip(self):
        pdu = StartFramePdu(timestamp=12345, frame_id=7)
        data = pdu.serialize()
        parsed = StartFramePdu.parse(data)
        assert parsed.timestamp == 12345
        assert parsed.frame_id == 7


class TestEndFramePdu:
    """Tests for EndFramePdu parse/serialize."""

    def test_round_trip(self):
        pdu = EndFramePdu(frame_id=42)
        data = pdu.serialize()
        parsed = EndFramePdu.parse(data)
        assert parsed.frame_id == 42


# --- GFX Pipeline Integration Tests ---


class TestGfxPipelineSurfaceLifecycle:
    """Tests for surface create/delete lifecycle."""

    @pytest.fixture
    def mock_h264(self):
        codec = MagicMock()
        codec.decode_frame = MagicMock(return_value=b"")
        return codec

    @pytest.fixture
    def pipeline(self, mock_h264):
        return GfxPipeline(h264_codec=mock_h264)

    @pytest.mark.asyncio
    async def test_create_surface(self, pipeline):
        """Creating a surface adds it to the surfaces dict."""
        pdu = CreateSurfacePdu(surface_id=1, width=800, height=600, pixel_format=0x20)
        gfx_data = _build_gfx_pdu(RDPGFX_CMDID_CREATE_SURFACE, pdu.serialize())
        await pipeline.handle_message(gfx_data)

        assert 1 in pipeline.surfaces
        assert pipeline.surfaces[1].width == 800
        assert pipeline.surfaces[1].height == 600

    @pytest.mark.asyncio
    async def test_delete_surface(self, pipeline):
        """Deleting a surface removes it from the surfaces dict."""
        # Create first
        create_pdu = CreateSurfacePdu(
            surface_id=2, width=640, height=480, pixel_format=0x20
        )
        await pipeline.handle_message(
            _build_gfx_pdu(RDPGFX_CMDID_CREATE_SURFACE, create_pdu.serialize())
        )
        assert 2 in pipeline.surfaces

        # Delete
        delete_pdu = DeleteSurfacePdu(surface_id=2)
        await pipeline.handle_message(
            _build_gfx_pdu(RDPGFX_CMDID_DELETE_SURFACE, delete_pdu.serialize())
        )
        assert 2 not in pipeline.surfaces

    @pytest.mark.asyncio
    async def test_map_surface(self, pipeline):
        """Mapping a surface stores the output origin coordinates."""
        create_pdu = CreateSurfacePdu(
            surface_id=3, width=1920, height=1080, pixel_format=0x20
        )
        await pipeline.handle_message(
            _build_gfx_pdu(RDPGFX_CMDID_CREATE_SURFACE, create_pdu.serialize())
        )

        map_pdu = MapSurfacePdu(
            surface_id=3, output_origin_x=50, output_origin_y=100
        )
        await pipeline.handle_message(
            _build_gfx_pdu(RDPGFX_CMDID_MAP_SURFACE, map_pdu.serialize())
        )
        assert pipeline._surface_mappings[3] == (50, 100)

    @pytest.mark.asyncio
    async def test_delete_surface_removes_mapping(self, pipeline):
        """Deleting a surface also removes its mapping."""
        create_pdu = CreateSurfacePdu(
            surface_id=4, width=100, height=100, pixel_format=0x20
        )
        await pipeline.handle_message(
            _build_gfx_pdu(RDPGFX_CMDID_CREATE_SURFACE, create_pdu.serialize())
        )
        map_pdu = MapSurfacePdu(surface_id=4, output_origin_x=0, output_origin_y=0)
        await pipeline.handle_message(
            _build_gfx_pdu(RDPGFX_CMDID_MAP_SURFACE, map_pdu.serialize())
        )
        assert 4 in pipeline._surface_mappings

        delete_pdu = DeleteSurfacePdu(surface_id=4)
        await pipeline.handle_message(
            _build_gfx_pdu(RDPGFX_CMDID_DELETE_SURFACE, delete_pdu.serialize())
        )
        assert 4 not in pipeline._surface_mappings

    @pytest.mark.asyncio
    async def test_create_multiple_surfaces(self, pipeline):
        """Multiple surfaces can coexist."""
        for sid in range(5):
            pdu = CreateSurfacePdu(
                surface_id=sid, width=100 + sid, height=200 + sid, pixel_format=0x20
            )
            await pipeline.handle_message(
                _build_gfx_pdu(RDPGFX_CMDID_CREATE_SURFACE, pdu.serialize())
            )

        assert len(pipeline.surfaces) == 5
        assert pipeline.surfaces[3].width == 103
        assert pipeline.surfaces[3].height == 203


class TestGfxPipelineCacheOperations:
    """Tests for cache management operations."""

    @pytest.fixture
    def mock_h264(self):
        codec = MagicMock()
        codec.decode_frame = MagicMock(return_value=b"")
        return codec

    @pytest.fixture
    def pipeline(self, mock_h264):
        return GfxPipeline(h264_codec=mock_h264)

    @pytest.mark.asyncio
    async def test_surface_to_cache(self, pipeline):
        """Surface-to-cache stores pixel data in the cache."""
        # Create a surface and write some pixels
        create_pdu = CreateSurfacePdu(
            surface_id=1, width=100, height=100, pixel_format=0x20
        )
        await pipeline.handle_message(
            _build_gfx_pdu(RDPGFX_CMDID_CREATE_SURFACE, create_pdu.serialize())
        )

        # Write known pixels to the surface
        surface = pipeline.surfaces[1]
        pixels = b"\xFF\x00\x00\xFF" * (10 * 10)  # 10x10 red pixels
        await surface.write_pixels(0, 0, 10, 10, pixels)

        # Surface to cache
        s2c_pdu = SurfaceToCachePdu(
            surface_id=1,
            cache_slot=5,
            cache_key=0xABCD,
            src_x=0,
            src_y=0,
            src_w=10,
            src_h=10,
        )
        await pipeline.handle_message(
            _build_gfx_pdu(RDPGFX_CMDID_SURFACE_TO_CACHE, s2c_pdu.serialize())
        )

        assert 5 in pipeline.cache
        assert pipeline.cache[5] == pixels

    @pytest.mark.asyncio
    async def test_evict_cache(self, pipeline):
        """Evict cache removes entries from the cache."""
        # Manually populate cache
        pipeline._cache[1] = b"\x00" * 100
        pipeline._cache[2] = b"\x01" * 200
        pipeline._cache[3] = b"\x02" * 300

        evict_pdu = EvictCachePdu(cache_slots=[1, 3])
        await pipeline.handle_message(
            _build_gfx_pdu(RDPGFX_CMDID_EVICT_CACHE, evict_pdu.serialize())
        )

        assert 1 not in pipeline.cache
        assert 2 in pipeline.cache
        assert 3 not in pipeline.cache

    @pytest.mark.asyncio
    async def test_evict_nonexistent_slot(self, pipeline):
        """Evicting a non-existent cache slot does not raise."""
        evict_pdu = EvictCachePdu(cache_slots=[999])
        await pipeline.handle_message(
            _build_gfx_pdu(RDPGFX_CMDID_EVICT_CACHE, evict_pdu.serialize())
        )
        # Should not raise


class TestGfxPipelineFrameAcknowledge:
    """Tests for frame acknowledge construction and sending."""

    @pytest.fixture
    def mock_h264(self):
        codec = MagicMock()
        codec.decode_frame = MagicMock(return_value=b"")
        return codec

    @pytest.fixture
    def send_fn(self):
        return AsyncMock()

    @pytest.fixture
    def pipeline(self, mock_h264, send_fn):
        return GfxPipeline(h264_codec=mock_h264, send_fn=send_fn)

    @pytest.mark.asyncio
    async def test_frame_acknowledge_sent_on_end_frame(self, pipeline, send_fn):
        """End Frame triggers a Frame Acknowledge PDU."""
        # Send Start Frame
        start_pdu = StartFramePdu(timestamp=1000, frame_id=42)
        await pipeline.handle_message(
            _build_gfx_pdu(RDPGFX_CMDID_START_FRAME, start_pdu.serialize())
        )

        # Send End Frame
        end_pdu = EndFramePdu(frame_id=42)
        await pipeline.handle_message(
            _build_gfx_pdu(RDPGFX_CMDID_END_FRAME, end_pdu.serialize())
        )

        # Verify Frame Acknowledge was sent
        send_fn.assert_called_once()
        sent_data = send_fn.call_args[0][0]

        # Parse the sent data to verify it's a valid Frame Acknowledge
        reader = ByteReader(sent_data, "test")
        cmd_id = reader.read_u16_le()
        assert cmd_id == RDPGFX_CMDID_FRAME_ACKNOWLEDGE
        _flags = reader.read_u16_le()
        _pdu_length = reader.read_u32_le()

        # Parse the ack payload
        ack = FrameAcknowledgePdu.parse(sent_data[_GFX_HEADER_SIZE:])
        assert ack.frame_id == 42
        assert ack.queue_depth == QUEUE_DEPTH_UNLIMITED
        assert ack.total_frames_decoded == 1

    @pytest.mark.asyncio
    async def test_frame_count_increments(self, pipeline, send_fn):
        """Total frames decoded increments with each End Frame."""
        for i in range(3):
            start_pdu = StartFramePdu(timestamp=1000 + i, frame_id=i)
            await pipeline.handle_message(
                _build_gfx_pdu(RDPGFX_CMDID_START_FRAME, start_pdu.serialize())
            )
            end_pdu = EndFramePdu(frame_id=i)
            await pipeline.handle_message(
                _build_gfx_pdu(RDPGFX_CMDID_END_FRAME, end_pdu.serialize())
            )

        assert pipeline.total_frames_decoded == 3

        # Check the last ack has correct total
        last_sent = send_fn.call_args[0][0]
        ack = FrameAcknowledgePdu.parse(last_sent[_GFX_HEADER_SIZE:])
        assert ack.total_frames_decoded == 3
        assert ack.frame_id == 2

    @pytest.mark.asyncio
    async def test_no_send_without_send_fn(self, mock_h264):
        """Frame acknowledge is skipped when no send_fn is set."""
        pipeline = GfxPipeline(h264_codec=mock_h264, send_fn=None)

        end_pdu = EndFramePdu(frame_id=1)
        # Should not raise even without send_fn
        await pipeline.handle_message(
            _build_gfx_pdu(RDPGFX_CMDID_END_FRAME, end_pdu.serialize())
        )
        assert pipeline.total_frames_decoded == 1


class TestGfxPipelineWireToSurface:
    """Tests for wire-to-surface H.264 decoding."""

    @pytest.mark.asyncio
    async def test_wire_to_surface_decodes_and_writes(self):
        """Wire-to-surface decodes H.264 and writes pixels to surface."""
        # Create a mock H264 codec that returns known pixel data
        mock_h264 = MagicMock()
        pixel_data = b"\xFF\x00\x00\xFF" * (10 * 10)  # 10x10 red
        mock_h264.decode_frame = MagicMock(return_value=pixel_data)

        pipeline = GfxPipeline(h264_codec=mock_h264)

        # Create surface
        create_pdu = CreateSurfacePdu(
            surface_id=1, width=100, height=100, pixel_format=0x20
        )
        await pipeline.handle_message(
            _build_gfx_pdu(RDPGFX_CMDID_CREATE_SURFACE, create_pdu.serialize())
        )

        # Wire to surface
        wire_pdu = WireToSurfacePdu(
            surface_id=1,
            codec_id=0x0003,
            pixel_format=0x20,
            dest_x=5,
            dest_y=5,
            dest_w=10,
            dest_h=10,
            bitmap_data=b"\x00" * 100,  # fake H.264 data
        )
        await pipeline.handle_message(
            _build_gfx_pdu(RDPGFX_CMDID_WIRE_TO_SURFACE_1, wire_pdu.serialize())
        )

        # Verify H264 codec was called
        mock_h264.decode_frame.assert_called_once_with(b"\x00" * 100)

        # Verify pixels were written to the surface
        surface = pipeline.surfaces[1]
        read_pixels = await surface.read_pixels(5, 5, 10, 10)
        assert read_pixels == pixel_data

    @pytest.mark.asyncio
    async def test_wire_to_surface_unknown_surface(self):
        """Wire-to-surface for unknown surface is handled gracefully."""
        mock_h264 = MagicMock()
        mock_h264.decode_frame = MagicMock(return_value=b"\x00" * 400)

        pipeline = GfxPipeline(h264_codec=mock_h264)

        wire_pdu = WireToSurfacePdu(
            surface_id=999,
            codec_id=0x0003,
            pixel_format=0x20,
            dest_x=0,
            dest_y=0,
            dest_w=10,
            dest_h=10,
            bitmap_data=b"\x00" * 50,
        )
        # Should not raise
        await pipeline.handle_message(
            _build_gfx_pdu(RDPGFX_CMDID_WIRE_TO_SURFACE_1, wire_pdu.serialize())
        )


class TestGfxPipelineChannelRegistration:
    """Tests for DRDYNVC channel registration."""

    def test_channel_name_constant(self):
        """GFX channel name matches the expected DRDYNVC name."""
        assert GFX_CHANNEL_NAME == "Microsoft::Windows::RDS::Graphics"

    def test_create_handler_returns_callable(self):
        """create_handler returns an async callable."""
        mock_h264 = MagicMock()
        pipeline = GfxPipeline(h264_codec=mock_h264)
        handler = pipeline.create_handler()
        assert callable(handler)
        # The handler should be the bound handle_message method
        assert handler.__func__ is GfxPipeline.handle_message


class TestBuildGfxPdu:
    """Tests for _build_gfx_pdu helper."""

    def test_builds_correct_header(self):
        """_build_gfx_pdu produces correct header format."""
        payload = b"\x01\x02\x03\x04"
        result = _build_gfx_pdu(0x000D, payload)

        reader = ByteReader(result, "test")
        cmd_id = reader.read_u16_le()
        flags = reader.read_u16_le()
        pdu_length = reader.read_u32_le()

        assert cmd_id == 0x000D
        assert flags == 0
        assert pdu_length == _GFX_HEADER_SIZE + len(payload)
        assert result[_GFX_HEADER_SIZE:] == payload
