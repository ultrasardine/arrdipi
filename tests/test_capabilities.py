"""Tests for capability set PDUs — round-trip and build_client_capabilities."""

import struct

import pytest

from arrdipi.pdu.capabilities import (
    AUTORECONNECT_SUPPORTED,
    ENC_SALTED_CHECKSUM,
    FASTPATH_OUTPUT_SUPPORTED,
    INPUT_FLAG_FASTPATH_INPUT,
    INPUT_FLAG_FASTPATH_INPUT2,
    INPUT_FLAG_MOUSE_HWHEEL,
    INPUT_FLAG_MOUSEX,
    INPUT_FLAG_SCANCODES,
    INPUT_FLAG_UNICODE,
    LONG_CREDENTIALS_SUPPORTED,
    NO_BITMAP_COMPRESSION_HDR,
    NSCODEC_GUID,
    REMOTEFX_GUID,
    VCCAPS_COMPR_CS_8K,
    BitmapCapabilitySet,
    BitmapCodecEntry,
    BitmapCodecsCapabilitySet,
    ClientCapabilitiesConfig,
    ConfirmActivePdu,
    DemandActivePdu,
    GeneralCapabilitySet,
    InputCapabilitySet,
    OrderCapabilitySet,
    PointerCapabilitySet,
    VirtualChannelCapabilitySet,
    _serialize_capability_set,
    build_client_capabilities,
)
from arrdipi.pdu.types import CapabilitySetType


class TestGeneralCapabilitySetRoundTrip:
    """Round-trip tests for GeneralCapabilitySet."""

    def test_default_round_trip(self) -> None:
        cap = GeneralCapabilitySet()
        data = cap.serialize()
        parsed = GeneralCapabilitySet.parse(data)
        assert parsed == cap

    def test_with_fastpath_flags(self) -> None:
        cap = GeneralCapabilitySet(
            extra_flags=FASTPATH_OUTPUT_SUPPORTED | LONG_CREDENTIALS_SUPPORTED,
            refresh_rect_support=1,
            suppress_output_support=1,
        )
        data = cap.serialize()
        parsed = GeneralCapabilitySet.parse(data)
        assert parsed == cap
        assert parsed.extra_flags & FASTPATH_OUTPUT_SUPPORTED

    def test_serialize_size(self) -> None:
        cap = GeneralCapabilitySet()
        data = cap.serialize()
        # 9 x u16 + 2 x u8 = 20 bytes
        assert len(data) == 20


class TestBitmapCapabilitySetRoundTrip:
    """Round-trip tests for BitmapCapabilitySet."""

    def test_default_round_trip(self) -> None:
        cap = BitmapCapabilitySet()
        data = cap.serialize()
        parsed = BitmapCapabilitySet.parse(data)
        assert parsed == cap

    def test_custom_resolution(self) -> None:
        cap = BitmapCapabilitySet(
            preferred_bits_per_pixel=16,
            desktop_width=1280,
            desktop_height=720,
        )
        data = cap.serialize()
        parsed = BitmapCapabilitySet.parse(data)
        assert parsed.preferred_bits_per_pixel == 16
        assert parsed.desktop_width == 1280
        assert parsed.desktop_height == 720

    def test_serialize_size(self) -> None:
        cap = BitmapCapabilitySet()
        data = cap.serialize()
        # 11 x u16 + 2 x u8 = 24 bytes
        assert len(data) == 24


class TestOrderCapabilitySetRoundTrip:
    """Round-trip tests for OrderCapabilitySet."""

    def test_default_round_trip(self) -> None:
        cap = OrderCapabilitySet()
        data = cap.serialize()
        parsed = OrderCapabilitySet.parse(data)
        assert parsed == cap

    def test_order_support_array_32_bytes(self) -> None:
        """Verify the order support array is exactly 32 bytes (Req 14, AC 4)."""
        order_support = bytes(range(32))
        cap = OrderCapabilitySet(order_support=order_support)
        data = cap.serialize()
        parsed = OrderCapabilitySet.parse(data)
        assert parsed.order_support == order_support
        assert len(parsed.order_support) == 32

    def test_serialize_size(self) -> None:
        cap = OrderCapabilitySet()
        data = cap.serialize()
        # 16 + 4 + 2*6 + 32 + 2*4 + 4*2 + 2*4 = 88 bytes
        # terminal_descriptor(16) + pad4octetsA(4) + 6*u16(12) + orderSupport(32)
        # + 2*u16(4) + 2*u32(8) + 4*u16(8) = 84 bytes
        assert len(data) == 84


class TestInputCapabilitySetRoundTrip:
    """Round-trip tests for InputCapabilitySet."""

    def test_default_round_trip(self) -> None:
        cap = InputCapabilitySet()
        data = cap.serialize()
        parsed = InputCapabilitySet.parse(data)
        assert parsed == cap

    def test_with_flags(self) -> None:
        cap = InputCapabilitySet(
            input_flags=INPUT_FLAG_SCANCODES | INPUT_FLAG_FASTPATH_INPUT,
            keyboard_layout=0x00000409,
        )
        data = cap.serialize()
        parsed = InputCapabilitySet.parse(data)
        assert parsed.input_flags == INPUT_FLAG_SCANCODES | INPUT_FLAG_FASTPATH_INPUT
        assert parsed.keyboard_layout == 0x00000409

    def test_serialize_size(self) -> None:
        cap = InputCapabilitySet()
        data = cap.serialize()
        # 2*u16 + 4*u32 + 64 bytes = 4 + 16 + 64 = 84 bytes
        assert len(data) == 84


class TestPointerCapabilitySetRoundTrip:
    """Round-trip tests for PointerCapabilitySet."""

    def test_default_round_trip(self) -> None:
        cap = PointerCapabilitySet()
        data = cap.serialize()
        parsed = PointerCapabilitySet.parse(data)
        assert parsed == cap

    def test_without_pointer_cache_size(self) -> None:
        """Parse with only 4 bytes (no optional pointerCacheSize)."""
        data = struct.pack("<HH", 1, 20)
        parsed = PointerCapabilitySet.parse(data)
        assert parsed.color_pointer_flag == 1
        assert parsed.color_pointer_cache_size == 20
        assert parsed.pointer_cache_size == 0

    def test_serialize_size(self) -> None:
        cap = PointerCapabilitySet()
        data = cap.serialize()
        # 3 x u16 = 6 bytes
        assert len(data) == 6


class TestVirtualChannelCapabilitySetRoundTrip:
    """Round-trip tests for VirtualChannelCapabilitySet."""

    def test_default_round_trip(self) -> None:
        cap = VirtualChannelCapabilitySet()
        data = cap.serialize()
        parsed = VirtualChannelCapabilitySet.parse(data)
        assert parsed == cap

    def test_without_chunk_size(self) -> None:
        """Parse with only 4 bytes (no optional VCChunkSize)."""
        data = struct.pack("<I", VCCAPS_COMPR_CS_8K)
        parsed = VirtualChannelCapabilitySet.parse(data)
        assert parsed.flags == VCCAPS_COMPR_CS_8K
        assert parsed.vc_chunk_size == 1600  # default

    def test_serialize_size(self) -> None:
        cap = VirtualChannelCapabilitySet()
        data = cap.serialize()
        # u32 + u32 = 8 bytes
        assert len(data) == 8


class TestBitmapCodecsCapabilitySetRoundTrip:
    """Round-trip tests for BitmapCodecsCapabilitySet."""

    def test_empty_codecs_round_trip(self) -> None:
        cap = BitmapCodecsCapabilitySet(codecs=[])
        data = cap.serialize()
        parsed = BitmapCodecsCapabilitySet.parse(data)
        assert parsed == cap

    def test_with_nscodec_and_remotefx(self) -> None:
        """Verify RemoteFX and NSCodec entries round-trip (Req 16 AC 4, Req 17 AC 4)."""
        codecs = [
            BitmapCodecEntry(
                codec_guid=NSCODEC_GUID,
                codec_id=1,
                codec_properties=bytes([0x01, 0x01, 0x03]),
            ),
            BitmapCodecEntry(
                codec_guid=REMOTEFX_GUID,
                codec_id=3,
                codec_properties=b"",
            ),
        ]
        cap = BitmapCodecsCapabilitySet(codecs=codecs)
        data = cap.serialize()
        parsed = BitmapCodecsCapabilitySet.parse(data)
        assert len(parsed.codecs) == 2
        assert parsed.codecs[0].codec_guid == NSCODEC_GUID
        assert parsed.codecs[0].codec_id == 1
        assert parsed.codecs[0].codec_properties == bytes([0x01, 0x01, 0x03])
        assert parsed.codecs[1].codec_guid == REMOTEFX_GUID
        assert parsed.codecs[1].codec_id == 3
        assert parsed.codecs[1].codec_properties == b""


class TestDemandActivePduRoundTrip:
    """Round-trip tests for DemandActivePdu (Req 7, AC 1)."""

    def test_basic_round_trip(self) -> None:
        pdu = DemandActivePdu(
            share_id=0x00010001,
            source_descriptor=b"RDP\x00",
            capability_sets={
                CapabilitySetType.GENERAL: GeneralCapabilitySet(),
                CapabilitySetType.BITMAP: BitmapCapabilitySet(),
            },
        )
        data = pdu.serialize()
        parsed = DemandActivePdu.parse(data)
        assert parsed.share_id == pdu.share_id
        assert parsed.source_descriptor == pdu.source_descriptor
        assert CapabilitySetType.GENERAL in parsed.capability_sets
        assert CapabilitySetType.BITMAP in parsed.capability_sets

    def test_extracts_share_id(self) -> None:
        """Verify share ID is correctly extracted (Req 7, AC 1)."""
        pdu = DemandActivePdu(
            share_id=0xDEADBEEF,
            source_descriptor=b"TEST\x00",
            capability_sets={},
        )
        data = pdu.serialize()
        parsed = DemandActivePdu.parse(data)
        assert parsed.share_id == 0xDEADBEEF

    def test_all_capability_types(self) -> None:
        """Verify all capability set types are parsed from DemandActive."""
        pdu = DemandActivePdu(
            share_id=1,
            source_descriptor=b"\x00",
            capability_sets={
                CapabilitySetType.GENERAL: GeneralCapabilitySet(),
                CapabilitySetType.BITMAP: BitmapCapabilitySet(),
                CapabilitySetType.ORDER: OrderCapabilitySet(),
                CapabilitySetType.INPUT: InputCapabilitySet(),
                CapabilitySetType.POINTER: PointerCapabilitySet(),
                CapabilitySetType.VIRTUAL_CHANNEL: VirtualChannelCapabilitySet(),
                CapabilitySetType.BITMAP_CODECS: BitmapCodecsCapabilitySet(),
            },
        )
        data = pdu.serialize()
        parsed = DemandActivePdu.parse(data)
        assert len(parsed.capability_sets) == 7


class TestConfirmActivePduRoundTrip:
    """Round-trip tests for ConfirmActivePdu (Req 7, AC 2)."""

    def test_basic_round_trip(self) -> None:
        pdu = ConfirmActivePdu(
            share_id=0x00010001,
            originator_id=0x03EA,
            source_descriptor=b"MSTSC\x00",
            capability_sets={
                CapabilitySetType.GENERAL: GeneralCapabilitySet(
                    extra_flags=FASTPATH_OUTPUT_SUPPORTED,
                ),
            },
        )
        data = pdu.serialize()
        parsed = ConfirmActivePdu.parse(data)
        assert parsed.share_id == pdu.share_id
        assert parsed.originator_id == 0x03EA
        assert parsed.source_descriptor == b"MSTSC\x00"
        assert CapabilitySetType.GENERAL in parsed.capability_sets

    def test_serialize_encodes_all_caps(self) -> None:
        """Verify ConfirmActivePdu serializes all client capability sets (Req 7, AC 2)."""
        pdu = ConfirmActivePdu(
            share_id=42,
            capability_sets={
                CapabilitySetType.GENERAL: GeneralCapabilitySet(),
                CapabilitySetType.BITMAP: BitmapCapabilitySet(),
                CapabilitySetType.ORDER: OrderCapabilitySet(),
            },
        )
        data = pdu.serialize()
        parsed = ConfirmActivePdu.parse(data)
        assert len(parsed.capability_sets) == 3


class TestBuildClientCapabilities:
    """Tests for build_client_capabilities helper (Req 7, AC 4)."""

    def test_returns_all_required_types(self) -> None:
        """Verify all required capability types are present."""
        config = ClientCapabilitiesConfig()
        caps = build_client_capabilities({}, config)
        cap_types = [t for t, _ in caps]
        assert CapabilitySetType.GENERAL in cap_types
        assert CapabilitySetType.BITMAP in cap_types
        assert CapabilitySetType.ORDER in cap_types
        assert CapabilitySetType.INPUT in cap_types
        assert CapabilitySetType.POINTER in cap_types
        assert CapabilitySetType.VIRTUAL_CHANNEL in cap_types
        assert CapabilitySetType.BITMAP_CODECS in cap_types

    def test_general_has_fastpath_support(self) -> None:
        """Verify Fast-Path support is advertised in GeneralCapabilitySet (Req 7, AC 4)."""
        config = ClientCapabilitiesConfig()
        caps = build_client_capabilities({}, config)
        general = next(c for t, c in caps if t == CapabilitySetType.GENERAL)
        assert isinstance(general, GeneralCapabilitySet)
        assert general.extra_flags & FASTPATH_OUTPUT_SUPPORTED

    def test_bitmap_uses_config_resolution(self) -> None:
        """Verify bitmap capability uses config width/height/depth."""
        config = ClientCapabilitiesConfig(width=1280, height=720, color_depth=16)
        caps = build_client_capabilities({}, config)
        bitmap = next(c for t, c in caps if t == CapabilitySetType.BITMAP)
        assert isinstance(bitmap, BitmapCapabilitySet)
        assert bitmap.desktop_width == 1280
        assert bitmap.desktop_height == 720
        assert bitmap.preferred_bits_per_pixel == 16

    def test_order_has_32_byte_support_array(self) -> None:
        """Verify order support array is 32 bytes (Req 14, AC 4)."""
        config = ClientCapabilitiesConfig()
        caps = build_client_capabilities({}, config)
        order = next(c for t, c in caps if t == CapabilitySetType.ORDER)
        assert isinstance(order, OrderCapabilitySet)
        assert len(order.order_support) == 32
        # DstBlt should be enabled
        assert order.order_support[0] == 1

    def test_bitmap_codecs_has_remotefx_and_nscodec(self) -> None:
        """Verify RemoteFX and NSCodec entries (Req 16 AC 4, Req 17 AC 4)."""
        config = ClientCapabilitiesConfig()
        caps = build_client_capabilities({}, config)
        codecs_cap = next(c for t, c in caps if t == CapabilitySetType.BITMAP_CODECS)
        assert isinstance(codecs_cap, BitmapCodecsCapabilitySet)
        guids = [c.codec_guid for c in codecs_cap.codecs]
        assert NSCODEC_GUID in guids
        assert REMOTEFX_GUID in guids

    def test_input_has_fastpath_flags(self) -> None:
        """Verify input capability advertises fast-path input."""
        config = ClientCapabilitiesConfig()
        caps = build_client_capabilities({}, config)
        input_cap = next(c for t, c in caps if t == CapabilitySetType.INPUT)
        assert isinstance(input_cap, InputCapabilitySet)
        assert input_cap.input_flags & INPUT_FLAG_FASTPATH_INPUT
        assert input_cap.input_flags & INPUT_FLAG_FASTPATH_INPUT2

    def test_virtual_channel_chunk_size(self) -> None:
        """Verify virtual channel has proper chunk size."""
        config = ClientCapabilitiesConfig()
        caps = build_client_capabilities({}, config)
        vc = next(c for t, c in caps if t == CapabilitySetType.VIRTUAL_CHANNEL)
        assert isinstance(vc, VirtualChannelCapabilitySet)
        assert vc.vc_chunk_size == 1600

    def test_all_caps_round_trip(self) -> None:
        """Verify all built capabilities can be serialized and parsed back."""
        config = ClientCapabilitiesConfig()
        caps = build_client_capabilities({}, config)
        for cap_type, cap in caps:
            data = cap.serialize()
            parser_cls = type(cap)
            parsed = parser_cls.parse(data)
            assert parsed == cap
