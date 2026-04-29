"""Capability set PDUs for RDP capability exchange.

Implements capability set types per [MS-RDPBCGR] Section 2.2.7:
- GeneralCapabilitySet (2.2.7.1.1)
- BitmapCapabilitySet (2.2.7.1.2)
- OrderCapabilitySet (2.2.7.1.3)
- InputCapabilitySet (2.2.7.1.6)
- PointerCapabilitySet (2.2.7.1.5)
- VirtualChannelCapabilitySet (2.2.7.1.10)
- BitmapCodecsCapabilitySet (2.2.7.2.10)
- DemandActivePdu (2.2.1.13.1)
- ConfirmActivePdu (2.2.1.13.2)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Self

from arrdipi.errors import PduParseError
from arrdipi.pdu.base import ByteReader, ByteWriter, Pdu
from arrdipi.pdu.types import CapabilitySetType


# --- Extra flags for GeneralCapabilitySet ---
FASTPATH_OUTPUT_SUPPORTED = 0x0001
LONG_CREDENTIALS_SUPPORTED = 0x0004
AUTORECONNECT_SUPPORTED = 0x0008
ENC_SALTED_CHECKSUM = 0x0010
NO_BITMAP_COMPRESSION_HDR = 0x0400

# --- Input flags ---
INPUT_FLAG_SCANCODES = 0x0001
INPUT_FLAG_MOUSEX = 0x0004
INPUT_FLAG_FASTPATH_INPUT = 0x0008
INPUT_FLAG_UNICODE = 0x0010
INPUT_FLAG_FASTPATH_INPUT2 = 0x0020
INPUT_FLAG_UNUSED1 = 0x0040
INPUT_FLAG_MOUSE_HWHEEL = 0x0100
INPUT_FLAG_QOE_TIMESTAMPS = 0x0200

# --- Virtual channel flags ---
VCCAPS_COMPR_SC = 0x00000001
VCCAPS_COMPR_CS_8K = 0x00000002

# --- Codec GUIDs ---
NSCODEC_GUID = bytes([
    0xB9, 0x1B, 0x8D, 0xCA, 0x0F, 0x00, 0x4F, 0x15,
    0x58, 0x9F, 0xAE, 0x2D, 0x1A, 0x87, 0xE2, 0xD6,
])
REMOTEFX_GUID = bytes([
    0x12, 0x2F, 0x77, 0x76, 0x72, 0xBD, 0x63, 0x44,
    0xAF, 0xB3, 0xB7, 0x3C, 0x9C, 0x6F, 0x78, 0x86,
])

# AVC420 (H.264) codec GUID for GFX pipeline (Req 18, AC 6)
AVC420_GUID = bytes([
    0x64, 0xCC, 0xD4, 0xE3, 0x7C, 0x2A, 0x86, 0x4F,
    0x99, 0x61, 0x7C, 0x28, 0x63, 0x44, 0xB9, 0xAA,
])

# AVC444 (H.264) codec GUID for GFX pipeline (Req 18, AC 6)
AVC444_GUID = bytes([
    0xAE, 0x01, 0x5C, 0xA1, 0xB4, 0x94, 0xD4, 0x4B,
    0xA5, 0x8C, 0x7B, 0xEE, 0x22, 0x15, 0xF6, 0x3C,
])

# Capability set header size (type u16 + length u16)
_CAP_HEADER_SIZE = 4


@dataclass
class GeneralCapabilitySet(Pdu):
    """General Capability Set [MS-RDPBCGR] 2.2.7.1.1.

    Type: CAPSTYPE_GENERAL (0x0001)
    """

    os_major_type: int = 1  # OSMAJORTYPE_WINDOWS
    os_minor_type: int = 3  # OSMINORTYPE_WINDOWS_NT
    protocol_version: int = 0x0200
    pad2octets_a: int = 0
    general_compression_types: int = 0
    extra_flags: int = 0
    update_capability_flag: int = 0
    remote_unshare_flag: int = 0
    general_compression_level: int = 0
    refresh_rect_support: int = 0
    suppress_output_support: int = 0

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse GeneralCapabilitySet from payload (after capability header)."""
        reader = ByteReader(data, pdu_type="GeneralCapabilitySet")
        return cls(
            os_major_type=reader.read_u16_le(),
            os_minor_type=reader.read_u16_le(),
            protocol_version=reader.read_u16_le(),
            pad2octets_a=reader.read_u16_le(),
            general_compression_types=reader.read_u16_le(),
            extra_flags=reader.read_u16_le(),
            update_capability_flag=reader.read_u16_le(),
            remote_unshare_flag=reader.read_u16_le(),
            general_compression_level=reader.read_u16_le(),
            refresh_rect_support=reader.read_u8(),
            suppress_output_support=reader.read_u8(),
        )

    def serialize(self) -> bytes:
        """Serialize GeneralCapabilitySet to payload bytes (without header)."""
        writer = ByteWriter()
        writer.write_u16_le(self.os_major_type)
        writer.write_u16_le(self.os_minor_type)
        writer.write_u16_le(self.protocol_version)
        writer.write_u16_le(self.pad2octets_a)
        writer.write_u16_le(self.general_compression_types)
        writer.write_u16_le(self.extra_flags)
        writer.write_u16_le(self.update_capability_flag)
        writer.write_u16_le(self.remote_unshare_flag)
        writer.write_u16_le(self.general_compression_level)
        writer.write_u8(self.refresh_rect_support)
        writer.write_u8(self.suppress_output_support)
        return writer.to_bytes()


@dataclass
class BitmapCapabilitySet(Pdu):
    """Bitmap Capability Set [MS-RDPBCGR] 2.2.7.1.2.

    Type: CAPSTYPE_BITMAP (0x0002)
    """

    preferred_bits_per_pixel: int = 32
    receive_1bit_per_pixel: int = 1
    receive_4bits_per_pixel: int = 1
    receive_8bits_per_pixel: int = 1
    desktop_width: int = 1920
    desktop_height: int = 1080
    pad2octets: int = 0
    desktop_resize_flag: int = 1
    bitmap_compression_flag: int = 1
    high_color_flags: int = 0
    drawing_flags: int = 0
    multiple_rectangle_support: int = 1
    pad2octets_b: int = 0

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse BitmapCapabilitySet from payload (after capability header)."""
        reader = ByteReader(data, pdu_type="BitmapCapabilitySet")
        return cls(
            preferred_bits_per_pixel=reader.read_u16_le(),
            receive_1bit_per_pixel=reader.read_u16_le(),
            receive_4bits_per_pixel=reader.read_u16_le(),
            receive_8bits_per_pixel=reader.read_u16_le(),
            desktop_width=reader.read_u16_le(),
            desktop_height=reader.read_u16_le(),
            pad2octets=reader.read_u16_le(),
            desktop_resize_flag=reader.read_u16_le(),
            bitmap_compression_flag=reader.read_u16_le(),
            high_color_flags=reader.read_u8(),
            drawing_flags=reader.read_u8(),
            multiple_rectangle_support=reader.read_u16_le(),
            pad2octets_b=reader.read_u16_le(),
        )

    def serialize(self) -> bytes:
        """Serialize BitmapCapabilitySet to payload bytes (without header)."""
        writer = ByteWriter()
        writer.write_u16_le(self.preferred_bits_per_pixel)
        writer.write_u16_le(self.receive_1bit_per_pixel)
        writer.write_u16_le(self.receive_4bits_per_pixel)
        writer.write_u16_le(self.receive_8bits_per_pixel)
        writer.write_u16_le(self.desktop_width)
        writer.write_u16_le(self.desktop_height)
        writer.write_u16_le(self.pad2octets)
        writer.write_u16_le(self.desktop_resize_flag)
        writer.write_u16_le(self.bitmap_compression_flag)
        writer.write_u8(self.high_color_flags)
        writer.write_u8(self.drawing_flags)
        writer.write_u16_le(self.multiple_rectangle_support)
        writer.write_u16_le(self.pad2octets_b)
        return writer.to_bytes()


@dataclass
class OrderCapabilitySet(Pdu):
    """Order Capability Set [MS-RDPBCGR] 2.2.7.1.3.

    Type: CAPSTYPE_ORDER (0x0003)
    Includes the 32-byte order support array for GDI orders (Req 14, AC 4).
    """

    terminal_descriptor: bytes = field(default_factory=lambda: b"\x00" * 16)
    pad4octets_a: int = 0
    desktop_save_x_granularity: int = 1
    desktop_save_y_granularity: int = 20
    pad2octets_a: int = 0
    maximum_order_level: int = 1
    number_fonts: int = 0
    order_flags: int = 0x0022  # NEGOTIATEORDERSUPPORT | ZEROBOUNDSDELTASSUPPORT
    order_support: bytes = field(default_factory=lambda: b"\x00" * 32)
    text_flags: int = 0
    order_support_ex_flags: int = 0
    pad4octets_b: int = 0
    desktop_save_size: int = 480 * 480
    pad2octets_c: int = 0
    pad2octets_d: int = 0
    text_ansi_code_page: int = 0
    pad2octets_e: int = 0

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse OrderCapabilitySet from payload (after capability header)."""
        reader = ByteReader(data, pdu_type="OrderCapabilitySet")
        return cls(
            terminal_descriptor=reader.read_bytes(16),
            pad4octets_a=reader.read_u32_le(),
            desktop_save_x_granularity=reader.read_u16_le(),
            desktop_save_y_granularity=reader.read_u16_le(),
            pad2octets_a=reader.read_u16_le(),
            maximum_order_level=reader.read_u16_le(),
            number_fonts=reader.read_u16_le(),
            order_flags=reader.read_u16_le(),
            order_support=reader.read_bytes(32),
            text_flags=reader.read_u16_le(),
            order_support_ex_flags=reader.read_u16_le(),
            pad4octets_b=reader.read_u32_le(),
            desktop_save_size=reader.read_u32_le(),
            pad2octets_c=reader.read_u16_le(),
            pad2octets_d=reader.read_u16_le(),
            text_ansi_code_page=reader.read_u16_le(),
            pad2octets_e=reader.read_u16_le(),
        )

    def serialize(self) -> bytes:
        """Serialize OrderCapabilitySet to payload bytes (without header)."""
        writer = ByteWriter()
        writer.write_bytes(self.terminal_descriptor)
        writer.write_u32_le(self.pad4octets_a)
        writer.write_u16_le(self.desktop_save_x_granularity)
        writer.write_u16_le(self.desktop_save_y_granularity)
        writer.write_u16_le(self.pad2octets_a)
        writer.write_u16_le(self.maximum_order_level)
        writer.write_u16_le(self.number_fonts)
        writer.write_u16_le(self.order_flags)
        writer.write_bytes(self.order_support)
        writer.write_u16_le(self.text_flags)
        writer.write_u16_le(self.order_support_ex_flags)
        writer.write_u32_le(self.pad4octets_b)
        writer.write_u32_le(self.desktop_save_size)
        writer.write_u16_le(self.pad2octets_c)
        writer.write_u16_le(self.pad2octets_d)
        writer.write_u16_le(self.text_ansi_code_page)
        writer.write_u16_le(self.pad2octets_e)
        return writer.to_bytes()


@dataclass
class InputCapabilitySet(Pdu):
    """Input Capability Set [MS-RDPBCGR] 2.2.7.1.6.

    Type: CAPSTYPE_INPUT (0x000D)
    """

    input_flags: int = 0
    pad2octets_a: int = 0
    keyboard_layout: int = 0
    keyboard_type: int = 4  # IBM enhanced (101/102-key)
    keyboard_sub_type: int = 0
    keyboard_function_key: int = 12
    ime_file_name: bytes = field(default_factory=lambda: b"\x00" * 64)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse InputCapabilitySet from payload (after capability header)."""
        reader = ByteReader(data, pdu_type="InputCapabilitySet")
        return cls(
            input_flags=reader.read_u16_le(),
            pad2octets_a=reader.read_u16_le(),
            keyboard_layout=reader.read_u32_le(),
            keyboard_type=reader.read_u32_le(),
            keyboard_sub_type=reader.read_u32_le(),
            keyboard_function_key=reader.read_u32_le(),
            ime_file_name=reader.read_bytes(64),
        )

    def serialize(self) -> bytes:
        """Serialize InputCapabilitySet to payload bytes (without header)."""
        writer = ByteWriter()
        writer.write_u16_le(self.input_flags)
        writer.write_u16_le(self.pad2octets_a)
        writer.write_u32_le(self.keyboard_layout)
        writer.write_u32_le(self.keyboard_type)
        writer.write_u32_le(self.keyboard_sub_type)
        writer.write_u32_le(self.keyboard_function_key)
        writer.write_bytes(self.ime_file_name)
        return writer.to_bytes()


@dataclass
class PointerCapabilitySet(Pdu):
    """Pointer Capability Set [MS-RDPBCGR] 2.2.7.1.5.

    Type: CAPSTYPE_POINTER (0x0008)
    """

    color_pointer_flag: int = 1
    color_pointer_cache_size: int = 25
    pointer_cache_size: int = 25

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse PointerCapabilitySet from payload (after capability header)."""
        reader = ByteReader(data, pdu_type="PointerCapabilitySet")
        color_pointer_flag = reader.read_u16_le()
        color_pointer_cache_size = reader.read_u16_le()
        # pointerCacheSize is optional
        pointer_cache_size = 0
        if reader.remaining() >= 2:
            pointer_cache_size = reader.read_u16_le()
        return cls(
            color_pointer_flag=color_pointer_flag,
            color_pointer_cache_size=color_pointer_cache_size,
            pointer_cache_size=pointer_cache_size,
        )

    def serialize(self) -> bytes:
        """Serialize PointerCapabilitySet to payload bytes (without header)."""
        writer = ByteWriter()
        writer.write_u16_le(self.color_pointer_flag)
        writer.write_u16_le(self.color_pointer_cache_size)
        writer.write_u16_le(self.pointer_cache_size)
        return writer.to_bytes()


@dataclass
class VirtualChannelCapabilitySet(Pdu):
    """Virtual Channel Capability Set [MS-RDPBCGR] 2.2.7.1.10.

    Type: CAPSTYPE_VIRTUALCHANNEL (0x0014)
    """

    flags: int = 0
    vc_chunk_size: int = 1600

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse VirtualChannelCapabilitySet from payload (after capability header)."""
        reader = ByteReader(data, pdu_type="VirtualChannelCapabilitySet")
        flags = reader.read_u32_le()
        # VCChunkSize is optional
        vc_chunk_size = 1600
        if reader.remaining() >= 4:
            vc_chunk_size = reader.read_u32_le()
        return cls(flags=flags, vc_chunk_size=vc_chunk_size)

    def serialize(self) -> bytes:
        """Serialize VirtualChannelCapabilitySet to payload bytes (without header)."""
        writer = ByteWriter()
        writer.write_u32_le(self.flags)
        writer.write_u32_le(self.vc_chunk_size)
        return writer.to_bytes()


@dataclass
class BitmapCodecEntry:
    """A single bitmap codec entry within BitmapCodecsCapabilitySet."""

    codec_guid: bytes  # 16 bytes
    codec_id: int  # u8
    codec_properties: bytes = b""

    @classmethod
    def parse(cls, reader: ByteReader) -> Self:
        """Parse a single codec entry from the reader."""
        codec_guid = reader.read_bytes(16)
        codec_id = reader.read_u8()
        codec_properties_length = reader.read_u16_le()
        codec_properties = reader.read_bytes(codec_properties_length)
        return cls(
            codec_guid=codec_guid,
            codec_id=codec_id,
            codec_properties=codec_properties,
        )

    def serialize(self) -> bytes:
        """Serialize a single codec entry."""
        writer = ByteWriter()
        writer.write_bytes(self.codec_guid)
        writer.write_u8(self.codec_id)
        writer.write_u16_le(len(self.codec_properties))
        writer.write_bytes(self.codec_properties)
        return writer.to_bytes()


@dataclass
class BitmapCodecsCapabilitySet(Pdu):
    """Bitmap Codecs Capability Set [MS-RDPBCGR] 2.2.7.2.10.

    Type: CAPSTYPE_BITMAP_CODECS (0x001D)
    Includes RemoteFX and NSCodec entries (Req 16 AC 4, Req 17 AC 4).
    """

    codecs: list[BitmapCodecEntry] = field(default_factory=list)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse BitmapCodecsCapabilitySet from payload (after capability header)."""
        reader = ByteReader(data, pdu_type="BitmapCodecsCapabilitySet")
        bitmap_codec_count = reader.read_u8()
        codecs: list[BitmapCodecEntry] = []
        for _ in range(bitmap_codec_count):
            codecs.append(BitmapCodecEntry.parse(reader))
        return cls(codecs=codecs)

    def serialize(self) -> bytes:
        """Serialize BitmapCodecsCapabilitySet to payload bytes (without header)."""
        writer = ByteWriter()
        writer.write_u8(len(self.codecs))
        for codec in self.codecs:
            writer.write_bytes(codec.serialize())
        return writer.to_bytes()


# --- Mapping from CapabilitySetType to parser class ---
_CAPABILITY_PARSERS: dict[CapabilitySetType, type[Pdu]] = {
    CapabilitySetType.GENERAL: GeneralCapabilitySet,
    CapabilitySetType.BITMAP: BitmapCapabilitySet,
    CapabilitySetType.ORDER: OrderCapabilitySet,
    CapabilitySetType.INPUT: InputCapabilitySet,
    CapabilitySetType.POINTER: PointerCapabilitySet,
    CapabilitySetType.VIRTUAL_CHANNEL: VirtualChannelCapabilitySet,
    CapabilitySetType.BITMAP_CODECS: BitmapCodecsCapabilitySet,
}


def _parse_capability_sets(data: bytes, count: int) -> dict[CapabilitySetType, Pdu]:
    """Parse a sequence of capability sets from raw bytes.

    Returns a dict mapping capability set type to parsed capability set object.
    Unknown capability types are silently skipped.
    """
    reader = ByteReader(data, pdu_type="CapabilitySets")
    caps: dict[CapabilitySetType, Pdu] = {}
    for _ in range(count):
        cap_type_raw = reader.read_u16_le()
        length_capability = reader.read_u16_le()
        # Payload length is total length minus the 4-byte header
        payload_length = length_capability - _CAP_HEADER_SIZE
        if payload_length < 0:
            raise PduParseError(
                pdu_type="CapabilitySet",
                offset=reader.offset,
                description=f"invalid capability length {length_capability}",
            )
        payload = reader.read_bytes(payload_length)

        try:
            cap_type = CapabilitySetType(cap_type_raw)
        except ValueError:
            # Unknown capability type — skip
            continue

        parser = _CAPABILITY_PARSERS.get(cap_type)
        if parser is not None:
            caps[cap_type] = parser.parse(payload)

    return caps


def _serialize_capability_set(cap_type: CapabilitySetType, cap: Pdu) -> bytes:
    """Serialize a single capability set with its header."""
    payload = cap.serialize()
    writer = ByteWriter()
    writer.write_u16_le(int(cap_type))
    writer.write_u16_le(len(payload) + _CAP_HEADER_SIZE)
    writer.write_bytes(payload)
    return writer.to_bytes()


@dataclass
class DemandActivePdu(Pdu):
    """Demand Active PDU [MS-RDPBCGR] 2.2.1.13.1.

    Sent by the server to initiate capability exchange (Req 7, AC 1).
    """

    share_id: int = 0
    source_descriptor: bytes = b""
    capability_sets: dict[CapabilitySetType, Pdu] = field(default_factory=dict)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse DemandActivePdu from binary data.

        Extracts share ID and all server capability sets.
        """
        reader = ByteReader(data, pdu_type="DemandActivePdu")
        share_id = reader.read_u32_le()
        length_source_descriptor = reader.read_u16_le()
        length_combined_capabilities = reader.read_u16_le()
        source_descriptor = reader.read_bytes(length_source_descriptor)
        number_capabilities = reader.read_u16_le()
        _pad2octets = reader.read_u16_le()

        # Read the combined capabilities block
        caps_data = reader.read_bytes(length_combined_capabilities - 4)  # subtract numberCaps + pad
        capability_sets = _parse_capability_sets(caps_data, number_capabilities)

        return cls(
            share_id=share_id,
            source_descriptor=source_descriptor,
            capability_sets=capability_sets,
        )

    def serialize(self) -> bytes:
        """Serialize DemandActivePdu to binary wire format."""
        # Serialize all capability sets
        caps_data = bytearray()
        for cap_type, cap in self.capability_sets.items():
            caps_data.extend(_serialize_capability_set(cap_type, cap))

        writer = ByteWriter()
        writer.write_u32_le(self.share_id)
        writer.write_u16_le(len(self.source_descriptor))
        # lengthCombinedCapabilities includes numberCapabilities (u16) + pad2octets (u16) + caps data
        writer.write_u16_le(len(caps_data) + 4)
        writer.write_bytes(self.source_descriptor)
        writer.write_u16_le(len(self.capability_sets))
        writer.write_u16_le(0)  # pad2octets
        writer.write_bytes(bytes(caps_data))
        return writer.to_bytes()


@dataclass
class ConfirmActivePdu(Pdu):
    """Confirm Active PDU [MS-RDPBCGR] 2.2.1.13.2.

    Sent by the client to confirm capability exchange (Req 7, AC 2).
    """

    share_id: int = 0
    originator_id: int = 0x03EA
    source_descriptor: bytes = b"MSTSC\x00"
    capability_sets: dict[CapabilitySetType, Pdu] = field(default_factory=dict)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse ConfirmActivePdu from binary data."""
        reader = ByteReader(data, pdu_type="ConfirmActivePdu")
        share_id = reader.read_u32_le()
        originator_id = reader.read_u16_le()
        length_source_descriptor = reader.read_u16_le()
        length_combined_capabilities = reader.read_u16_le()
        source_descriptor = reader.read_bytes(length_source_descriptor)
        number_capabilities = reader.read_u16_le()
        _pad2octets = reader.read_u16_le()

        # Read the combined capabilities block
        caps_data = reader.read_bytes(length_combined_capabilities - 4)
        capability_sets = _parse_capability_sets(caps_data, number_capabilities)

        return cls(
            share_id=share_id,
            originator_id=originator_id,
            source_descriptor=source_descriptor,
            capability_sets=capability_sets,
        )

    def serialize(self) -> bytes:
        """Serialize ConfirmActivePdu to binary wire format (Req 7, AC 2)."""
        # Serialize all capability sets
        caps_data = bytearray()
        for cap_type, cap in self.capability_sets.items():
            caps_data.extend(_serialize_capability_set(cap_type, cap))

        writer = ByteWriter()
        writer.write_u32_le(self.share_id)
        writer.write_u16_le(self.originator_id)
        writer.write_u16_le(len(self.source_descriptor))
        # lengthCombinedCapabilities includes numberCapabilities (u16) + pad2octets (u16) + caps data
        writer.write_u16_le(len(caps_data) + 4)
        writer.write_bytes(self.source_descriptor)
        writer.write_u16_le(len(self.capability_sets))
        writer.write_u16_le(0)  # pad2octets
        writer.write_bytes(bytes(caps_data))
        return writer.to_bytes()


@dataclass
class ClientCapabilitiesConfig:
    """Configuration for building client capabilities."""

    width: int = 1920
    height: int = 1080
    color_depth: int = 32
    keyboard_layout: int = 0x00000409  # US English
    keyboard_type: int = 4  # IBM enhanced (101/102-key)
    keyboard_sub_type: int = 0
    keyboard_function_key: int = 12


def build_client_capabilities(
    server_caps: dict[CapabilitySetType, Pdu],
    config: ClientCapabilitiesConfig,
) -> list[tuple[CapabilitySetType, Pdu]]:
    """Build the client capability set list for the Confirm Active PDU.

    Advertises Fast-Path support in GeneralCapabilitySet (Req 7, AC 4).
    Includes Order support array for GDI orders (Req 14, AC 4).
    Includes RemoteFX and NSCodec in BitmapCodecs (Req 16 AC 4, Req 17 AC 4).

    Args:
        server_caps: Parsed server capability sets from DemandActivePdu.
        config: Client configuration for resolution, color depth, etc.

    Returns:
        List of (CapabilitySetType, capability_set) tuples for ConfirmActivePdu.
    """
    caps: list[tuple[CapabilitySetType, Pdu]] = []

    # General capability set with Fast-Path support advertised
    general = GeneralCapabilitySet(
        os_major_type=1,  # OSMAJORTYPE_WINDOWS
        os_minor_type=3,  # OSMINORTYPE_WINDOWS_NT
        protocol_version=0x0200,
        extra_flags=(
            FASTPATH_OUTPUT_SUPPORTED
            | LONG_CREDENTIALS_SUPPORTED
            | NO_BITMAP_COMPRESSION_HDR
            | ENC_SALTED_CHECKSUM
            | AUTORECONNECT_SUPPORTED
        ),
        refresh_rect_support=1,
        suppress_output_support=1,
    )
    caps.append((CapabilitySetType.GENERAL, general))

    # Bitmap capability set
    bitmap = BitmapCapabilitySet(
        preferred_bits_per_pixel=config.color_depth,
        desktop_width=config.width,
        desktop_height=config.height,
        desktop_resize_flag=1,
        bitmap_compression_flag=1,
        multiple_rectangle_support=1,
    )
    caps.append((CapabilitySetType.BITMAP, bitmap))

    # Order capability set with 32-byte order support array (Req 14, AC 4)
    # Enable common drawing orders
    order_support = bytearray(32)
    # DstBlt (index 0)
    order_support[0] = 1
    # PatBlt (index 1)
    order_support[1] = 1
    # ScrBlt (index 2)
    order_support[2] = 1
    # MemBlt (index 3)
    order_support[3] = 1
    # Mem3Blt (index 4)
    order_support[4] = 1
    # LineTo (index 8)
    order_support[8] = 1
    # SaveBitmap (index 11)
    order_support[11] = 1
    # MultiDstBlt (index 15)
    order_support[15] = 1
    # MultiPatBlt (index 16)
    order_support[16] = 1
    # MultiScrBlt (index 17)
    order_support[17] = 1
    # MultiOpaqueRect (index 18)
    order_support[18] = 1
    # GlyphIndex (index 27)
    order_support[27] = 1

    order = OrderCapabilitySet(
        order_flags=0x0022,  # NEGOTIATEORDERSUPPORT | ZEROBOUNDSDELTASSUPPORT
        order_support=bytes(order_support),
        desktop_save_size=480 * 480,
    )
    caps.append((CapabilitySetType.ORDER, order))

    # Input capability set with fast-path input support
    input_cap = InputCapabilitySet(
        input_flags=(
            INPUT_FLAG_SCANCODES
            | INPUT_FLAG_MOUSEX
            | INPUT_FLAG_FASTPATH_INPUT
            | INPUT_FLAG_UNICODE
            | INPUT_FLAG_FASTPATH_INPUT2
            | INPUT_FLAG_MOUSE_HWHEEL
        ),
        keyboard_layout=config.keyboard_layout,
        keyboard_type=config.keyboard_type,
        keyboard_sub_type=config.keyboard_sub_type,
        keyboard_function_key=config.keyboard_function_key,
    )
    caps.append((CapabilitySetType.INPUT, input_cap))

    # Pointer capability set
    pointer = PointerCapabilitySet(
        color_pointer_flag=1,
        color_pointer_cache_size=25,
        pointer_cache_size=25,
    )
    caps.append((CapabilitySetType.POINTER, pointer))

    # Virtual channel capability set
    virtual_channel = VirtualChannelCapabilitySet(
        flags=VCCAPS_COMPR_CS_8K,
        vc_chunk_size=1600,
    )
    caps.append((CapabilitySetType.VIRTUAL_CHANNEL, virtual_channel))

    # Bitmap codecs capability set with RemoteFX, NSCodec, AVC420, AVC444 (Req 16 AC 4, Req 17 AC 4, Req 18 AC 6)
    codecs = [
        BitmapCodecEntry(
            codec_guid=NSCODEC_GUID,
            codec_id=1,
            codec_properties=bytes([0x01, 0x01, 0x03]),  # dynamic fidelity, subsampling, color loss level
        ),
        BitmapCodecEntry(
            codec_guid=REMOTEFX_GUID,
            codec_id=3,
            codec_properties=b"",
        ),
        BitmapCodecEntry(
            codec_guid=AVC420_GUID,
            codec_id=4,
            codec_properties=b"",
        ),
        BitmapCodecEntry(
            codec_guid=AVC444_GUID,
            codec_id=5,
            codec_properties=b"",
        ),
    ]
    bitmap_codecs = BitmapCodecsCapabilitySet(codecs=codecs)
    caps.append((CapabilitySetType.BITMAP_CODECS, bitmap_codecs))

    return caps
