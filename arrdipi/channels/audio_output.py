"""Audio output channel (RDPSND).

Implements [MS-RDPEA] — Remote Desktop Protocol Audio Output Virtual Channel Extension.
Operates over the "rdpsnd" static virtual channel.

The audio output channel handles:
- Server Audio Formats and Version exchange
- Wave/Wave2 audio data playback
- Wave Confirm acknowledgment

Requirements addressed: Req 23 (AC 1–5)
"""

from __future__ import annotations

import struct
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Self

# RDPSND message types
SNDC_FORMATS = 0x07  # Server Audio Formats and Version
SNDC_TRAINING = 0x06  # Training
SNDC_TRAININGCONFIRM = 0x06  # Training Confirm (same as training)
SNDC_WAVE = 0x02  # Wave
SNDC_WAVE2 = 0x0D  # Wave2
SNDC_CLOSE = 0x01  # Close
SNDC_SETVOLUME = 0x03  # Set Volume
SNDC_SETPITCH = 0x04  # Set Pitch
SNDC_QUALITYMODE = 0x0C  # Quality Mode

# Client message types
CYCLIC_WAVE_CONFIRM = 0x05  # Wave Confirm

# Audio format tags
WAVE_FORMAT_PCM = 0x0001

# Common sample rates
SAMPLE_RATE_44100 = 44100
SAMPLE_RATE_22050 = 22050
SAMPLE_RATE_11025 = 11025

# RDPSND PDU header size
RDPSND_HEADER_SIZE = 4  # msgType(u8) + pad(u8) + bodySize(u16)


@dataclass
class AudioFormat:
    """An audio format descriptor per [MS-RDPEA] 2.2.2.1.1."""

    format_tag: int
    channels: int
    samples_per_sec: int
    avg_bytes_per_sec: int
    block_align: int
    bits_per_sample: int
    extra_data: bytes = b""

    def serialize(self) -> bytes:
        """Serialize to wire format."""
        header = struct.pack(
            "<HHIIHHH",
            self.format_tag,
            self.channels,
            self.samples_per_sec,
            self.avg_bytes_per_sec,
            self.block_align,
            self.bits_per_sample,
            len(self.extra_data),
        )
        return header + self.extra_data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> tuple[Self, int]:
        """Parse an audio format from data at the given offset.

        Returns:
            Tuple of (AudioFormat, bytes consumed).
        """
        if len(data) < offset + 18:
            raise ValueError("Insufficient data for AudioFormat")

        (
            format_tag,
            channels,
            samples_per_sec,
            avg_bytes_per_sec,
            block_align,
            bits_per_sample,
            cb_size,
        ) = struct.unpack_from("<HHIIHHH", data, offset)

        extra_start = offset + 18
        extra_data = data[extra_start : extra_start + cb_size]
        total_consumed = 18 + cb_size

        return cls(
            format_tag=format_tag,
            channels=channels,
            samples_per_sec=samples_per_sec,
            avg_bytes_per_sec=avg_bytes_per_sec,
            block_align=block_align,
            bits_per_sample=bits_per_sample,
            extra_data=extra_data,
        ), total_consumed


@dataclass
class ServerAudioFormatsPdu:
    """Server Audio Formats and Version PDU [MS-RDPEA] 2.2.2.1.

    Sent by the server to announce supported audio formats.
    """

    version: int = 0x06
    formats: list[AudioFormat] = field(default_factory=list)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse from raw RDPSND message body (after header)."""
        if len(data) < 20:
            return cls()

        # dwFlags(u32) + dwVolume(u32) + dwPitch(u32) + wDGramPort(u16) +
        # wNumberOfFormats(u16) + cLastBlockConfirmed(u8) + wVersion(u16) + bPad(u8)
        _dw_flags = struct.unpack_from("<I", data, 0)[0]
        _dw_volume = struct.unpack_from("<I", data, 4)[0]
        _dw_pitch = struct.unpack_from("<I", data, 8)[0]
        _w_dgram_port = struct.unpack_from("<H", data, 12)[0]
        w_number_of_formats = struct.unpack_from("<H", data, 14)[0]
        _c_last_block_confirmed = data[16]
        w_version = struct.unpack_from("<H", data, 17)[0]
        # bPad at offset 19

        formats: list[AudioFormat] = []
        offset = 20
        for _ in range(w_number_of_formats):
            if offset >= len(data):
                break
            fmt, consumed = AudioFormat.parse(data, offset)
            formats.append(fmt)
            offset += consumed

        return cls(version=w_version, formats=formats)

    def serialize(self) -> bytes:
        """Serialize to wire format."""
        formats_data = b"".join(f.serialize() for f in self.formats)
        body = struct.pack(
            "<IIIHH",
            0,  # dwFlags
            0xFFFFFFFF,  # dwVolume (max)
            0,  # dwPitch
            0,  # wDGramPort
            len(self.formats),  # wNumberOfFormats
        )
        body += struct.pack("<BHB", 0, self.version, 0)  # cLastBlockConfirmed, wVersion, bPad
        body += formats_data
        return body


@dataclass
class ClientAudioFormatsPdu:
    """Client Audio Formats and Version PDU [MS-RDPEA] 2.2.2.2.

    Sent by the client to respond with supported formats.
    """

    version: int = 0x06
    formats: list[AudioFormat] = field(default_factory=list)

    def serialize(self) -> bytes:
        """Serialize to wire format (header + body)."""
        formats_data = b"".join(f.serialize() for f in self.formats)
        body = struct.pack(
            "<IIIHH",
            0,  # dwFlags
            0xFFFFFFFF,  # dwVolume
            0,  # dwPitch
            0,  # wDGramPort
            len(self.formats),  # wNumberOfFormats
        )
        body += struct.pack("<BHB", 0, self.version, 0)  # cLastBlockConfirmed, wVersion, bPad
        body += formats_data

        # RDPSND header: msgType(u8) + pad(u8) + bodySize(u16)
        header = struct.pack("<BBH", SNDC_FORMATS, 0, len(body))
        return header + body


@dataclass
class WavePdu:
    """Wave PDU [MS-RDPEA] 2.2.3.3.

    Contains audio data to be played.
    """

    timestamp: int
    block_no: int
    audio_data: bytes = b""

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse from raw RDPSND message body (after header)."""
        if len(data) < 8:
            return cls(timestamp=0, block_no=0)

        # wTimeStamp(u16) + wFormatNo(u16) + cBlockNo(u8) + bPad(u8*3)
        timestamp = struct.unpack_from("<H", data, 0)[0]
        _format_no = struct.unpack_from("<H", data, 2)[0]
        block_no = data[4]
        # bPad: 3 bytes at offset 5
        # The first 4 bytes of audio data are embedded in the header padding
        # Remaining audio data follows
        audio_data = data[8:]
        return cls(timestamp=timestamp, block_no=block_no, audio_data=audio_data)

    def serialize(self) -> bytes:
        """Serialize to wire format."""
        body = struct.pack("<HHB", self.timestamp, 0, self.block_no)
        body += b"\x00" * 3  # bPad
        body += self.audio_data
        return body


@dataclass
class Wave2Pdu:
    """Wave2 PDU [MS-RDPEA] 2.2.3.8.

    Enhanced wave PDU with format index and audio data.
    """

    timestamp: int
    format_no: int
    block_no: int
    audio_data: bytes = b""

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse from raw RDPSND message body (after header)."""
        if len(data) < 12:
            return cls(timestamp=0, format_no=0, block_no=0)

        # wTimeStamp(u16) + wFormatNo(u16) + cBlockNo(u8) + bPad(u8*3) + dwAudioTimeStamp(u32)
        timestamp = struct.unpack_from("<H", data, 0)[0]
        format_no = struct.unpack_from("<H", data, 2)[0]
        block_no = data[4]
        # bPad: 3 bytes at offset 5
        # dwAudioTimeStamp at offset 8
        audio_data = data[12:]
        return cls(
            timestamp=timestamp,
            format_no=format_no,
            block_no=block_no,
            audio_data=audio_data,
        )

    def serialize(self) -> bytes:
        """Serialize to wire format."""
        body = struct.pack("<HHB", self.timestamp, self.format_no, self.block_no)
        body += b"\x00" * 3  # bPad
        body += struct.pack("<I", 0)  # dwAudioTimeStamp
        body += self.audio_data
        return body


@dataclass
class WaveConfirmPdu:
    """Wave Confirm PDU [MS-RDPEA] 2.2.3.4.

    Sent by the client to acknowledge playback of a wave block.
    """

    timestamp: int
    block_no: int

    def serialize(self) -> bytes:
        """Serialize to wire format (header + body)."""
        body = struct.pack("<HBB", self.timestamp, self.block_no, 0)  # pad
        header = struct.pack("<BBH", CYCLIC_WAVE_CONFIRM, 0, len(body))
        return header + body

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse from raw RDPSND message body (after header)."""
        if len(data) < 4:
            return cls(timestamp=0, block_no=0)
        timestamp = struct.unpack_from("<H", data, 0)[0]
        block_no = data[2]
        return cls(timestamp=timestamp, block_no=block_no)


# --- Audio Output Channel ---


class AudioOutputChannel:
    """Audio output channel operating over the "rdpsnd" static VC.

    Handles the RDPSND protocol exchange including format negotiation,
    wave data playback, and wave confirm acknowledgment.

    (Req 23, AC 1–5)
    """

    def __init__(self, send_fn: Callable[[bytes], Awaitable[None]]) -> None:
        """Initialize the audio output channel.

        Args:
            send_fn: Async callable to send data on the underlying static channel.
        """
        self._send_fn = send_fn
        self._server_formats: list[AudioFormat] = []
        self._negotiated_formats: list[AudioFormat] = []
        self._stream: Any | None = None
        self._ready = False

    @property
    def ready(self) -> bool:
        """Whether format negotiation has completed."""
        return self._ready

    @property
    def server_formats(self) -> list[AudioFormat]:
        """Audio formats supported by the server."""
        return self._server_formats

    @property
    def negotiated_formats(self) -> list[AudioFormat]:
        """Audio formats negotiated with the server."""
        return self._negotiated_formats

    async def handle_message(self, data: bytes) -> None:
        """Dispatch an inbound RDPSND PDU.

        Parses the RDPSND header and routes to the appropriate handler.

        Args:
            data: The complete RDPSND PDU bytes.
        """
        if len(data) < RDPSND_HEADER_SIZE:
            return

        msg_type = data[0]
        # pad = data[1]
        body_size = struct.unpack_from("<H", data, 2)[0]
        body = data[RDPSND_HEADER_SIZE : RDPSND_HEADER_SIZE + body_size]

        if msg_type == SNDC_FORMATS:
            await self._handle_server_formats(body)
        elif msg_type == SNDC_WAVE:
            await self._handle_wave(body)
        elif msg_type == SNDC_WAVE2:
            await self._handle_wave2(body)
        elif msg_type == SNDC_TRAINING:
            await self._handle_training(body)
        elif msg_type == SNDC_CLOSE:
            self._handle_close()

    async def _handle_server_formats(self, body: bytes) -> None:
        """Handle Server Audio Formats → respond with supported client formats.

        Filters server formats to those we support (PCM) and responds.

        (Req 23, AC 2, 5)
        """
        server_pdu = ServerAudioFormatsPdu.parse(body)
        self._server_formats = server_pdu.formats

        # Filter to supported formats (PCM at common sample rates)
        supported = [
            fmt
            for fmt in server_pdu.formats
            if fmt.format_tag == WAVE_FORMAT_PCM
        ]

        # If no PCM formats from server, offer our own defaults
        if not supported:
            supported = self._get_default_pcm_formats()

        self._negotiated_formats = supported

        # Send Client Audio Formats response
        client_pdu = ClientAudioFormatsPdu(
            version=server_pdu.version,
            formats=supported,
        )
        await self._send_fn(client_pdu.serialize())
        self._ready = True

    async def _handle_wave(self, body: bytes) -> None:
        """Handle Wave PDU → decode audio, play, send confirm.

        (Req 23, AC 3–4)
        """
        wave = WavePdu.parse(body)
        await self._play_audio(wave.audio_data)
        await self._send_wave_confirm(wave.timestamp, wave.block_no)

    async def _handle_wave2(self, body: bytes) -> None:
        """Handle Wave2 PDU → decode audio, play, send confirm.

        (Req 23, AC 3–4)
        """
        wave2 = Wave2Pdu.parse(body)
        await self._play_audio(wave2.audio_data)
        await self._send_wave_confirm(wave2.timestamp, wave2.block_no)

    async def _handle_training(self, body: bytes) -> None:
        """Handle Training PDU → respond with Training Confirm."""
        if len(body) < 4:
            return
        timestamp = struct.unpack_from("<H", body, 0)[0]
        pack_size = struct.unpack_from("<H", body, 2)[0]

        # Send Training Confirm
        confirm_body = struct.pack("<HH", timestamp, pack_size)
        header = struct.pack("<BBH", SNDC_TRAININGCONFIRM, 0, len(confirm_body))
        await self._send_fn(header + confirm_body)

    def _handle_close(self) -> None:
        """Handle Close PDU — stop audio stream."""
        if self._stream is not None:
            try:
                self._stream.stop()
                self._stream.close()
            except Exception:
                pass
            self._stream = None

    async def _play_audio(self, audio_data: bytes) -> None:
        """Play audio data via sounddevice.

        (Req 23, AC 3)
        """
        if not audio_data or not self._negotiated_formats:
            return

        try:
            import sounddevice as sd
            import numpy as np

            fmt = self._negotiated_formats[0]
            # Convert bytes to numpy array
            dtype = f"int{fmt.bits_per_sample}" if fmt.bits_per_sample in (8, 16, 32) else "int16"
            samples = np.frombuffer(audio_data, dtype=dtype)

            if fmt.channels > 1:
                samples = samples.reshape(-1, fmt.channels)

            sd.play(samples, samplerate=fmt.samples_per_sec, blocking=False)
        except (ImportError, Exception):
            # sounddevice not available or audio error — skip playback
            pass

    async def _send_wave_confirm(self, timestamp: int, block_no: int) -> None:
        """Send Wave Confirm after playback completes.

        (Req 23, AC 4)
        """
        confirm = WaveConfirmPdu(timestamp=timestamp, block_no=block_no)
        await self._send_fn(confirm.serialize())

    @staticmethod
    def _get_default_pcm_formats() -> list[AudioFormat]:
        """Get default PCM audio formats the client supports."""
        formats = []
        for rate in [SAMPLE_RATE_44100, SAMPLE_RATE_22050, SAMPLE_RATE_11025]:
            for channels in [2, 1]:
                for bits in [16, 8]:
                    block_align = channels * (bits // 8)
                    avg_bytes = rate * block_align
                    formats.append(
                        AudioFormat(
                            format_tag=WAVE_FORMAT_PCM,
                            channels=channels,
                            samples_per_sec=rate,
                            avg_bytes_per_sec=avg_bytes,
                            block_align=block_align,
                            bits_per_sample=bits,
                        )
                    )
        return formats
