"""Tests for the audio output channel (RDPSND)."""

from __future__ import annotations

import struct
from unittest.mock import AsyncMock, patch

import pytest

from arrdipi.channels.audio_output import (
    CYCLIC_WAVE_CONFIRM,
    RDPSND_HEADER_SIZE,
    SNDC_FORMATS,
    SNDC_TRAINING,
    SNDC_WAVE,
    SNDC_WAVE2,
    WAVE_FORMAT_PCM,
    AudioFormat,
    AudioOutputChannel,
    ClientAudioFormatsPdu,
    ServerAudioFormatsPdu,
    Wave2Pdu,
    WaveConfirmPdu,
    WavePdu,
)


class TestAudioFormat:
    """Tests for AudioFormat dataclass."""

    def test_serialize_and_parse(self) -> None:
        fmt = AudioFormat(
            format_tag=WAVE_FORMAT_PCM,
            channels=2,
            samples_per_sec=44100,
            avg_bytes_per_sec=176400,
            block_align=4,
            bits_per_sample=16,
        )
        data = fmt.serialize()
        parsed, consumed = AudioFormat.parse(data)
        assert parsed.format_tag == WAVE_FORMAT_PCM
        assert parsed.channels == 2
        assert parsed.samples_per_sec == 44100
        assert parsed.avg_bytes_per_sec == 176400
        assert parsed.block_align == 4
        assert parsed.bits_per_sample == 16
        assert consumed == 18

    def test_serialize_with_extra_data(self) -> None:
        fmt = AudioFormat(
            format_tag=0x0055,  # MP3
            channels=2,
            samples_per_sec=44100,
            avg_bytes_per_sec=16000,
            block_align=1,
            bits_per_sample=0,
            extra_data=b"\x01\x02\x03\x04",
        )
        data = fmt.serialize()
        parsed, consumed = AudioFormat.parse(data)
        assert parsed.extra_data == b"\x01\x02\x03\x04"
        assert consumed == 22  # 18 + 4 extra bytes


class TestServerAudioFormatsPdu:
    """Tests for ServerAudioFormatsPdu."""

    def test_parse(self) -> None:
        # Build a server formats PDU with one PCM format
        fmt = AudioFormat(
            format_tag=WAVE_FORMAT_PCM,
            channels=2,
            samples_per_sec=44100,
            avg_bytes_per_sec=176400,
            block_align=4,
            bits_per_sample=16,
        )
        # Header: dwFlags(4) + dwVolume(4) + dwPitch(4) + wDGramPort(2) +
        # wNumberOfFormats(2) + cLastBlockConfirmed(1) + wVersion(2) + bPad(1) = 20
        body = struct.pack("<IIIHH", 0, 0xFFFFFFFF, 0, 0, 1)
        body += struct.pack("<BHB", 0, 0x06, 0)
        body += fmt.serialize()

        parsed = ServerAudioFormatsPdu.parse(body)
        assert parsed.version == 0x06
        assert len(parsed.formats) == 1
        assert parsed.formats[0].format_tag == WAVE_FORMAT_PCM
        assert parsed.formats[0].samples_per_sec == 44100

    def test_parse_multiple_formats(self) -> None:
        fmt1 = AudioFormat(
            format_tag=WAVE_FORMAT_PCM, channels=2, samples_per_sec=44100,
            avg_bytes_per_sec=176400, block_align=4, bits_per_sample=16,
        )
        fmt2 = AudioFormat(
            format_tag=WAVE_FORMAT_PCM, channels=1, samples_per_sec=22050,
            avg_bytes_per_sec=44100, block_align=2, bits_per_sample=16,
        )
        body = struct.pack("<IIIHH", 0, 0xFFFFFFFF, 0, 0, 2)
        body += struct.pack("<BHB", 0, 0x06, 0)
        body += fmt1.serialize() + fmt2.serialize()

        parsed = ServerAudioFormatsPdu.parse(body)
        assert len(parsed.formats) == 2


class TestClientAudioFormatsPdu:
    """Tests for ClientAudioFormatsPdu."""

    def test_serialize(self) -> None:
        fmt = AudioFormat(
            format_tag=WAVE_FORMAT_PCM, channels=2, samples_per_sec=44100,
            avg_bytes_per_sec=176400, block_align=4, bits_per_sample=16,
        )
        pdu = ClientAudioFormatsPdu(version=0x06, formats=[fmt])
        data = pdu.serialize()

        # Check header
        assert data[0] == SNDC_FORMATS
        body_size = struct.unpack_from("<H", data, 2)[0]
        assert body_size > 0


class TestWavePdu:
    """Tests for WavePdu."""

    def test_parse(self) -> None:
        audio = b"\x01\x02\x03\x04" * 100
        body = struct.pack("<HHB", 1234, 0, 5)  # timestamp, formatNo, blockNo
        body += b"\x00" * 3  # bPad
        body += audio

        parsed = WavePdu.parse(body)
        assert parsed.timestamp == 1234
        assert parsed.block_no == 5
        assert parsed.audio_data == audio

    def test_serialize(self) -> None:
        pdu = WavePdu(timestamp=100, block_no=3, audio_data=b"\xAA\xBB")
        data = pdu.serialize()
        assert struct.unpack_from("<H", data, 0)[0] == 100
        assert data[4] == 3


class TestWave2Pdu:
    """Tests for Wave2Pdu."""

    def test_parse(self) -> None:
        audio = b"\x10\x20\x30\x40"
        body = struct.pack("<HHB", 5678, 1, 7)  # timestamp, formatNo, blockNo
        body += b"\x00" * 3  # bPad
        body += struct.pack("<I", 0)  # dwAudioTimeStamp
        body += audio

        parsed = Wave2Pdu.parse(body)
        assert parsed.timestamp == 5678
        assert parsed.format_no == 1
        assert parsed.block_no == 7
        assert parsed.audio_data == audio

    def test_serialize(self) -> None:
        pdu = Wave2Pdu(timestamp=200, format_no=0, block_no=10, audio_data=b"\xFF")
        data = pdu.serialize()
        assert struct.unpack_from("<H", data, 0)[0] == 200


class TestWaveConfirmPdu:
    """Tests for WaveConfirmPdu."""

    def test_serialize(self) -> None:
        pdu = WaveConfirmPdu(timestamp=1000, block_no=42)
        data = pdu.serialize()
        assert data[0] == CYCLIC_WAVE_CONFIRM
        body_size = struct.unpack_from("<H", data, 2)[0]
        assert body_size == 4
        # Parse body
        body = data[4:]
        assert struct.unpack_from("<H", body, 0)[0] == 1000
        assert body[2] == 42

    def test_parse(self) -> None:
        body = struct.pack("<HBB", 500, 7, 0)
        parsed = WaveConfirmPdu.parse(body)
        assert parsed.timestamp == 500
        assert parsed.block_no == 7


class TestAudioOutputChannel:
    """Tests for AudioOutputChannel."""

    @pytest.mark.asyncio
    async def test_format_negotiation(self) -> None:
        """Server Audio Formats → client responds with supported PCM formats."""
        send_fn = AsyncMock()
        channel = AudioOutputChannel(send_fn)

        # Build server formats PDU with PCM format
        fmt = AudioFormat(
            format_tag=WAVE_FORMAT_PCM, channels=2, samples_per_sec=44100,
            avg_bytes_per_sec=176400, block_align=4, bits_per_sample=16,
        )
        body = struct.pack("<IIIHH", 0, 0xFFFFFFFF, 0, 0, 1)
        body += struct.pack("<BHB", 0, 0x06, 0)
        body += fmt.serialize()

        # Wrap in RDPSND header
        header = struct.pack("<BBH", SNDC_FORMATS, 0, len(body))
        pdu_data = header + body

        await channel.handle_message(pdu_data)

        assert channel.ready is True
        assert len(channel.negotiated_formats) == 1
        assert channel.negotiated_formats[0].format_tag == WAVE_FORMAT_PCM

        # Verify client response was sent
        send_fn.assert_called_once()
        response = send_fn.call_args[0][0]
        assert response[0] == SNDC_FORMATS

    @pytest.mark.asyncio
    async def test_wave_pdu_sends_confirm(self) -> None:
        """Wave PDU → sends Wave Confirm after playback."""
        send_fn = AsyncMock()
        channel = AudioOutputChannel(send_fn)
        channel._negotiated_formats = [
            AudioFormat(
                format_tag=WAVE_FORMAT_PCM, channels=1, samples_per_sec=22050,
                avg_bytes_per_sec=44100, block_align=2, bits_per_sample=16,
            )
        ]
        channel._ready = True

        # Build Wave PDU
        audio = b"\x00" * 100
        wave_body = struct.pack("<HHB", 999, 0, 3)
        wave_body += b"\x00" * 3
        wave_body += audio
        header = struct.pack("<BBH", SNDC_WAVE, 0, len(wave_body))
        pdu_data = header + wave_body

        # Mock sounddevice to avoid actual audio playback
        with patch("arrdipi.channels.audio_output.AudioOutputChannel._play_audio", new_callable=AsyncMock):
            await channel.handle_message(pdu_data)

        # Verify Wave Confirm was sent
        send_fn.assert_called_once()
        confirm = send_fn.call_args[0][0]
        assert confirm[0] == CYCLIC_WAVE_CONFIRM
        # Parse confirm body
        body = confirm[4:]
        timestamp = struct.unpack_from("<H", body, 0)[0]
        block_no = body[2]
        assert timestamp == 999
        assert block_no == 3

    @pytest.mark.asyncio
    async def test_wave2_pdu_sends_confirm(self) -> None:
        """Wave2 PDU → sends Wave Confirm after playback."""
        send_fn = AsyncMock()
        channel = AudioOutputChannel(send_fn)
        channel._negotiated_formats = [
            AudioFormat(
                format_tag=WAVE_FORMAT_PCM, channels=2, samples_per_sec=44100,
                avg_bytes_per_sec=176400, block_align=4, bits_per_sample=16,
            )
        ]
        channel._ready = True

        # Build Wave2 PDU
        audio = b"\x00" * 200
        wave2_body = struct.pack("<HHB", 2000, 0, 15)
        wave2_body += b"\x00" * 3
        wave2_body += struct.pack("<I", 0)
        wave2_body += audio
        header = struct.pack("<BBH", SNDC_WAVE2, 0, len(wave2_body))
        pdu_data = header + wave2_body

        with patch("arrdipi.channels.audio_output.AudioOutputChannel._play_audio", new_callable=AsyncMock):
            await channel.handle_message(pdu_data)

        send_fn.assert_called_once()
        confirm = send_fn.call_args[0][0]
        assert confirm[0] == CYCLIC_WAVE_CONFIRM
        body = confirm[4:]
        assert struct.unpack_from("<H", body, 0)[0] == 2000
        assert body[2] == 15

    @pytest.mark.asyncio
    async def test_training_confirm(self) -> None:
        """Training PDU → responds with Training Confirm."""
        send_fn = AsyncMock()
        channel = AudioOutputChannel(send_fn)

        # Build Training PDU
        training_body = struct.pack("<HH", 1234, 0)
        header = struct.pack("<BBH", SNDC_TRAINING, 0, len(training_body))
        pdu_data = header + training_body

        await channel.handle_message(pdu_data)

        send_fn.assert_called_once()
        response = send_fn.call_args[0][0]
        # Training confirm uses same msg type
        assert response[0] == SNDC_TRAINING

    @pytest.mark.asyncio
    async def test_format_negotiation_no_pcm(self) -> None:
        """When server has no PCM formats, client offers defaults."""
        send_fn = AsyncMock()
        channel = AudioOutputChannel(send_fn)

        # Build server formats with non-PCM format only
        fmt = AudioFormat(
            format_tag=0x0055,  # MP3
            channels=2, samples_per_sec=44100,
            avg_bytes_per_sec=16000, block_align=1, bits_per_sample=0,
        )
        body = struct.pack("<IIIHH", 0, 0xFFFFFFFF, 0, 0, 1)
        body += struct.pack("<BHB", 0, 0x06, 0)
        body += fmt.serialize()
        header = struct.pack("<BBH", SNDC_FORMATS, 0, len(body))
        pdu_data = header + body

        await channel.handle_message(pdu_data)

        assert channel.ready is True
        # Should have default PCM formats
        assert len(channel.negotiated_formats) > 0
        assert all(f.format_tag == WAVE_FORMAT_PCM for f in channel.negotiated_formats)
