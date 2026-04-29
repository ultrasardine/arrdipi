"""Tests for the audio input channel (AUDIN)."""

from __future__ import annotations

import struct
from unittest.mock import AsyncMock, patch

import pytest

from arrdipi.channels.audio_input import (
    AUDIN_RESULT_SUCCESS,
    CYCLIC_MSG_ID_CLOSE,
    CYCLIC_MSG_ID_DATA,
    CYCLIC_MSG_ID_FORMATS,
    CYCLIC_MSG_ID_OPEN,
    CYCLIC_MSG_ID_OPEN_REPLY,
    CYCLIC_MSG_ID_VERSION,
    WAVE_FORMAT_PCM,
    AudinClosePdu,
    AudinDataPdu,
    AudinFormat,
    AudinOpenPdu,
    AudinOpenReplyPdu,
    AudioInputChannel,
)


class TestAudinFormat:
    """Tests for AudinFormat dataclass."""

    def test_serialize_and_parse(self) -> None:
        fmt = AudinFormat(
            format_tag=WAVE_FORMAT_PCM,
            channels=1,
            samples_per_sec=44100,
            avg_bytes_per_sec=88200,
            block_align=2,
            bits_per_sample=16,
        )
        data = fmt.serialize()
        parsed, consumed = AudinFormat.parse(data)
        assert parsed.format_tag == WAVE_FORMAT_PCM
        assert parsed.channels == 1
        assert parsed.samples_per_sec == 44100
        assert parsed.block_align == 2
        assert parsed.bits_per_sample == 16
        assert consumed == 18


class TestAudinOpenPdu:
    """Tests for AudinOpenPdu."""

    def test_serialize(self) -> None:
        fmt = AudinFormat(
            format_tag=WAVE_FORMAT_PCM, channels=1, samples_per_sec=44100,
            avg_bytes_per_sec=88200, block_align=2, bits_per_sample=16,
        )
        pdu = AudinOpenPdu(initial_format_index=0, frames_per_packet=1024, formats=[fmt])
        data = pdu.serialize()
        assert data[0] == CYCLIC_MSG_ID_OPEN

    def test_parse(self) -> None:
        fmt = AudinFormat(
            format_tag=WAVE_FORMAT_PCM, channels=1, samples_per_sec=44100,
            avg_bytes_per_sec=88200, block_align=2, bits_per_sample=16,
        )
        # Body: frames_per_packet(u32) + initial_format_index(u32) + format data
        body = struct.pack("<II", 1024, 0) + fmt.serialize()
        parsed = AudinOpenPdu.parse(body)
        assert parsed.frames_per_packet == 1024
        assert parsed.initial_format_index == 0
        assert len(parsed.formats) == 1
        assert parsed.formats[0].format_tag == WAVE_FORMAT_PCM


class TestAudinOpenReplyPdu:
    """Tests for AudinOpenReplyPdu."""

    def test_serialize(self) -> None:
        pdu = AudinOpenReplyPdu(result=AUDIN_RESULT_SUCCESS)
        data = pdu.serialize()
        assert data[0] == CYCLIC_MSG_ID_OPEN_REPLY
        result = struct.unpack_from("<I", data, 1)[0]
        assert result == AUDIN_RESULT_SUCCESS

    def test_parse(self) -> None:
        body = struct.pack("<I", AUDIN_RESULT_SUCCESS)
        parsed = AudinOpenReplyPdu.parse(body)
        assert parsed.result == AUDIN_RESULT_SUCCESS


class TestAudinDataPdu:
    """Tests for AudinDataPdu."""

    def test_serialize(self) -> None:
        audio = b"\x01\x02\x03\x04" * 50
        pdu = AudinDataPdu(audio_data=audio)
        data = pdu.serialize()
        assert data[0] == CYCLIC_MSG_ID_DATA
        assert data[1:] == audio

    def test_parse(self) -> None:
        audio = b"\xAA\xBB\xCC\xDD"
        parsed = AudinDataPdu.parse(audio)
        assert parsed.audio_data == audio


class TestAudinClosePdu:
    """Tests for AudinClosePdu."""

    def test_serialize(self) -> None:
        pdu = AudinClosePdu()
        data = pdu.serialize()
        assert data == struct.pack("<B", CYCLIC_MSG_ID_CLOSE)

    def test_parse(self) -> None:
        parsed = AudinClosePdu.parse(b"")
        assert isinstance(parsed, AudinClosePdu)


class TestAudioInputChannel:
    """Tests for AudioInputChannel."""

    @pytest.mark.asyncio
    async def test_open_close_lifecycle(self) -> None:
        """Open → starts capture, Close → stops capture."""
        send_fn = AsyncMock()
        channel = AudioInputChannel(send_fn)

        # Build Open PDU
        fmt = AudinFormat(
            format_tag=WAVE_FORMAT_PCM, channels=1, samples_per_sec=44100,
            avg_bytes_per_sec=88200, block_align=2, bits_per_sample=16,
        )
        open_body = struct.pack("<II", 1024, 0) + fmt.serialize()
        open_pdu = struct.pack("<B", CYCLIC_MSG_ID_OPEN) + open_body

        # Mock sounddevice to avoid actual audio capture
        with patch("arrdipi.channels.audio_input.AudioInputChannel._start_capture"):
            await channel.handle_message(open_pdu)

        # Verify Open Reply was sent
        send_fn.assert_called_once()
        reply_data = send_fn.call_args[0][0]
        assert reply_data[0] == CYCLIC_MSG_ID_OPEN_REPLY
        result = struct.unpack_from("<I", reply_data, 1)[0]
        assert result == AUDIN_RESULT_SUCCESS

        # Verify format was set
        assert channel.current_format is not None
        assert channel.current_format.format_tag == WAVE_FORMAT_PCM

        # Now close
        send_fn.reset_mock()
        close_pdu = struct.pack("<B", CYCLIC_MSG_ID_CLOSE)
        await channel.handle_message(close_pdu)

        # After close, capturing should be False
        assert channel.capturing is False

    @pytest.mark.asyncio
    async def test_send_audio_data(self) -> None:
        """send_audio_data() constructs and sends a Data PDU."""
        send_fn = AsyncMock()
        channel = AudioInputChannel(send_fn)
        channel._capturing = True

        audio = b"\x10\x20\x30\x40" * 100
        await channel.send_audio_data(audio)

        send_fn.assert_called_once()
        data = send_fn.call_args[0][0]
        assert data[0] == CYCLIC_MSG_ID_DATA
        assert data[1:] == audio

    @pytest.mark.asyncio
    async def test_send_audio_data_not_capturing(self) -> None:
        """send_audio_data() does nothing when not capturing."""
        send_fn = AsyncMock()
        channel = AudioInputChannel(send_fn)
        channel._capturing = False

        await channel.send_audio_data(b"\x00" * 100)
        send_fn.assert_not_called()

    @pytest.mark.asyncio
    async def test_version_exchange(self) -> None:
        """Version PDU → responds with client version."""
        send_fn = AsyncMock()
        channel = AudioInputChannel(send_fn)

        version_pdu = struct.pack("<BI", CYCLIC_MSG_ID_VERSION, 1)
        await channel.handle_message(version_pdu)

        send_fn.assert_called_once()
        response = send_fn.call_args[0][0]
        assert response[0] == CYCLIC_MSG_ID_VERSION

    @pytest.mark.asyncio
    async def test_formats_exchange(self) -> None:
        """Formats PDU → responds with supported formats."""
        send_fn = AsyncMock()
        channel = AudioInputChannel(send_fn)

        # Build formats PDU with one PCM format
        fmt = AudinFormat(
            format_tag=WAVE_FORMAT_PCM, channels=1, samples_per_sec=44100,
            avg_bytes_per_sec=88200, block_align=2, bits_per_sample=16,
        )
        body = struct.pack("<I", 1) + fmt.serialize()
        formats_pdu = struct.pack("<B", CYCLIC_MSG_ID_FORMATS) + body

        await channel.handle_message(formats_pdu)

        send_fn.assert_called_once()
        response = send_fn.call_args[0][0]
        assert response[0] == CYCLIC_MSG_ID_FORMATS

    @pytest.mark.asyncio
    async def test_open_sets_format(self) -> None:
        """Open PDU sets the current format from the provided formats."""
        send_fn = AsyncMock()
        channel = AudioInputChannel(send_fn)

        fmt = AudinFormat(
            format_tag=WAVE_FORMAT_PCM, channels=2, samples_per_sec=22050,
            avg_bytes_per_sec=88200, block_align=4, bits_per_sample=16,
        )
        open_body = struct.pack("<II", 512, 0) + fmt.serialize()
        open_pdu = struct.pack("<B", CYCLIC_MSG_ID_OPEN) + open_body

        with patch("arrdipi.channels.audio_input.AudioInputChannel._start_capture"):
            await channel.handle_message(open_pdu)

        assert channel.current_format is not None
        assert channel.current_format.channels == 2
        assert channel.current_format.samples_per_sec == 22050
