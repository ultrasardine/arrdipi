"""Tests for the arrdipi public API — connect() and package exports."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import arrdipi
from arrdipi import (
    ArrdipiError,
    AudioInputChannel,
    AudioOutputChannel,
    AuthenticationError,
    ChannelJoinError,
    ClipboardChannel,
    ConnectionPhaseError,
    ConnectionTimeoutError,
    DecompressionError,
    DriveChannel,
    DrivePath,
    FinalizationTimeoutError,
    GraphicsSurface,
    NegotiationError,
    NegotiationFailureError,
    PduParseError,
    RleDecodeError,
    Session,
    SessionConfig,
    connect,
)
from arrdipi.connection import ConnectionSequence


class TestPackageImport:
    """Test that import arrdipi works and exposes the documented API."""

    def test_import_arrdipi(self) -> None:
        """Verify import arrdipi succeeds and has version."""
        assert arrdipi.__version__ == "0.1.0"

    def test_connect_function_exported(self) -> None:
        """Verify connect() is accessible from the package."""
        assert callable(arrdipi.connect)

    def test_session_exported(self) -> None:
        """Verify Session class is accessible."""
        assert arrdipi.Session is Session

    def test_session_config_exported(self) -> None:
        """Verify SessionConfig is accessible."""
        assert arrdipi.SessionConfig is SessionConfig

    def test_graphics_surface_exported(self) -> None:
        """Verify GraphicsSurface is accessible."""
        assert arrdipi.GraphicsSurface is GraphicsSurface

    def test_drive_path_exported(self) -> None:
        """Verify DrivePath is accessible."""
        assert arrdipi.DrivePath is DrivePath

    def test_clipboard_channel_exported(self) -> None:
        """Verify ClipboardChannel class is accessible."""
        assert arrdipi.ClipboardChannel is ClipboardChannel
        from arrdipi.channels.clipboard import ClipboardChannel as _CC
        assert arrdipi.ClipboardChannel is _CC

    def test_audio_output_channel_exported(self) -> None:
        """Verify AudioOutputChannel class is accessible."""
        assert arrdipi.AudioOutputChannel is AudioOutputChannel
        from arrdipi.channels.audio_output import AudioOutputChannel as _AOC
        assert arrdipi.AudioOutputChannel is _AOC

    def test_audio_input_channel_exported(self) -> None:
        """Verify AudioInputChannel class is accessible."""
        assert arrdipi.AudioInputChannel is AudioInputChannel
        from arrdipi.channels.audio_input import AudioInputChannel as _AIC
        assert arrdipi.AudioInputChannel is _AIC

    def test_drive_channel_exported(self) -> None:
        """Verify DriveChannel class is accessible."""
        assert arrdipi.DriveChannel is DriveChannel
        from arrdipi.channels.drive import DriveChannel as _DC
        assert arrdipi.DriveChannel is _DC

    def test_error_types_exported(self) -> None:
        """Verify all error types are accessible from the package."""
        assert arrdipi.ArrdipiError is ArrdipiError
        assert arrdipi.ConnectionTimeoutError is ConnectionTimeoutError
        assert arrdipi.NegotiationFailureError is NegotiationFailureError
        assert arrdipi.ConnectionPhaseError is ConnectionPhaseError
        assert arrdipi.ChannelJoinError is ChannelJoinError
        assert arrdipi.AuthenticationError is AuthenticationError
        assert arrdipi.NegotiationError is NegotiationError
        assert arrdipi.PduParseError is PduParseError
        assert arrdipi.DecompressionError is DecompressionError
        assert arrdipi.RleDecodeError is RleDecodeError
        assert arrdipi.FinalizationTimeoutError is FinalizationTimeoutError

    def test_all_exports_defined(self) -> None:
        """Verify __all__ contains expected symbols."""
        assert "connect" in arrdipi.__all__
        assert "Session" in arrdipi.__all__
        assert "SessionConfig" in arrdipi.__all__
        assert "GraphicsSurface" in arrdipi.__all__
        assert "DrivePath" in arrdipi.__all__
        assert "ClipboardChannel" in arrdipi.__all__
        assert "AudioOutputChannel" in arrdipi.__all__
        assert "AudioInputChannel" in arrdipi.__all__
        assert "DriveChannel" in arrdipi.__all__
        assert "ArrdipiError" in arrdipi.__all__


class TestConnect:
    """Test the connect() async function."""

    @pytest.mark.asyncio
    async def test_connect_constructs_config_and_returns_session(self) -> None:
        """Verify connect() constructs SessionConfig, runs ConnectionSequence, returns Session."""
        mock_session = MagicMock(spec=Session)

        with patch.object(
            ConnectionSequence, "execute", new_callable=AsyncMock, return_value=mock_session
        ) as mock_execute:
            with patch.object(
                ConnectionSequence, "__init__", return_value=None
            ) as mock_init:
                result = await connect(
                    host="192.168.1.100",
                    port=3389,
                    username="admin",
                    password="secret",
                    domain="CORP",
                    width=1280,
                    height=720,
                    security="nla",
                )

                # Verify ConnectionSequence was initialized with a SessionConfig
                mock_init.assert_called_once()
                config = mock_init.call_args[0][0]
                assert isinstance(config, SessionConfig)
                assert config.host == "192.168.1.100"
                assert config.port == 3389
                assert config.username == "admin"
                assert config.password == "secret"
                assert config.domain == "CORP"
                assert config.width == 1280
                assert config.height == 720

                # Verify execute was called and session returned
                mock_execute.assert_called_once()
                assert result is mock_session

    @pytest.mark.asyncio
    async def test_connect_default_parameters(self) -> None:
        """Verify connect() uses sensible defaults."""
        mock_session = MagicMock(spec=Session)

        with patch.object(
            ConnectionSequence, "execute", new_callable=AsyncMock, return_value=mock_session
        ):
            with patch.object(
                ConnectionSequence, "__init__", return_value=None
            ) as mock_init:
                await connect(host="server.example.com")

                config = mock_init.call_args[0][0]
                assert config.port == 3389
                assert config.width == 1920
                assert config.height == 1080
                assert config.verify_cert is True
                assert config.connect_timeout == 5.0
                assert "cliprdr" in config.channel_names
                assert "rdpsnd" in config.channel_names
                assert "rdpdr" in config.channel_names
                assert "drdynvc" in config.channel_names

    @pytest.mark.asyncio
    async def test_connect_security_mode_mapping(self) -> None:
        """Verify security string is mapped to SecurityProtocol enum."""
        from arrdipi.pdu.types import SecurityProtocol

        mock_session = MagicMock(spec=Session)

        for mode, expected in [
            ("auto", SecurityProtocol.AUTO),
            ("rdp", SecurityProtocol.RDP),
            ("tls", SecurityProtocol.TLS),
            ("nla", SecurityProtocol.NLA),
            ("TLS", SecurityProtocol.TLS),  # case-insensitive
        ]:
            with patch.object(
                ConnectionSequence, "execute", new_callable=AsyncMock, return_value=mock_session
            ):
                with patch.object(
                    ConnectionSequence, "__init__", return_value=None
                ) as mock_init:
                    await connect(host="server", security=mode)
                    config = mock_init.call_args[0][0]
                    assert config.security == expected, f"Failed for mode={mode}"

    @pytest.mark.asyncio
    async def test_connect_propagates_connection_error(self) -> None:
        """Verify connect() propagates ConnectionPhaseError from the sequence."""
        cause = RuntimeError("TCP failed")
        error = ConnectionPhaseError(phase_number=1, phase_name="Connection Initiation", cause=cause)

        with patch.object(
            ConnectionSequence, "execute", new_callable=AsyncMock, side_effect=error
        ):
            with patch.object(ConnectionSequence, "__init__", return_value=None):
                with pytest.raises(ConnectionPhaseError) as exc_info:
                    await connect(host="unreachable.host")
                assert exc_info.value.phase_number == 1

    @pytest.mark.asyncio
    async def test_connect_with_custom_channels_and_drives(self) -> None:
        """Verify connect() passes custom channel names and drive paths."""
        mock_session = MagicMock(spec=Session)
        drives = [DrivePath(name="C", path="/tmp/share")]

        with patch.object(
            ConnectionSequence, "execute", new_callable=AsyncMock, return_value=mock_session
        ):
            with patch.object(
                ConnectionSequence, "__init__", return_value=None
            ) as mock_init:
                await connect(
                    host="server",
                    channel_names=["cliprdr"],
                    drive_paths=drives,
                )
                config = mock_init.call_args[0][0]
                assert config.channel_names == ["cliprdr"]
                assert config.drive_paths == drives
