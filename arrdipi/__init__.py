"""arrdipi — A pure Python RDP client library.

Public API exports for the arrdipi package.
"""

from __future__ import annotations

__version__ = "0.1.0"

from arrdipi.channels.audio_input import AudioInputChannel
from arrdipi.channels.audio_output import AudioOutputChannel
from arrdipi.channels.clipboard import ClipboardChannel
from arrdipi.channels.drive import DriveChannel
from arrdipi.connection import ConnectionSequence, DrivePath, SessionConfig
from arrdipi.errors import (
    ArrdipiError,
    AuthenticationError,
    ChannelJoinError,
    ConnectionPhaseError,
    ConnectionTimeoutError,
    DecompressionError,
    FinalizationTimeoutError,
    NegotiationError,
    NegotiationFailureError,
    PduParseError,
    RleDecodeError,
)
from arrdipi.graphics.surface import GraphicsSurface
from arrdipi.session import Session


async def connect(
    host: str,
    port: int = 3389,
    username: str = "",
    password: str = "",
    domain: str = "",
    *,
    width: int = 1920,
    height: int = 1080,
    security: str = "auto",
    verify_cert: bool = True,
    connect_timeout: float = 5.0,
    channel_names: list[str] | None = None,
    drive_paths: list[DrivePath] | None = None,
) -> Session:
    """Connect to an RDP server and return an active Session.

    This is the primary entry point for the arrdipi library. It constructs
    a SessionConfig, runs the full 10-phase ConnectionSequence, and returns
    a connected Session ready for interaction.

    (Req 27, AC 1–2, 8)

    Args:
        host: The RDP server hostname or IP address.
        port: The RDP server port (default 3389).
        username: Username for authentication.
        password: Password for authentication.
        domain: Windows domain for authentication.
        width: Desktop width in pixels (default 1920).
        height: Desktop height in pixels (default 1080).
        security: Security mode — "auto", "rdp", "tls", or "nla" (default "auto").
        verify_cert: Whether to verify TLS certificates (default True).
        connect_timeout: TCP connection timeout in seconds (default 5.0).
        channel_names: List of static virtual channel names to request.
            Defaults to ["cliprdr", "rdpsnd", "rdpdr", "drdynvc"].
        drive_paths: List of DrivePath objects for drive redirection.

    Returns:
        A connected Session object.

    Raises:
        ConnectionTimeoutError: If TCP connection times out.
        NegotiationFailureError: If X.224 negotiation fails.
        AuthenticationError: If NLA/CredSSP authentication fails.
        ConnectionPhaseError: If any connection phase fails.
    """
    from arrdipi.pdu.types import SecurityProtocol

    # Map string security mode to enum
    security_map = {
        "auto": SecurityProtocol.AUTO,
        "rdp": SecurityProtocol.RDP,
        "tls": SecurityProtocol.TLS,
        "nla": SecurityProtocol.NLA,
    }
    security_protocol = security_map.get(security.lower(), SecurityProtocol.AUTO)

    config = SessionConfig(
        host=host,
        port=port,
        username=username,
        password=password,
        domain=domain,
        security=security_protocol,
        width=width,
        height=height,
        verify_cert=verify_cert,
        connect_timeout=connect_timeout,
        channel_names=channel_names or ["cliprdr", "rdpsnd", "rdpdr", "drdynvc"],
        drive_paths=drive_paths or [],
    )

    sequence = ConnectionSequence(config)
    session = await sequence.execute()
    return session


__all__ = [
    # Core API
    "connect",
    "Session",
    "SessionConfig",
    "DrivePath",
    "GraphicsSurface",
    # Channel types
    "ClipboardChannel",
    "AudioOutputChannel",
    "AudioInputChannel",
    "DriveChannel",
    # Error types
    "ArrdipiError",
    "ConnectionTimeoutError",
    "NegotiationFailureError",
    "ConnectionPhaseError",
    "ChannelJoinError",
    "AuthenticationError",
    "NegotiationError",
    "PduParseError",
    "DecompressionError",
    "RleDecodeError",
    "FinalizationTimeoutError",
]
