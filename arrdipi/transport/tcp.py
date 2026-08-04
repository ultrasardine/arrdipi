"""TCP transport layer with async I/O and TLS upgrade support.

Provides the lowest-level async network I/O using asyncio streams.
Supports in-place TLS upgrade for Enhanced RDP Security (Req 10, AC 1).
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass, field

from arrdipi.errors import ConnectionTimeoutError


@dataclass
class TcpTransport:
    """Async TCP transport with configurable timeout and TLS upgrade.

    Wraps asyncio StreamReader/StreamWriter for RDP protocol communication.
    The TLS upgrade replaces the reader/writer in-place so upper layers
    are unaware of the transition.
    """

    reader: asyncio.StreamReader = field(repr=False)
    writer: asyncio.StreamWriter = field(repr=False)

    @classmethod
    async def connect(
        cls, host: str, port: int, timeout: float = 5.0
    ) -> TcpTransport:
        """Open a TCP connection with configurable timeout.

        Args:
            host: Target hostname or IP address.
            port: Target port number.
            timeout: Maximum seconds to wait for connection (default 5.0).

        Returns:
            A connected TcpTransport instance.

        Raises:
            ConnectionTimeoutError: If the connection cannot be established
                within the specified timeout (Req 1, AC 5).
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            raise ConnectionTimeoutError(host=host, port=port, timeout=timeout)

        return cls(reader=reader, writer=writer)

    async def send(self, data: bytes) -> None:
        """Send data over the TCP connection.

        Args:
            data: Raw bytes to send.
        """
        self.writer.write(data)
        await self.writer.drain()

    async def recv(self, n: int) -> bytes:
        """Receive exactly n bytes from the TCP connection.

        Uses readexactly to ensure the full requested amount is read.

        Args:
            n: Number of bytes to read.

        Returns:
            Exactly n bytes of data.

        Raises:
            asyncio.IncompleteReadError: If the connection is closed before
                n bytes are available.
        """
        return await self.reader.readexactly(n)

    async def close(self) -> None:
        """Close the TCP connection gracefully."""
        self.writer.close()
        await self.writer.wait_closed()

    async def upgrade_to_tls(
        self, ssl_context: ssl.SSLContext, server_hostname: str | None
    ) -> None:
        """Upgrade the plain TCP socket to TLS in-place.

        Uses socket-level TLS wrapping instead of asyncio's start_tls()
        to work around a known issue where start_tls() fails on macOS
        when the connection has already exchanged data (e.g. X.224
        negotiation bytes confuse asyncio's TLS state machine).

        Args:
            ssl_context: Configured SSL context for the TLS handshake.
            server_hostname: Server hostname for SNI and certificate
                verification, or None to skip SNI.

        Raises:
            ssl.SSLError: If the TLS handshake fails.
        """
        # Get the raw socket from the asyncio transport
        transport = self.writer.transport
        sock = transport.get_extra_info("socket")

        # Pause reading so asyncio doesn't interfere during upgrade
        transport.pause_reading()

        # Dup the socket so we can close the asyncio transport without closing the fd
        raw_fd = sock.fileno()
        raw_sock = socket.fromfd(raw_fd, sock.family, sock.type)
        raw_sock.settimeout(10)

        # Close the asyncio transport (but not the underlying fd since we dup'd)
        self.writer.transport.close()

        # Perform TLS handshake on the raw socket
        ssl_sock = ssl_context.wrap_socket(
            raw_sock,
            server_hostname=server_hostname,
            do_handshake_on_connect=True,
        )
        ssl_sock.setblocking(False)

        # Re-create asyncio streams from the TLS-wrapped socket
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        new_transport, _ = await loop.create_connection(
            lambda: protocol, sock=ssl_sock
        )
        writer = asyncio.StreamWriter(new_transport, protocol, reader, loop)

        self.reader = reader
        self.writer = writer
