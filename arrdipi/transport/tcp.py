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

        Detaches the raw socket from the current asyncio transport, then
        re-creates the connection with ``ssl=ssl_context`` so asyncio
        performs the TLS handshake asynchronously on the dup'd fd.

        This avoids both:
        - ``loop.start_tls()`` which fails on macOS when the connection
          has already exchanged data (X.224 negotiation confuses its
          TLS state machine).
        - Passing a pre-wrapped SSLSocket to ``create_connection`` without
          ``ssl=``, which leaves asyncio unaware of TLS (breaks
          ``get_extra_info("ssl_object")`` needed by CredSSP).

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

        # Dup the fd so we can close the asyncio transport without losing the connection
        raw_sock = socket.fromfd(sock.fileno(), sock.family, sock.type)
        raw_sock.setblocking(False)

        # Close the asyncio transport (closes the original fd, dup'd fd stays open)
        self.writer.close()
        await self.writer.wait_closed()

        # Re-create the connection WITH TLS — asyncio handles the handshake
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        new_transport, _ = await loop.create_connection(
            lambda: protocol,
            sock=raw_sock,
            ssl=ssl_context,
            server_hostname=server_hostname or "",
        )
        writer = asyncio.StreamWriter(new_transport, protocol, reader, loop)

        self.reader = reader
        self.writer = writer
