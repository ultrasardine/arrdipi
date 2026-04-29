"""TCP transport layer with async I/O and TLS upgrade support.

Provides the lowest-level async network I/O using asyncio streams.
Supports in-place TLS upgrade for Enhanced RDP Security (Req 10, AC 1).
"""

from __future__ import annotations

import asyncio
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
        self, ssl_context: ssl.SSLContext, server_hostname: str
    ) -> None:
        """Upgrade the plain TCP socket to TLS in-place.

        Replaces reader/writer with TLS-wrapped streams using
        the event loop's start_tls() method. Upper layers continue
        using the same TcpTransport instance transparently.

        Args:
            ssl_context: Configured SSL context for the TLS handshake.
            server_hostname: Server hostname for SNI and certificate verification.

        Raises:
            ssl.SSLError: If the TLS handshake fails.
        """
        loop = asyncio.get_event_loop()
        transport = self.writer.transport
        protocol = transport.get_protocol()

        new_transport = await loop.start_tls(
            transport,
            protocol,
            ssl_context,
            server_hostname=server_hostname,
        )

        # Replace the writer's transport with the TLS-wrapped one
        self.writer._transport = new_transport  # noqa: SLF001

        # Create a new reader connected to the upgraded transport
        new_reader = asyncio.StreamReader()
        new_protocol = asyncio.StreamReaderProtocol(new_reader)
        new_protocol.connection_made(new_transport)
        new_transport.set_protocol(new_protocol)

        self.reader = new_reader
