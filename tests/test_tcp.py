"""Tests for TCP transport layer: connect timeout, send/recv data flow, TLS upgrade."""

from __future__ import annotations

import asyncio
import ssl
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from arrdipi.errors import ConnectionTimeoutError
from arrdipi.transport.tcp import TcpTransport


@pytest.mark.asyncio
async def test_connect_timeout_raises_connection_timeout_error():
    """ConnectionTimeoutError is raised when TCP connect exceeds timeout."""
    with patch(
        "arrdipi.transport.tcp.asyncio.open_connection",
        new_callable=AsyncMock,
        side_effect=asyncio.TimeoutError(),
    ):
        with patch(
            "arrdipi.transport.tcp.asyncio.wait_for",
            side_effect=asyncio.TimeoutError(),
        ):
            with pytest.raises(ConnectionTimeoutError) as exc_info:
                await TcpTransport.connect("192.168.1.1", 3389, timeout=2.0)

            assert exc_info.value.host == "192.168.1.1"
            assert exc_info.value.port == 3389
            assert exc_info.value.timeout == 2.0
            assert "192.168.1.1:3389" in str(exc_info.value)
            assert "2.0s" in str(exc_info.value)


@pytest.mark.asyncio
async def test_connect_success():
    """Successful connect returns a TcpTransport with reader and writer."""
    mock_reader = AsyncMock(spec=asyncio.StreamReader)
    mock_writer = MagicMock(spec=asyncio.StreamWriter)

    async def fake_open_connection(host, port):
        return mock_reader, mock_writer

    with patch(
        "arrdipi.transport.tcp.asyncio.wait_for",
        new_callable=AsyncMock,
        return_value=(mock_reader, mock_writer),
    ):
        transport = await TcpTransport.connect("10.0.0.1", 3389, timeout=5.0)

    assert transport.reader is mock_reader
    assert transport.writer is mock_writer


@pytest.mark.asyncio
async def test_send_writes_data_and_drains():
    """send() writes data to the writer and calls drain."""
    mock_reader = AsyncMock(spec=asyncio.StreamReader)
    mock_writer = MagicMock(spec=asyncio.StreamWriter)
    mock_writer.drain = AsyncMock()

    transport = TcpTransport(reader=mock_reader, writer=mock_writer)
    data = b"\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00"

    await transport.send(data)

    mock_writer.write.assert_called_once_with(data)
    mock_writer.drain.assert_awaited_once()


@pytest.mark.asyncio
async def test_recv_reads_exact_bytes():
    """recv(n) reads exactly n bytes using readexactly."""
    mock_reader = AsyncMock(spec=asyncio.StreamReader)
    expected_data = b"\x03\x00\x00\x08\x02\xf0\x80\x00"
    mock_reader.readexactly = AsyncMock(return_value=expected_data)

    mock_writer = MagicMock(spec=asyncio.StreamWriter)
    transport = TcpTransport(reader=mock_reader, writer=mock_writer)

    result = await transport.recv(8)

    assert result == expected_data
    mock_reader.readexactly.assert_awaited_once_with(8)


@pytest.mark.asyncio
async def test_recv_raises_on_incomplete_read():
    """recv() propagates IncompleteReadError when connection drops."""
    mock_reader = AsyncMock(spec=asyncio.StreamReader)
    mock_reader.readexactly = AsyncMock(
        side_effect=asyncio.IncompleteReadError(partial=b"\x03\x00", expected=8)
    )

    mock_writer = MagicMock(spec=asyncio.StreamWriter)
    transport = TcpTransport(reader=mock_reader, writer=mock_writer)

    with pytest.raises(asyncio.IncompleteReadError):
        await transport.recv(8)


@pytest.mark.asyncio
async def test_close_closes_writer():
    """close() calls writer.close() and wait_closed()."""
    mock_reader = AsyncMock(spec=asyncio.StreamReader)
    mock_writer = MagicMock(spec=asyncio.StreamWriter)
    mock_writer.wait_closed = AsyncMock()

    transport = TcpTransport(reader=mock_reader, writer=mock_writer)

    await transport.close()

    mock_writer.close.assert_called_once()
    mock_writer.wait_closed.assert_awaited_once()


@pytest.mark.asyncio
async def test_upgrade_to_tls_replaces_reader():
    """upgrade_to_tls() upgrades the transport and replaces the reader."""
    mock_reader = AsyncMock(spec=asyncio.StreamReader)
    mock_writer = MagicMock(spec=asyncio.StreamWriter)

    # Mock the underlying transport and protocol
    mock_transport = MagicMock()
    mock_protocol = MagicMock()
    mock_transport.get_protocol.return_value = mock_protocol
    mock_writer.transport = mock_transport
    mock_writer._transport = mock_transport

    # Mock the new TLS transport
    mock_tls_transport = MagicMock()
    mock_tls_transport.set_protocol = MagicMock()

    mock_ssl_context = MagicMock(spec=ssl.SSLContext)

    transport = TcpTransport(reader=mock_reader, writer=mock_writer)

    with patch("asyncio.get_event_loop") as mock_get_loop:
        mock_loop = MagicMock()
        mock_loop.start_tls = AsyncMock(return_value=mock_tls_transport)
        mock_get_loop.return_value = mock_loop

        await transport.upgrade_to_tls(mock_ssl_context, "rdp.example.com")

    # Verify start_tls was called with correct args
    mock_loop.start_tls.assert_awaited_once_with(
        mock_transport,
        mock_protocol,
        mock_ssl_context,
        server_hostname="rdp.example.com",
    )

    # Reader should be replaced with a new StreamReader
    assert transport.reader is not mock_reader
    assert isinstance(transport.reader, asyncio.StreamReader)


@pytest.mark.asyncio
async def test_connect_timeout_default_value():
    """Default timeout is 5.0 seconds."""
    with patch(
        "arrdipi.transport.tcp.asyncio.wait_for",
        side_effect=asyncio.TimeoutError(),
    ) as mock_wait_for:
        with pytest.raises(ConnectionTimeoutError) as exc_info:
            await TcpTransport.connect("example.com", 3389)

        assert exc_info.value.timeout == 5.0


@pytest.mark.asyncio
async def test_send_recv_data_flow():
    """End-to-end data flow: send data, then receive response."""
    mock_reader = AsyncMock(spec=asyncio.StreamReader)
    mock_writer = MagicMock(spec=asyncio.StreamWriter)
    mock_writer.drain = AsyncMock()

    # Simulate sending a request and receiving a response
    request_data = b"\x03\x00\x00\x13"
    response_data = b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x00"
    mock_reader.readexactly = AsyncMock(return_value=response_data)

    transport = TcpTransport(reader=mock_reader, writer=mock_writer)

    # Send request
    await transport.send(request_data)
    mock_writer.write.assert_called_once_with(request_data)

    # Receive response
    result = await transport.recv(9)
    assert result == response_data
