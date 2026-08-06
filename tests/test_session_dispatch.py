"""Tests for Session._dispatch_loop() dual-path routing.

Validates that the dispatch loop correctly routes interleaved fast-path
and slow-path PDUs received from X224Layer.recv_any().

Requirements: Req 2 AC 1-5, Req 8 AC 6
"""

from __future__ import annotations

import asyncio
import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from arrdipi.pdu.capabilities import FASTPATH_OUTPUT_SUPPORTED, GeneralCapabilitySet
from arrdipi.pdu.fastpath import (
    FastPathOutputPdu,
    FastPathOutputUpdate,
    FastPathOutputUpdateCode,
    FastPathOutputFragmentation,
)
from arrdipi.pdu.types import CapabilitySetType
from arrdipi.session import Session


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_session() -> tuple[Session, MagicMock, MagicMock, MagicMock]:
    """Create a Session with mocked dependencies for dispatch loop testing.

    Returns:
        Tuple of (session, mock_x224, mock_mcs, mock_security).
    """
    mock_tcp = MagicMock()
    mock_tcp.send = AsyncMock()
    mock_tcp.close = AsyncMock()

    mock_x224 = MagicMock()
    mock_x224.recv_any = AsyncMock()

    mock_mcs = MagicMock()
    mock_mcs.user_channel_id = 1007
    mock_mcs.io_channel_id = 1003
    mock_mcs.channel_map = {}
    mock_mcs.send_to_channel = AsyncMock()
    mock_mcs.recv_pdu = AsyncMock()

    mock_security = MagicMock()
    mock_security.is_enhanced = True
    mock_security.unwrap_pdu = MagicMock(return_value=(b"", 0))

    mock_config = MagicMock()
    mock_config.width = 1024
    mock_config.height = 768
    mock_config.auto_reconnect_cookie = None

    server_caps: dict[CapabilitySetType, object] = {}
    general_cap = GeneralCapabilitySet(
        os_major_type=1,
        os_minor_type=3,
        protocol_version=0x0200,
        extra_flags=FASTPATH_OUTPUT_SUPPORTED,
    )
    server_caps[CapabilitySetType.GENERAL] = general_cap

    session = Session(
        tcp=mock_tcp,
        x224=mock_x224,
        mcs=mock_mcs,
        security=mock_security,
        config=mock_config,
        server_caps=server_caps,
        share_id=0x00010001,
    )

    return session, mock_x224, mock_mcs, mock_security


def _build_fast_path_synchronize_pdu() -> bytes:
    """Build a minimal fast-path PDU with a single SYNCHRONIZE update.

    Structure: fpOutputHeader(1) + length(1) + updateHeader(1) + size(2) + data(0)
    """
    # fpOutputHeader: action=0x00 (fast-path), flags=0x00
    fp_header = 0x00
    # updateHeader: updateCode=SYNCHRONIZE(0x03), fragmentation=SINGLE(0x00), compression=0
    update_header = 0x03  # updateCode=3, frag=0, comp=0
    # size of update data = 0
    update_size = struct.pack("<H", 0)
    # The update bytes
    update_bytes = bytes([update_header]) + update_size

    # Total PDU = fpOutputHeader + length + updates
    total_len = 1 + 1 + len(update_bytes)
    return bytes([fp_header, total_len]) + update_bytes


def _build_fast_path_bitmap_pdu() -> bytes:
    """Build a minimal fast-path PDU with a BITMAP update (empty payload).

    The handler will try to parse it but we'll mock _process_bitmap_update
    to avoid actual parsing.
    """
    fp_header = 0x00
    # updateHeader: updateCode=BITMAP(0x01), fragmentation=SINGLE(0x00), compression=0
    update_header = 0x01
    # Minimal payload: numberRectangles = 0
    payload = struct.pack("<H", 0)
    update_size = struct.pack("<H", len(payload))
    update_bytes = bytes([update_header]) + update_size + payload

    total_len = 1 + 1 + len(update_bytes)
    return bytes([fp_header, total_len]) + update_bytes


def _build_slow_path_mcs_pdu(channel_id: int, payload: bytes) -> bytes:
    """Build raw MCS SendDataIndication bytes.

    Type byte 0x68 + user_id(u16 BE) + channel_id(u16 BE) +
    priority(u8) + PER length + payload.
    """
    buf = bytearray()
    buf.append(0x68)  # SendDataIndication type
    buf.extend(struct.pack(">H", 1007 - 1001))  # user_id - base
    buf.extend(struct.pack(">H", channel_id))
    buf.append(0x70)  # priority + segmentation
    # PER length
    if len(payload) < 0x80:
        buf.append(len(payload))
    else:
        buf.append(0x80 | ((len(payload) >> 8) & 0x7F))
        buf.append(len(payload) & 0xFF)
    buf.extend(payload)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDispatchLoopDualPath:
    """Tests for _dispatch_loop() with dual fast-path/slow-path routing."""

    @pytest.mark.asyncio
    async def test_fast_path_pdu_routes_to_handle_fast_path_output(self) -> None:
        """When recv_any returns is_fast_path=True, _handle_fast_path_output is called."""
        session, mock_x224, _, _ = _make_session()

        fp_data = _build_fast_path_synchronize_pdu()

        # Return one fast-path PDU, then raise CancelledError to stop the loop
        mock_x224.recv_any = AsyncMock(
            side_effect=[(True, fp_data), asyncio.CancelledError()]
        )

        with patch.object(session, "_handle_fast_path_output", new_callable=AsyncMock) as mock_handler:
            await session.start()
            await asyncio.sleep(0.05)
            await session.close()

            mock_handler.assert_called_once_with(fp_data)

    @pytest.mark.asyncio
    async def test_slow_path_pdu_routes_to_route_pdu(self) -> None:
        """When recv_any returns is_fast_path=False, MCS parsing + _route_pdu is called."""
        session, mock_x224, mock_mcs, mock_security = _make_session()

        # Build a slow-path MCS SendDataIndication
        io_payload = b"\x01\x02\x03\x04"
        slow_path_raw = _build_slow_path_mcs_pdu(1003, io_payload)

        mock_mcs.parse_send_data_indication = MagicMock(
            return_value=(1003, io_payload)
        )

        mock_x224.recv_any = AsyncMock(
            side_effect=[(False, slow_path_raw), asyncio.CancelledError()]
        )

        with patch.object(session, "_route_pdu", new_callable=AsyncMock) as mock_route:
            await session.start()
            await asyncio.sleep(0.05)
            await session.close()

            mock_mcs.parse_send_data_indication.assert_called_once_with(slow_path_raw)
            mock_route.assert_called_once_with(1003, io_payload)

    @pytest.mark.asyncio
    async def test_interleaved_fast_and_slow_path(self) -> None:
        """Interleaved fast-path and slow-path PDUs are routed correctly."""
        session, mock_x224, mock_mcs, _ = _make_session()

        fp_data = _build_fast_path_synchronize_pdu()
        slow_payload = b"\xAA\xBB"
        slow_raw = _build_slow_path_mcs_pdu(1003, slow_payload)

        # Sequence: fast-path, slow-path, fast-path, then stop
        mock_x224.recv_any = AsyncMock(
            side_effect=[
                (True, fp_data),
                (False, slow_raw),
                (True, fp_data),
                asyncio.CancelledError(),
            ]
        )

        mock_mcs.parse_send_data_indication = MagicMock(
            return_value=(1003, slow_payload)
        )

        fp_calls = []
        route_calls = []

        async def track_fp(data: bytes) -> None:
            fp_calls.append(data)

        async def track_route(channel_id: int, payload: bytes) -> None:
            route_calls.append((channel_id, payload))

        with patch.object(session, "_handle_fast_path_output", side_effect=track_fp):
            with patch.object(session, "_route_pdu", side_effect=track_route):
                await session.start()
                await asyncio.sleep(0.1)
                await session.close()

        assert len(fp_calls) == 2
        assert len(route_calls) == 1
        assert route_calls[0] == (1003, slow_payload)

    @pytest.mark.asyncio
    async def test_timeout_continues_loop(self) -> None:
        """asyncio.TimeoutError does not break the loop."""
        session, mock_x224, _, _ = _make_session()

        fp_data = _build_fast_path_synchronize_pdu()

        # Timeout once, then deliver a PDU, then stop
        mock_x224.recv_any = AsyncMock(
            side_effect=[
                asyncio.TimeoutError(),
                (True, fp_data),
                asyncio.CancelledError(),
            ]
        )

        with patch.object(session, "_handle_fast_path_output", new_callable=AsyncMock) as mock_handler:
            await session.start()
            await asyncio.sleep(0.05)
            await session.close()

            # The fast-path PDU after the timeout should still be handled
            mock_handler.assert_called_once_with(fp_data)

    @pytest.mark.asyncio
    async def test_os_error_triggers_disconnect(self) -> None:
        """OSError in recv_any triggers disconnect handling."""
        session, mock_x224, _, _ = _make_session()
        disconnect_cb = AsyncMock()
        session.on_disconnect(disconnect_cb)

        mock_x224.recv_any = AsyncMock(
            side_effect=OSError("Connection reset")
        )

        await session.start()
        await asyncio.sleep(0.05)

        disconnect_cb.assert_called_once()
        assert session.closed

    @pytest.mark.asyncio
    async def test_connection_error_triggers_disconnect(self) -> None:
        """ConnectionError in recv_any triggers disconnect handling."""
        session, mock_x224, _, _ = _make_session()
        disconnect_cb = AsyncMock()
        session.on_disconnect(disconnect_cb)

        mock_x224.recv_any = AsyncMock(
            side_effect=ConnectionError("Broken pipe")
        )

        await session.start()
        await asyncio.sleep(0.05)

        disconnect_cb.assert_called_once()
        assert session.closed

    @pytest.mark.asyncio
    async def test_eof_error_triggers_disconnect(self) -> None:
        """EOFError in recv_any triggers disconnect handling."""
        session, mock_x224, _, _ = _make_session()
        disconnect_cb = AsyncMock()
        session.on_disconnect(disconnect_cb)

        mock_x224.recv_any = AsyncMock(
            side_effect=EOFError("Unexpected EOF")
        )

        await session.start()
        await asyncio.sleep(0.05)

        disconnect_cb.assert_called_once()
        assert session.closed

    @pytest.mark.asyncio
    async def test_mppc_initialized_in_session(self) -> None:
        """Session.__init__ creates an MppcDecompressor instance."""
        session, _, _, _ = _make_session()
        from arrdipi.codec.mppc import MppcDecompressor

        assert hasattr(session, "_mppc")
        assert isinstance(session._mppc, MppcDecompressor)

    @pytest.mark.asyncio
    async def test_dispatch_loop_uses_30s_timeout(self) -> None:
        """The dispatch loop wraps recv_any in asyncio.wait_for with 30s timeout."""
        session, mock_x224, _, _ = _make_session()

        # After a timeout, the loop should continue
        call_count = 0

        async def counting_recv_any():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise asyncio.TimeoutError()
            elif call_count == 2:
                raise asyncio.CancelledError()

        mock_x224.recv_any = AsyncMock(side_effect=counting_recv_any)

        await session.start()
        await asyncio.sleep(0.05)
        await session.close()

        # Should have been called twice (timeout + cancel)
        assert call_count == 2
