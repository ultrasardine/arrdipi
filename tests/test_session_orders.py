"""Tests for Session._process_orders_update() — task 10.

Verifies that raw drawing order data received via the fast-path ORDERS
update type is correctly forwarded to the GdiOrderProcessor.

(Req 5, AC 1–3)
"""

from __future__ import annotations

import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from arrdipi.graphics.gdi import GdiOrderProcessor
from arrdipi.graphics.surface import GraphicsSurface
from arrdipi.pdu.capabilities import FASTPATH_OUTPUT_SUPPORTED, GeneralCapabilitySet
from arrdipi.pdu.types import CapabilitySetType
from arrdipi.session import Session


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_session() -> Session:
    """Create a Session with mocked dependencies for orders testing."""
    mock_tcp = MagicMock()
    mock_tcp.send = AsyncMock()
    mock_tcp.close = AsyncMock()

    mock_x224 = MagicMock()

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

    general_cap = GeneralCapabilitySet(
        os_major_type=1,
        os_minor_type=3,
        protocol_version=0x0200,
        extra_flags=FASTPATH_OUTPUT_SUPPORTED,
    )
    server_caps = {CapabilitySetType.GENERAL: general_cap}

    session = Session(
        tcp=mock_tcp,
        x224=mock_x224,
        mcs=mock_mcs,
        security=mock_security,
        config=mock_config,
        server_caps=server_caps,
        share_id=0x00010001,
    )
    return session


class TestProcessOrdersUpdate:
    """Tests for Session._process_orders_update()."""

    @pytest.mark.asyncio
    async def test_orders_data_forwarded_to_gdi_processor(self) -> None:
        """Verify that _process_orders_update forwards data to GdiOrderProcessor.process_order_data()."""
        session = _make_session()

        # Patch the _gdi.process_order_data to track calls
        session._gdi.process_order_data = AsyncMock()

        order_data = b"\x01\x00\x04some_order_payload"
        await session._process_orders_update(order_data)

        session._gdi.process_order_data.assert_called_once_with(order_data)

    @pytest.mark.asyncio
    async def test_orders_update_uses_gdi_instance(self) -> None:
        """Verify the session has a GdiOrderProcessor instance linked to its surface."""
        session = _make_session()

        assert isinstance(session._gdi, GdiOrderProcessor)
        # The GDI processor should operate on the same surface as the session
        assert session._gdi._surface is session._surface

    @pytest.mark.asyncio
    async def test_empty_order_data_handled_gracefully(self) -> None:
        """Empty or minimal order data should not raise exceptions."""
        session = _make_session()

        # Empty data
        await session._process_orders_update(b"")

        # Single byte (too short for num_orders)
        await session._process_orders_update(b"\x00")

    @pytest.mark.asyncio
    async def test_zero_orders_count(self) -> None:
        """When numOrders is zero, no processing should occur."""
        session = _make_session()

        # num_orders = 0 (u16 LE)
        data = struct.pack("<H", 0)
        await session._process_orders_update(data)
        # Should complete without error

    @pytest.mark.asyncio
    async def test_orders_reach_gdi_through_fast_path_pipeline(self) -> None:
        """Integration: orders dispatched via _handle_fast_path_output reach GDI."""
        session = _make_session()
        session._gdi.process_order_data = AsyncMock()

        # Build a minimal fast-path output PDU with an ORDERS update
        # fpOutputHeader: action=0x00, reserved=0, flags=0 → byte 0x00
        # length: single-byte form
        # update: updateHeader byte = updateCode(4 bits) | frag(2 bits) | comp(1 bit) | reserved(1 bit)
        #   ORDERS = 0x00, SINGLE frag = 0x00, no compression → 0x00
        # size: u16 LE of payload length
        # payload: arbitrary order bytes

        order_payload = b"\x02\x00\x01\x04\x0A\x05\x00\x00\x00\x01\x02"
        update_header = 0x00  # updateCode=0 (ORDERS), frag=SINGLE, comp=0
        update_size = len(order_payload)
        update_bytes = struct.pack("<B", update_header) + struct.pack("<H", update_size) + order_payload

        # Full PDU: fpOutputHeader(1) + length(1) + updates
        pdu_body = update_bytes
        pdu_length = 1 + 1 + len(pdu_body)  # header + length byte + body
        fp_output_header = 0x00  # action=0, reserved=0, flags=0
        full_pdu = struct.pack("<BB", fp_output_header, pdu_length) + pdu_body

        await session._handle_fast_path_output(full_pdu)

        session._gdi.process_order_data.assert_called_once_with(order_payload)
