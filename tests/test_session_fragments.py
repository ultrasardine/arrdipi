"""Tests for Session fragment reassembly (Req 6, AC 1–8).

Tests cover:
- Full FIRST → NEXT → LAST reassembly sequence
- SINGLE fragment dispatched immediately
- Duplicate FIRST discards incomplete buffer with warning
- NEXT without preceding FIRST is rejected
- LAST without preceding FIRST is rejected
- MaxRequestSize overflow discards buffer
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from arrdipi.pdu.capabilities import FASTPATH_OUTPUT_SUPPORTED, GeneralCapabilitySet
from arrdipi.pdu.fastpath import FastPathOutputFragmentation
from arrdipi.pdu.types import CapabilitySetType
from arrdipi.session import Session


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_session(max_request_size: int = 262144) -> Session:
    """Create a minimal Session with mocked dependencies for fragment testing."""
    mock_tcp = MagicMock()
    mock_x224 = MagicMock()
    mock_mcs = MagicMock()
    mock_mcs.user_channel_id = 1007
    mock_mcs.io_channel_id = 1003
    mock_mcs.channel_map = {}

    mock_security = MagicMock()
    mock_security.is_enhanced = True

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
    session._max_request_size = max_request_size
    return session


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

FRAG_SINGLE = FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE
FRAG_FIRST = FastPathOutputFragmentation.FASTPATH_FRAGMENT_FIRST
FRAG_NEXT = FastPathOutputFragmentation.FASTPATH_FRAGMENT_NEXT
FRAG_LAST = FastPathOutputFragmentation.FASTPATH_FRAGMENT_LAST

UPDATE_BITMAP = 0x01


class TestReassembleFragment:
    """Tests for Session._reassemble_fragment()."""

    def test_single_returns_data_immediately(self):
        """SINGLE fragmentation returns data as-is without buffering."""
        session = _make_session()
        data = b"\x01\x02\x03\x04"

        result = session._reassemble_fragment(UPDATE_BITMAP, FRAG_SINGLE, data)

        assert result == data
        assert UPDATE_BITMAP not in session._fragment_buffers

    def test_full_first_next_last_sequence(self):
        """Full FIRST → NEXT → LAST sequence reassembles correctly."""
        session = _make_session()
        part1 = b"AAAA"
        part2 = b"BBBB"
        part3 = b"CCCC"

        # FIRST: starts buffer, returns None
        result = session._reassemble_fragment(UPDATE_BITMAP, FRAG_FIRST, part1)
        assert result is None
        assert UPDATE_BITMAP in session._fragment_buffers

        # NEXT: appends to buffer, returns None
        result = session._reassemble_fragment(UPDATE_BITMAP, FRAG_NEXT, part2)
        assert result is None
        assert UPDATE_BITMAP in session._fragment_buffers

        # LAST: completes and returns full reassembled data
        result = session._reassemble_fragment(UPDATE_BITMAP, FRAG_LAST, part3)
        assert result == b"AAAABBBBCCCC"
        assert UPDATE_BITMAP not in session._fragment_buffers

    def test_first_next_next_last_sequence(self):
        """Multiple NEXT fragments accumulate correctly."""
        session = _make_session()

        session._reassemble_fragment(UPDATE_BITMAP, FRAG_FIRST, b"A")
        session._reassemble_fragment(UPDATE_BITMAP, FRAG_NEXT, b"B")
        session._reassemble_fragment(UPDATE_BITMAP, FRAG_NEXT, b"C")
        session._reassemble_fragment(UPDATE_BITMAP, FRAG_NEXT, b"D")
        result = session._reassemble_fragment(UPDATE_BITMAP, FRAG_LAST, b"E")

        assert result == b"ABCDE"

    def test_duplicate_first_discards_incomplete_buffer(self, caplog):
        """A new FIRST discards any existing incomplete buffer with a warning."""
        session = _make_session()

        # Start first sequence
        session._reassemble_fragment(UPDATE_BITMAP, FRAG_FIRST, b"OLD_DATA")
        session._reassemble_fragment(UPDATE_BITMAP, FRAG_NEXT, b"MORE")

        # Another FIRST arrives — should discard existing buffer
        with caplog.at_level("WARNING"):
            result = session._reassemble_fragment(UPDATE_BITMAP, FRAG_FIRST, b"NEW")

        assert result is None
        assert "Discarding incomplete fragment buffer" in caplog.text
        # Buffer now contains only the new data
        assert session._fragment_buffers[UPDATE_BITMAP] == bytearray(b"NEW")

        # LAST completes with the new buffer
        result = session._reassemble_fragment(UPDATE_BITMAP, FRAG_LAST, b"_END")
        assert result == b"NEW_END"

    def test_next_without_first_is_rejected(self, caplog):
        """NEXT fragment without a preceding FIRST returns None with error."""
        session = _make_session()

        with caplog.at_level("ERROR"):
            result = session._reassemble_fragment(UPDATE_BITMAP, FRAG_NEXT, b"orphan")

        assert result is None
        assert "NEXT fragment without FIRST" in caplog.text

    def test_last_without_first_is_rejected(self, caplog):
        """LAST fragment without a preceding FIRST returns None with error."""
        session = _make_session()

        with caplog.at_level("ERROR"):
            result = session._reassemble_fragment(UPDATE_BITMAP, FRAG_LAST, b"orphan")

        assert result is None
        assert "LAST fragment without preceding FIRST" in caplog.text

    def test_max_request_size_overflow(self, caplog):
        """Buffer exceeding MaxRequestSize is discarded with error."""
        session = _make_session(max_request_size=10)

        # FIRST with 6 bytes — fits
        session._reassemble_fragment(UPDATE_BITMAP, FRAG_FIRST, b"123456")
        assert UPDATE_BITMAP in session._fragment_buffers

        # NEXT with 6 more bytes → total 12, exceeds limit of 10
        with caplog.at_level("ERROR"):
            result = session._reassemble_fragment(UPDATE_BITMAP, FRAG_NEXT, b"789012")

        assert result is None
        assert "Fragment buffer exceeds MaxRequestSize" in caplog.text
        assert UPDATE_BITMAP not in session._fragment_buffers

    def test_independent_update_codes(self):
        """Different update codes maintain independent fragment buffers."""
        session = _make_session()
        code_a = 0x01  # BITMAP
        code_b = 0x00  # ORDERS

        # Start both
        session._reassemble_fragment(code_a, FRAG_FIRST, b"A1")
        session._reassemble_fragment(code_b, FRAG_FIRST, b"B1")

        # Append to both
        session._reassemble_fragment(code_a, FRAG_NEXT, b"A2")
        session._reassemble_fragment(code_b, FRAG_NEXT, b"B2")

        # Complete code_b first
        result_b = session._reassemble_fragment(code_b, FRAG_LAST, b"B3")
        assert result_b == b"B1B2B3"
        assert code_a in session._fragment_buffers  # Still accumulating

        # Complete code_a
        result_a = session._reassemble_fragment(code_a, FRAG_LAST, b"A3")
        assert result_a == b"A1A2A3"

    def test_max_request_size_exactly_at_limit(self):
        """Buffer exactly at MaxRequestSize is still valid (limit is exclusive)."""
        session = _make_session(max_request_size=10)

        # FIRST with 5 bytes
        session._reassemble_fragment(UPDATE_BITMAP, FRAG_FIRST, b"12345")

        # NEXT with 5 more bytes → total 10, exactly at limit — should pass
        result = session._reassemble_fragment(UPDATE_BITMAP, FRAG_NEXT, b"67890")
        assert result is None
        assert UPDATE_BITMAP in session._fragment_buffers

        # LAST completes it
        result = session._reassemble_fragment(UPDATE_BITMAP, FRAG_LAST, b"X")
        assert result == b"1234567890X"
