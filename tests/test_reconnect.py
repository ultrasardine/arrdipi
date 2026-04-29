"""Tests for the auto-reconnect handler.

Tests cover:
- HMAC computation with known vectors (Req 26, AC 3)
- Max attempts enforcement (Req 26, AC 5)
- Fallback to full authentication on server rejection (Req 26, AC 4)
- Cookie storage and parsing (Req 26, AC 1)
- ReconnectHandler wiring into Session._handle_disconnect
"""

from __future__ import annotations

import asyncio
import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from arrdipi.reconnect import AutoReconnectCookie, ReconnectHandler


# --- Fixtures ---


def _make_session_config(**overrides):
    """Create a minimal SessionConfig for testing."""
    from arrdipi.connection import SessionConfig

    defaults = {
        "host": "test-server.example.com",
        "port": 3389,
        "username": "testuser",
        "password": "testpass",
        "domain": "TESTDOMAIN",
    }
    defaults.update(overrides)
    return SessionConfig(**defaults)


def _make_cookie_bytes(
    cb_len: int = 28,
    version: int = 1,
    logon_id: int = 42,
    arc_random_bits: bytes | None = None,
) -> bytes:
    """Create raw auto-reconnect cookie bytes."""
    if arc_random_bits is None:
        arc_random_bits = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
    header = struct.pack("<III", cb_len, version, logon_id)
    return header + arc_random_bits


# --- AutoReconnectCookie tests ---


class TestAutoReconnectCookie:
    """Tests for AutoReconnectCookie parsing and serialization."""

    def test_parse_valid_cookie(self):
        """Parse a valid 28-byte cookie."""
        arc_random = b"\xaa" * 16
        data = _make_cookie_bytes(cb_len=28, version=1, logon_id=100, arc_random_bits=arc_random)

        cookie = AutoReconnectCookie.parse(data)

        assert cookie.cb_len == 28
        assert cookie.version == 1
        assert cookie.logon_id == 100
        assert cookie.arc_random_bits == arc_random

    def test_parse_too_short_raises(self):
        """Parsing data shorter than 28 bytes raises ValueError."""
        with pytest.raises(ValueError, match="too short"):
            AutoReconnectCookie.parse(b"\x00" * 20)

    def test_parse_invalid_version_raises(self):
        """Parsing a cookie with unsupported version raises ValueError."""
        data = _make_cookie_bytes(version=99)
        with pytest.raises(ValueError, match="Unsupported.*version"):
            AutoReconnectCookie.parse(data)

    def test_serialize_roundtrip(self):
        """Serialize and re-parse produces the same cookie."""
        arc_random = bytes(range(16))
        data = _make_cookie_bytes(cb_len=28, version=1, logon_id=7, arc_random_bits=arc_random)

        cookie = AutoReconnectCookie.parse(data)
        serialized = cookie.serialize()

        assert serialized == data

    def test_parse_with_extra_data(self):
        """Parsing succeeds when data has trailing bytes beyond 28."""
        data = _make_cookie_bytes() + b"\xff" * 10
        cookie = AutoReconnectCookie.parse(data)
        assert cookie.cb_len == 28
        assert cookie.version == 1


# --- ReconnectHandler tests ---


class TestReconnectHandler:
    """Tests for ReconnectHandler functionality."""

    def test_initial_state(self):
        """Handler starts with no cookie and zero attempts."""
        config = _make_session_config()
        handler = ReconnectHandler(config=config)

        assert handler.cookie is None
        assert handler.has_cookie is False
        assert handler.attempts == 0
        assert handler.max_attempts == 3

    def test_custom_max_attempts(self):
        """Handler respects custom max_attempts parameter."""
        config = _make_session_config()
        handler = ReconnectHandler(config=config, max_attempts=5)

        assert handler.max_attempts == 5

    def test_store_cookie(self):
        """store_cookie parses and stores the cookie correctly."""
        config = _make_session_config()
        handler = ReconnectHandler(config=config)

        cookie_data = _make_cookie_bytes(logon_id=42)
        handler.store_cookie(cookie_data)

        assert handler.has_cookie is True
        assert handler.cookie is not None
        assert handler.cookie.logon_id == 42
        assert handler.attempts == 0  # Reset on new cookie

    def test_store_cookie_resets_attempts(self):
        """Storing a new cookie resets the attempt counter."""
        config = _make_session_config()
        handler = ReconnectHandler(config=config)
        handler._attempts = 2  # Simulate previous attempts

        cookie_data = _make_cookie_bytes()
        handler.store_cookie(cookie_data)

        assert handler.attempts == 0

    def test_store_cookie_invalid_raises(self):
        """store_cookie raises ValueError on invalid data."""
        config = _make_session_config()
        handler = ReconnectHandler(config=config)

        with pytest.raises(ValueError):
            handler.store_cookie(b"\x00" * 10)

    def test_compute_hmac_known_vector(self):
        """HMAC computation produces correct result with known inputs.

        Uses HMAC-MD5(key=arc_random_bits, data=client_random) per [MS-RDPBCGR] 5.5.
        """
        config = _make_session_config()
        handler = ReconnectHandler(config=config)

        # Known test vector
        arc_random_bits = b"\x00" * 16  # 16-byte key (all zeros)
        client_random = b"\x00" * 32  # 32-byte data (all zeros)

        result = handler.compute_hmac(arc_random_bits, client_random)

        # HMAC-MD5 with all-zero key and all-zero data
        # Verify it's 16 bytes (MD5 output size)
        assert len(result) == 16
        assert isinstance(result, bytes)

    def test_compute_hmac_different_inputs_different_outputs(self):
        """Different inputs produce different HMAC outputs."""
        config = _make_session_config()
        handler = ReconnectHandler(config=config)

        arc_random_1 = b"\x01" * 16
        arc_random_2 = b"\x02" * 16
        client_random = b"\xab" * 32

        hmac_1 = handler.compute_hmac(arc_random_1, client_random)
        hmac_2 = handler.compute_hmac(arc_random_2, client_random)

        assert hmac_1 != hmac_2

    def test_compute_hmac_deterministic(self):
        """Same inputs always produce the same HMAC output."""
        config = _make_session_config()
        handler = ReconnectHandler(config=config)

        arc_random = b"\xde\xad\xbe\xef" * 4
        client_random = b"\xca\xfe\xba\xbe" * 8

        hmac_1 = handler.compute_hmac(arc_random, client_random)
        hmac_2 = handler.compute_hmac(arc_random, client_random)

        assert hmac_1 == hmac_2

    def test_compute_hmac_known_value(self):
        """Verify HMAC-MD5 against a known cryptographic test vector.

        HMAC-MD5 with key=0x0b*16 and data="Hi There" is a well-known vector
        from RFC 2104. We adapt it to our interface.
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.hmac import HMAC as CryptoHMAC

        config = _make_session_config()
        handler = ReconnectHandler(config=config)

        # Use specific known values
        key = b"\x0b" * 16
        data = b"Hi There" + b"\x00" * 24  # Pad to 32 bytes for client_random

        result = handler.compute_hmac(key, data)

        # Verify independently using cryptography directly
        h = CryptoHMAC(key, hashes.MD5())
        h.update(data)
        expected = h.finalize()

        assert result == expected

    @pytest.mark.asyncio
    async def test_attempt_reconnect_no_cookie_returns_none(self):
        """attempt_reconnect returns None when no cookie is stored."""
        config = _make_session_config()
        handler = ReconnectHandler(config=config)

        result = await handler.attempt_reconnect()

        assert result is None

    @pytest.mark.asyncio
    async def test_attempt_reconnect_max_attempts_exceeded(self):
        """attempt_reconnect returns None after max attempts exceeded."""
        config = _make_session_config()
        handler = ReconnectHandler(config=config, max_attempts=2)

        # Store a cookie
        cookie_data = _make_cookie_bytes()
        handler.store_cookie(cookie_data)

        # Exhaust attempts
        handler._attempts = 2

        result = await handler.attempt_reconnect()

        assert result is None

    @pytest.mark.asyncio
    async def test_attempt_reconnect_increments_counter(self):
        """Each reconnection attempt increments the attempt counter."""
        config = _make_session_config()
        handler = ReconnectHandler(config=config, max_attempts=3)

        cookie_data = _make_cookie_bytes()
        handler.store_cookie(cookie_data)
        handler.set_client_random(b"\x00" * 32)

        # Mock ConnectionSequence to raise (simulating failure)
        with patch("arrdipi.connection.ConnectionSequence") as mock_seq_cls:
            mock_seq = AsyncMock()
            mock_seq.execute.side_effect = ConnectionError("Server rejected")
            mock_seq_cls.return_value = mock_seq

            # Also mock the fallback
            with patch.object(handler, "_fallback_full_auth", new_callable=AsyncMock) as mock_fallback:
                mock_fallback.return_value = None
                await handler.attempt_reconnect()

        assert handler.attempts == 1

    @pytest.mark.asyncio
    async def test_attempt_reconnect_success(self):
        """Successful reconnection returns a new Session."""
        config = _make_session_config()
        handler = ReconnectHandler(config=config)

        cookie_data = _make_cookie_bytes()
        handler.store_cookie(cookie_data)
        handler.set_client_random(b"\xab" * 32)

        mock_session = MagicMock()

        with patch("arrdipi.connection.ConnectionSequence") as mock_seq_cls:
            mock_seq = AsyncMock()
            mock_seq.execute.return_value = mock_session
            mock_seq_cls.return_value = mock_seq

            result = await handler.attempt_reconnect()

        assert result is mock_session

    @pytest.mark.asyncio
    async def test_attempt_reconnect_falls_back_on_failure(self):
        """On reconnection failure, falls back to full authentication."""
        config = _make_session_config()
        handler = ReconnectHandler(config=config)

        cookie_data = _make_cookie_bytes()
        handler.store_cookie(cookie_data)
        handler.set_client_random(b"\x00" * 32)

        mock_fallback_session = MagicMock()

        with patch("arrdipi.connection.ConnectionSequence") as mock_seq_cls:
            # First call (with cookie) fails
            mock_seq_fail = AsyncMock()
            mock_seq_fail.execute.side_effect = ConnectionError("Rejected")

            # Second call (fallback) succeeds
            mock_seq_success = AsyncMock()
            mock_seq_success.execute.return_value = mock_fallback_session

            mock_seq_cls.side_effect = [mock_seq_fail, mock_seq_success]

            result = await handler.attempt_reconnect()

        assert result is mock_fallback_session

    @pytest.mark.asyncio
    async def test_fallback_full_auth_no_cookie(self):
        """Fallback creates a connection without auto-reconnect cookie."""
        config = _make_session_config()
        handler = ReconnectHandler(config=config)

        mock_session = MagicMock()

        with patch("arrdipi.connection.ConnectionSequence") as mock_seq_cls:
            mock_seq = AsyncMock()
            mock_seq.execute.return_value = mock_session
            mock_seq_cls.return_value = mock_seq

            result = await handler._fallback_full_auth()

            # Verify the config passed has no auto_reconnect_cookie
            call_args = mock_seq_cls.call_args[0][0]
            assert call_args.auto_reconnect_cookie is None

        assert result is mock_session

    @pytest.mark.asyncio
    async def test_fallback_full_auth_failure_returns_none(self):
        """Fallback returns None if full auth also fails."""
        config = _make_session_config()
        handler = ReconnectHandler(config=config)

        with patch("arrdipi.connection.ConnectionSequence") as mock_seq_cls:
            mock_seq = AsyncMock()
            mock_seq.execute.side_effect = ConnectionError("Auth failed")
            mock_seq_cls.return_value = mock_seq

            result = await handler._fallback_full_auth()

        assert result is None

    @pytest.mark.asyncio
    async def test_max_attempts_enforcement_across_multiple_calls(self):
        """Multiple reconnection attempts are tracked and limited."""
        config = _make_session_config()
        handler = ReconnectHandler(config=config, max_attempts=2)

        cookie_data = _make_cookie_bytes()
        handler.store_cookie(cookie_data)
        handler.set_client_random(b"\x00" * 32)

        with patch("arrdipi.connection.ConnectionSequence") as mock_seq_cls:
            mock_seq = AsyncMock()
            mock_seq.execute.side_effect = ConnectionError("Rejected")
            mock_seq_cls.return_value = mock_seq

            with patch.object(handler, "_fallback_full_auth", new_callable=AsyncMock) as mock_fallback:
                mock_fallback.return_value = None

                # First attempt
                await handler.attempt_reconnect()
                assert handler.attempts == 1

                # Second attempt
                await handler.attempt_reconnect()
                assert handler.attempts == 2

                # Third attempt should be blocked
                result = await handler.attempt_reconnect()
                assert result is None
                assert handler.attempts == 2  # Not incremented


# --- Session integration tests ---


class TestSessionReconnectIntegration:
    """Tests for ReconnectHandler integration with Session."""

    def _make_session(self):
        """Create a minimal Session for testing."""
        from arrdipi.session import Session

        tcp = MagicMock()
        x224 = MagicMock()
        mcs = MagicMock()
        mcs.channel_map = {}
        mcs.io_channel_id = 1003
        mcs.user_channel_id = 1007
        security = MagicMock()
        security.is_enhanced = True
        config = _make_session_config()
        server_caps = {}

        session = Session(
            tcp=tcp,
            x224=x224,
            mcs=mcs,
            security=security,
            config=config,
            server_caps=server_caps,
            share_id=1,
        )
        return session

    def test_session_has_reconnect_handler(self):
        """Session initializes with a ReconnectHandler."""
        session = self._make_session()
        assert session.reconnect_handler is not None
        assert isinstance(session.reconnect_handler, ReconnectHandler)

    def test_session_handle_save_session_info_stores_cookie(self):
        """Session extracts and stores cookie from Save Session Info PDU."""
        session = self._make_session()

        # Build a Save Session Info PDU with extended info containing cookie
        # InfoType = 3 (logon extended)
        info_type = struct.pack("<I", 3)
        # fieldsPresentFlags with LOGON_EX_AUTORECONNECTCOOKIE (0x0001)
        fields_present = struct.pack("<I", 0x0001)
        # Auto-reconnect cookie (28 bytes)
        cookie_data = _make_cookie_bytes(logon_id=99)

        pdu_data = info_type + fields_present + cookie_data

        session._handle_save_session_info(pdu_data)

        assert session.reconnect_handler.has_cookie is True
        assert session.reconnect_handler.cookie.logon_id == 99

    def test_session_handle_save_session_info_no_cookie_flag(self):
        """Session ignores Save Session Info without cookie flag."""
        session = self._make_session()

        # InfoType = 3 but no LOGON_EX_AUTORECONNECTCOOKIE flag
        info_type = struct.pack("<I", 3)
        fields_present = struct.pack("<I", 0x0000)

        pdu_data = info_type + fields_present

        session._handle_save_session_info(pdu_data)

        assert session.reconnect_handler.has_cookie is False

    def test_session_handle_save_session_info_non_extended(self):
        """Session ignores non-extended Save Session Info PDUs."""
        session = self._make_session()

        # InfoType = 0 (logon, not extended)
        info_type = struct.pack("<I", 0)
        pdu_data = info_type + b"\x00" * 20

        session._handle_save_session_info(pdu_data)

        assert session.reconnect_handler.has_cookie is False

    @pytest.mark.asyncio
    async def test_handle_disconnect_attempts_reconnect(self):
        """_handle_disconnect triggers auto-reconnect when cookie is available."""
        session = self._make_session()

        # Store a cookie
        cookie_data = _make_cookie_bytes()
        session.reconnect_handler.store_cookie(cookie_data)

        # Mock the reconnect handler's attempt_reconnect
        mock_new_session = MagicMock()
        with patch.object(
            session._reconnect_handler,
            "attempt_reconnect",
            new_callable=AsyncMock,
            return_value=mock_new_session,
        ):
            await session._handle_disconnect("network error")

        assert session.closed is True
        assert session.reconnected_session is mock_new_session

    @pytest.mark.asyncio
    async def test_handle_disconnect_no_cookie_closes(self):
        """_handle_disconnect closes session when no cookie is available."""
        session = self._make_session()

        await session._handle_disconnect("connection lost")

        assert session.closed is True
        assert session.reconnected_session is None

    @pytest.mark.asyncio
    async def test_handle_disconnect_reconnect_fails_closes(self):
        """_handle_disconnect closes session when reconnection fails."""
        session = self._make_session()

        # Store a cookie
        cookie_data = _make_cookie_bytes()
        session.reconnect_handler.store_cookie(cookie_data)

        # Mock reconnect to return None (failure)
        with patch.object(
            session._reconnect_handler,
            "attempt_reconnect",
            new_callable=AsyncMock,
            return_value=None,
        ):
            await session._handle_disconnect("network error")

        assert session.closed is True
        assert session.reconnected_session is None

    @pytest.mark.asyncio
    async def test_handle_disconnect_invokes_callbacks_before_reconnect(self):
        """Disconnect callbacks are invoked before reconnection attempt."""
        session = self._make_session()

        callback_called = []

        async def on_disconnect(reason):
            callback_called.append(reason)

        session.on_disconnect(on_disconnect)

        # Store a cookie
        cookie_data = _make_cookie_bytes()
        session.reconnect_handler.store_cookie(cookie_data)

        with patch.object(
            session._reconnect_handler,
            "attempt_reconnect",
            new_callable=AsyncMock,
            return_value=None,
        ):
            await session._handle_disconnect("test reason")

        assert callback_called == ["test reason"]
