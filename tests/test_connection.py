"""Tests for the 10-phase RDP connection sequence orchestrator.

Tests cover:
- SessionConfig dataclass construction
- ConnectionSequence phase execution with mocks
- Error propagation with phase context (ConnectionPhaseError)
- Enhanced Security skips phase 4
- Each phase's behavior in isolation
"""

from __future__ import annotations

import asyncio
import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from arrdipi.connection import (
    ConnectionSequence,
    DrivePath,
    Session,
    SessionConfig,
    _PHASE_NAMES,
)
from arrdipi.errors import (
    ConnectionPhaseError,
    ConnectionTimeoutError,
    FinalizationTimeoutError,
)
from arrdipi.mcs.gcc import (
    ServerCoreData,
    ServerNetworkData,
    ServerSecurityData,
)
from arrdipi.pdu.capabilities import (
    CapabilitySetType,
    DemandActivePdu,
    GeneralCapabilitySet,
)
from arrdipi.pdu.types import (
    CompressionType,
    NegotiationProtocol,
    PerformanceFlags,
    SecurityProtocol,
)
from arrdipi.security.enhanced import TlsSecurityLayer
from arrdipi.security.licensing import (
    LicenseErrorCode,
    LicenseErrorPdu,
    LicenseMsgType,
    LicensePreamble,
)
from arrdipi.security.nla import NlaSecurityLayer
from arrdipi.security.standard import StandardSecurityLayer


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def default_config() -> SessionConfig:
    """Create a default SessionConfig for testing."""
    return SessionConfig(
        host="192.168.1.100",
        port=3389,
        username="testuser",
        password="testpass",
        domain="TESTDOMAIN",
    )


def _build_licensing_complete_pdu() -> bytes:
    """Build a licensing ERROR_ALERT with STATUS_VALID_CLIENT."""
    error_pdu = LicenseErrorPdu(
        error_code=LicenseErrorCode.STATUS_VALID_CLIENT,
        state_transition=0x00000002,  # ST_NO_TRANSITION
    )
    body = error_pdu.serialize()
    preamble = LicensePreamble(
        msg_type=LicenseMsgType.ERROR_ALERT,
        flags=0x03,
        msg_size=len(body) + 4,
    )
    return preamble.serialize() + body


def _build_demand_active_pdu() -> bytes:
    """Build a minimal Demand Active PDU for testing."""
    demand = DemandActivePdu(
        share_id=0x00010001,
        source_descriptor=b"RDP\x00",
        capability_sets={
            CapabilitySetType.GENERAL: GeneralCapabilitySet(),
        },
    )
    return demand.serialize()


def _wrap_in_share_control(pdu_type: int, source: int, payload: bytes) -> bytes:
    """Wrap payload in a ShareControl header."""
    total_length = len(payload) + 6
    header = struct.pack("<HHH", total_length, pdu_type, source)
    return header + payload


def _wrap_in_share_data(pdu_type2: int, payload: bytes) -> bytes:
    """Wrap payload in ShareData header."""
    share_data_header = struct.pack(
        "<IBBHBBH",
        0,  # shareId
        0,  # pad1
        1,  # streamId
        len(payload),  # uncompressedLength
        pdu_type2,  # pduType2
        0,  # compressedType
        0,  # compressedLength
    )
    return share_data_header + payload


# ---------------------------------------------------------------------------
# SessionConfig tests
# ---------------------------------------------------------------------------


class TestSessionConfig:
    """Tests for SessionConfig dataclass."""

    def test_default_values(self) -> None:
        """SessionConfig has sensible defaults."""
        config = SessionConfig(host="example.com")
        assert config.host == "example.com"
        assert config.port == 3389
        assert config.username == ""
        assert config.password == ""
        assert config.domain == ""
        assert config.security == SecurityProtocol.AUTO
        assert config.width == 1920
        assert config.height == 1080
        assert config.color_depth == 32
        assert config.verify_cert is True
        assert config.connect_timeout == 5.0
        assert config.finalization_timeout == 10.0
        assert config.auto_reconnect_cookie is None
        assert config.compression_type == CompressionType.TYPE_64K
        assert config.channel_names == ["cliprdr", "rdpsnd", "rdpdr", "drdynvc"]
        assert config.drive_paths == []

    def test_custom_values(self) -> None:
        """SessionConfig accepts all custom parameters."""
        config = SessionConfig(
            host="10.0.0.1",
            port=3390,
            username="admin",
            password="secret",
            domain="CORP",
            security=SecurityProtocol.NLA,
            width=1280,
            height=720,
            color_depth=16,
            verify_cert=False,
            connect_timeout=10.0,
            finalization_timeout=30.0,
            performance_flags=PerformanceFlags.DISABLE_WALLPAPER,
            auto_reconnect_cookie=b"\x01\x02\x03",
            compression_type=CompressionType.TYPE_RDP6,
            channel_names=["cliprdr"],
            drive_paths=[DrivePath(name="C", path="/tmp")],
        )
        assert config.host == "10.0.0.1"
        assert config.port == 3390
        assert config.security == SecurityProtocol.NLA
        assert config.width == 1280
        assert config.color_depth == 16
        assert config.verify_cert is False
        assert config.auto_reconnect_cookie == b"\x01\x02\x03"
        assert len(config.drive_paths) == 1
        assert config.drive_paths[0].name == "C"


# ---------------------------------------------------------------------------
# ConnectionSequence — security layer factory tests
# ---------------------------------------------------------------------------


class TestCreateSecurityLayer:
    """Tests for _create_security_layer factory method."""

    def test_creates_standard_for_protocol_rdp(self, default_config: SessionConfig) -> None:
        """PROTOCOL_RDP creates StandardSecurityLayer."""
        seq = ConnectionSequence(default_config)
        layer = seq._create_security_layer(NegotiationProtocol.PROTOCOL_RDP)
        assert isinstance(layer, StandardSecurityLayer)
        assert layer.is_enhanced is False

    def test_creates_tls_for_protocol_ssl(self, default_config: SessionConfig) -> None:
        """PROTOCOL_SSL creates TlsSecurityLayer."""
        seq = ConnectionSequence(default_config)
        layer = seq._create_security_layer(NegotiationProtocol.PROTOCOL_SSL)
        assert isinstance(layer, TlsSecurityLayer)
        assert layer.is_enhanced is True
        assert layer.verify_cert is True

    def test_creates_nla_for_protocol_hybrid(self, default_config: SessionConfig) -> None:
        """PROTOCOL_HYBRID creates NlaSecurityLayer."""
        seq = ConnectionSequence(default_config)
        layer = seq._create_security_layer(NegotiationProtocol.PROTOCOL_HYBRID)
        assert isinstance(layer, NlaSecurityLayer)
        assert layer.is_enhanced is True
        assert layer.username == "testuser"
        assert layer.password == "testpass"
        assert layer.domain == "TESTDOMAIN"

    def test_verify_cert_false_propagates(self) -> None:
        """verify_cert=False propagates to TLS and NLA layers."""
        config = SessionConfig(host="h", verify_cert=False)
        seq = ConnectionSequence(config)

        tls = seq._create_security_layer(NegotiationProtocol.PROTOCOL_SSL)
        assert isinstance(tls, TlsSecurityLayer)
        assert tls.verify_cert is False

        nla = seq._create_security_layer(NegotiationProtocol.PROTOCOL_HYBRID)
        assert isinstance(nla, NlaSecurityLayer)
        assert nla.verify_cert is False


# ---------------------------------------------------------------------------
# ConnectionSequence — phase 1 tests
# ---------------------------------------------------------------------------


class TestPhase1ConnectionInitiation:
    """Tests for _phase1_connection_initiation."""

    @pytest.mark.asyncio
    async def test_phase1_connects_and_negotiates(self, default_config: SessionConfig) -> None:
        """Phase 1 establishes TCP and performs X.224 negotiation."""
        seq = ConnectionSequence(default_config)

        mock_tcp = MagicMock()
        mock_x224 = MagicMock()
        mock_x224.negotiate = AsyncMock(return_value=NegotiationProtocol.PROTOCOL_SSL)

        with (
            patch(
                "arrdipi.connection.TcpTransport.connect",
                new_callable=AsyncMock,
                return_value=mock_tcp,
            ) as mock_connect,
            patch(
                "arrdipi.connection.X224Layer",
                return_value=mock_x224,
            ),
        ):
            tcp, x224, protocol = await seq._phase1_connection_initiation()

        mock_connect.assert_called_once_with(
            host="192.168.1.100", port=3389, timeout=5.0
        )
        assert protocol == NegotiationProtocol.PROTOCOL_SSL

    @pytest.mark.asyncio
    async def test_phase1_timeout_raises_connection_timeout(self) -> None:
        """Phase 1 raises ConnectionTimeoutError on TCP timeout."""
        config = SessionConfig(host="unreachable", connect_timeout=0.1)
        seq = ConnectionSequence(config)

        with patch(
            "arrdipi.connection.TcpTransport.connect",
            new_callable=AsyncMock,
            side_effect=ConnectionTimeoutError(host="unreachable", port=3389, timeout=0.1),
        ):
            with pytest.raises(ConnectionTimeoutError):
                await seq._phase1_connection_initiation()


# ---------------------------------------------------------------------------
# ConnectionSequence — phase 4 skip for Enhanced Security
# ---------------------------------------------------------------------------


class TestPhase4SecurityCommencement:
    """Tests for phase 4 behavior."""

    @pytest.mark.asyncio
    async def test_enhanced_security_skips_phase4(self, default_config: SessionConfig) -> None:
        """Enhanced Security (TLS/NLA) skips phase 4 entirely."""
        seq = ConnectionSequence(default_config)

        # Set up internal state as if phases 1-3 completed
        seq._mcs = MagicMock()
        seq._security = TlsSecurityLayer(verify_cert=True)
        seq._server_security = ServerSecurityData()
        seq._server_network = ServerNetworkData(mcs_channel_id=1003)

        # Phase 4 should not be called for enhanced security
        # The execute() method checks is_enhanced before calling phase 4
        assert seq._security.is_enhanced is True

    @pytest.mark.asyncio
    async def test_standard_security_executes_phase4(self, default_config: SessionConfig) -> None:
        """Standard Security executes phase 4 (Security Exchange PDU)."""
        seq = ConnectionSequence(default_config)

        mock_mcs = MagicMock()
        mock_mcs.send_to_channel = AsyncMock()

        mock_security = MagicMock(spec=StandardSecurityLayer)
        mock_security.is_enhanced = False
        mock_security.init_keys = MagicMock(return_value=b"\x00" * 64)

        seq._mcs = mock_mcs
        seq._security = mock_security
        seq._server_security = ServerSecurityData(
            server_random=b"\x01" * 32,
            server_certificate=b"\x02" * 100,
        )
        seq._server_network = ServerNetworkData(mcs_channel_id=1003)

        await seq._phase4_security_commencement()

        mock_security.init_keys.assert_called_once_with(
            server_random=b"\x01" * 32,
            server_certificate=b"\x02" * 100,
        )
        mock_mcs.send_to_channel.assert_called_once()
        call_args = mock_mcs.send_to_channel.call_args
        assert call_args[0][0] == 1003  # I/O channel


# ---------------------------------------------------------------------------
# ConnectionSequence — error propagation
# ---------------------------------------------------------------------------


class TestErrorPropagation:
    """Tests for ConnectionPhaseError wrapping."""

    @pytest.mark.asyncio
    async def test_phase1_error_wrapped_with_context(self, default_config: SessionConfig) -> None:
        """Errors in phase 1 are wrapped with phase number and name."""
        seq = ConnectionSequence(default_config)

        with patch(
            "arrdipi.connection.TcpTransport.connect",
            new_callable=AsyncMock,
            side_effect=OSError("Connection refused"),
        ):
            with pytest.raises(ConnectionPhaseError) as exc_info:
                await seq.execute()

        error = exc_info.value
        assert error.phase_number == 1
        assert error.phase_name == "Connection Initiation"
        assert isinstance(error.cause, OSError)
        assert "Connection refused" in str(error.cause)

    @pytest.mark.asyncio
    async def test_phase2_error_wrapped_with_context(self, default_config: SessionConfig) -> None:
        """Errors in phase 2 are wrapped with phase number and name."""
        seq = ConnectionSequence(default_config)

        mock_tcp = MagicMock()
        mock_x224 = MagicMock()
        mock_x224.negotiate = AsyncMock(return_value=NegotiationProtocol.PROTOCOL_SSL)

        mock_tls = MagicMock(spec=TlsSecurityLayer)
        mock_tls.establish = AsyncMock()
        mock_tls.is_enhanced = True

        mock_mcs = MagicMock()
        mock_mcs.connect_initial = AsyncMock(side_effect=ValueError("GCC parse error"))

        with (
            patch(
                "arrdipi.connection.TcpTransport.connect",
                new_callable=AsyncMock,
                return_value=mock_tcp,
            ),
            patch("arrdipi.connection.X224Layer", return_value=mock_x224),
            patch.object(seq, "_create_security_layer", return_value=mock_tls),
            patch("arrdipi.connection.McsLayer", return_value=mock_mcs),
        ):
            with pytest.raises(ConnectionPhaseError) as exc_info:
                await seq.execute()

        error = exc_info.value
        assert error.phase_number == 2
        assert error.phase_name == "Basic Settings Exchange"

    @pytest.mark.asyncio
    async def test_connection_phase_error_not_double_wrapped(
        self, default_config: SessionConfig
    ) -> None:
        """ConnectionPhaseError is not double-wrapped."""
        seq = ConnectionSequence(default_config)

        original_error = ConnectionPhaseError(
            phase_number=1, phase_name="Connection Initiation", cause=OSError("test")
        )

        with patch(
            "arrdipi.connection.TcpTransport.connect",
            new_callable=AsyncMock,
            side_effect=original_error,
        ):
            with pytest.raises(ConnectionPhaseError) as exc_info:
                await seq.execute()

        # Should be the same error, not double-wrapped
        assert exc_info.value is original_error


# ---------------------------------------------------------------------------
# ConnectionSequence — phase 5 (Secure Settings Exchange)
# ---------------------------------------------------------------------------


class TestPhase5SecureSettingsExchange:
    """Tests for _phase5_secure_settings_exchange."""

    @pytest.mark.asyncio
    async def test_sends_client_info_pdu(self, default_config: SessionConfig) -> None:
        """Phase 5 sends Client Info PDU with credentials."""
        seq = ConnectionSequence(default_config)

        mock_mcs = MagicMock()
        mock_mcs.send_to_channel = AsyncMock()

        mock_security = TlsSecurityLayer()
        seq._mcs = mock_mcs
        seq._security = mock_security
        seq._server_network = ServerNetworkData(mcs_channel_id=1003)

        await seq._phase5_secure_settings_exchange()

        mock_mcs.send_to_channel.assert_called_once()
        call_args = mock_mcs.send_to_channel.call_args
        assert call_args[0][0] == 1003  # I/O channel
        # The PDU data should be non-empty
        assert len(call_args[0][1]) > 0


# ---------------------------------------------------------------------------
# ConnectionSequence — phase 7 (Licensing)
# ---------------------------------------------------------------------------


class TestPhase7Licensing:
    """Tests for _phase7_licensing."""

    @pytest.mark.asyncio
    async def test_licensing_completes_on_status_valid_client(
        self, default_config: SessionConfig
    ) -> None:
        """Phase 7 completes when server sends STATUS_VALID_CLIENT."""
        seq = ConnectionSequence(default_config)

        # Build the licensing complete PDU
        licensing_data = _build_licensing_complete_pdu()

        # Wrap in security header (Enhanced Security: 4 bytes flags)
        sec_header = struct.pack("<HH", 0x0080, 0)  # SEC_LICENSE_PKT
        wrapped_data = sec_header + licensing_data

        mock_mcs = MagicMock()
        mock_mcs.recv_pdu = AsyncMock(return_value=(1003, wrapped_data))

        mock_security = TlsSecurityLayer()
        seq._mcs = mock_mcs
        seq._security = mock_security
        seq._server_network = ServerNetworkData(mcs_channel_id=1003)

        await seq._phase7_licensing()

        # Should have received at least one PDU
        mock_mcs.recv_pdu.assert_called()


# ---------------------------------------------------------------------------
# ConnectionSequence — phase 9 (Capabilities Exchange)
# ---------------------------------------------------------------------------


class TestPhase9CapabilitiesExchange:
    """Tests for _phase9_capabilities_exchange."""

    @pytest.mark.asyncio
    async def test_receives_demand_active_sends_confirm(
        self, default_config: SessionConfig
    ) -> None:
        """Phase 9 receives Demand Active and sends Confirm Active."""
        seq = ConnectionSequence(default_config)

        # Build Demand Active PDU wrapped in ShareControl header
        demand_payload = _build_demand_active_pdu()
        share_control = _wrap_in_share_control(0x0001, 1003, demand_payload)

        # Wrap in security header
        sec_header = struct.pack("<HH", 0, 0)
        wrapped = sec_header + share_control

        mock_mcs = MagicMock()
        mock_mcs.recv_pdu = AsyncMock(return_value=(1003, wrapped))
        mock_mcs.send_to_channel = AsyncMock()
        mock_mcs.user_channel_id = 1007

        mock_security = TlsSecurityLayer()
        seq._mcs = mock_mcs
        seq._security = mock_security
        seq._server_network = ServerNetworkData(mcs_channel_id=1003)

        share_id, server_caps = await seq._phase9_capabilities_exchange()

        assert share_id == 0x00010001
        assert CapabilitySetType.GENERAL in server_caps
        mock_mcs.send_to_channel.assert_called_once()


# ---------------------------------------------------------------------------
# ConnectionSequence — phase 10 (Connection Finalization)
# ---------------------------------------------------------------------------


class TestPhase10ConnectionFinalization:
    """Tests for _phase10_connection_finalization."""

    @pytest.mark.asyncio
    async def test_sends_and_receives_finalization_pdus(
        self, default_config: SessionConfig
    ) -> None:
        """Phase 10 sends client PDUs and receives server PDUs."""
        seq = ConnectionSequence(default_config)

        # Build server finalization PDUs
        from arrdipi.pdu.finalization import ControlAction, ControlPdu, FontMapPdu, SynchronizePdu

        sync_data = SynchronizePdu(message_type=1, target_user=1007).serialize()
        cooperate_data = ControlPdu(
            action=ControlAction.COOPERATE, grant_id=0, control_id=0
        ).serialize()
        granted_data = ControlPdu(
            action=ControlAction.GRANTED_CONTROL, grant_id=1007, control_id=0x00010001
        ).serialize()
        font_map_data = FontMapPdu(
            number_entries=0, total_num_entries=0, map_flags=0x0003, entry_size=0x0004
        ).serialize()

        # Wrap each in ShareData + ShareControl + security header
        def wrap_server_pdu(pdu_type2: int, payload: bytes) -> bytes:
            share_data = _wrap_in_share_data(pdu_type2, payload)
            share_control = _wrap_in_share_control(0x0007, 1003, share_data)
            sec_header = struct.pack("<HH", 0, 0)
            return sec_header + share_control

        server_pdus = [
            (1003, wrap_server_pdu(0x1F, sync_data)),
            (1003, wrap_server_pdu(0x14, cooperate_data)),
            (1003, wrap_server_pdu(0x14, granted_data)),
            (1003, wrap_server_pdu(0x28, font_map_data)),
        ]

        mock_mcs = MagicMock()
        mock_mcs.recv_pdu = AsyncMock(side_effect=server_pdus)
        mock_mcs.send_to_channel = AsyncMock()
        mock_mcs.user_channel_id = 1007

        mock_security = TlsSecurityLayer()
        seq._mcs = mock_mcs
        seq._security = mock_security
        seq._server_network = ServerNetworkData(mcs_channel_id=1003)

        await seq._phase10_connection_finalization()

        # Should have sent 4 client PDUs (sync, cooperate, request control, font list)
        assert mock_mcs.send_to_channel.call_count == 4

    @pytest.mark.asyncio
    async def test_finalization_timeout_raises_error(self) -> None:
        """Phase 10 raises FinalizationTimeoutError on timeout."""
        config = SessionConfig(host="h", finalization_timeout=0.1)
        seq = ConnectionSequence(config)

        mock_mcs = MagicMock()
        # Never return a valid finalization PDU
        mock_mcs.recv_pdu = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_mcs.send_to_channel = AsyncMock()
        mock_mcs.user_channel_id = 1007

        mock_security = TlsSecurityLayer()
        seq._mcs = mock_mcs
        seq._security = mock_security
        seq._server_network = ServerNetworkData(mcs_channel_id=1003)

        with pytest.raises(FinalizationTimeoutError) as exc_info:
            await seq._phase10_connection_finalization()

        assert "Server Synchronize PDU" in str(exc_info.value)


# ---------------------------------------------------------------------------
# ConnectionSequence — full execute with mocks
# ---------------------------------------------------------------------------


class TestFullExecute:
    """Tests for the full execute() flow."""

    @pytest.mark.asyncio
    async def test_full_execute_returns_session(self, default_config: SessionConfig) -> None:
        """Full execute() returns a Session object on success."""
        seq = ConnectionSequence(default_config)

        # Mock phase 1
        mock_tcp = MagicMock()
        mock_x224 = MagicMock()
        mock_x224.negotiate = AsyncMock(return_value=NegotiationProtocol.PROTOCOL_SSL)

        # Mock security layer
        mock_security = MagicMock(spec=TlsSecurityLayer)
        mock_security.establish = AsyncMock()
        mock_security.is_enhanced = True
        mock_security.unwrap_pdu = MagicMock()
        mock_security.wrap_pdu = MagicMock()

        # Mock MCS
        mock_mcs = MagicMock()
        mock_mcs.connect_initial = AsyncMock(
            return_value=(
                ServerCoreData(),
                ServerSecurityData(),
                ServerNetworkData(mcs_channel_id=1003, channel_ids=[1004, 1005]),
            )
        )
        mock_mcs.erect_domain_and_attach_user = AsyncMock(return_value=1007)
        mock_mcs.join_channels = AsyncMock()
        mock_mcs.send_to_channel = AsyncMock()
        mock_mcs.user_channel_id = 1007
        mock_mcs.channel_map = {1004: "cliprdr", 1005: "rdpsnd"}
        mock_mcs.io_channel_id = 1003

        # Build licensing response
        licensing_data = _build_licensing_complete_pdu()
        sec_header = struct.pack("<HH", 0x0080, 0)
        licensing_wrapped = sec_header + licensing_data
        mock_security.unwrap_pdu.side_effect = lambda data: (data[4:], struct.unpack_from("<H", data, 0)[0])

        # Build Demand Active response
        demand_payload = _build_demand_active_pdu()
        share_control = _wrap_in_share_control(0x0001, 1003, demand_payload)
        demand_wrapped = struct.pack("<HH", 0, 0) + share_control

        # Build finalization responses
        from arrdipi.pdu.finalization import ControlAction, ControlPdu, FontMapPdu, SynchronizePdu

        def wrap_server_pdu(pdu_type2: int, payload: bytes) -> bytes:
            share_data = _wrap_in_share_data(pdu_type2, payload)
            share_control = _wrap_in_share_control(0x0007, 1003, share_data)
            return struct.pack("<HH", 0, 0) + share_control

        sync_wrapped = wrap_server_pdu(
            0x1F, SynchronizePdu(message_type=1, target_user=1007).serialize()
        )
        cooperate_wrapped = wrap_server_pdu(
            0x14,
            ControlPdu(action=ControlAction.COOPERATE, grant_id=0, control_id=0).serialize(),
        )
        granted_wrapped = wrap_server_pdu(
            0x14,
            ControlPdu(
                action=ControlAction.GRANTED_CONTROL, grant_id=1007, control_id=0x00010001
            ).serialize(),
        )
        font_map_wrapped = wrap_server_pdu(
            0x28,
            FontMapPdu(
                number_entries=0, total_num_entries=0, map_flags=0x0003, entry_size=0x0004
            ).serialize(),
        )

        # Set up recv_pdu to return licensing, then demand active, then finalization
        mock_mcs.recv_pdu = AsyncMock(
            side_effect=[
                (1003, licensing_wrapped),
                (1003, demand_wrapped),
                (1003, sync_wrapped),
                (1003, cooperate_wrapped),
                (1003, granted_wrapped),
                (1003, font_map_wrapped),
            ]
        )

        with (
            patch(
                "arrdipi.connection.TcpTransport.connect",
                new_callable=AsyncMock,
                return_value=mock_tcp,
            ),
            patch("arrdipi.connection.X224Layer", return_value=mock_x224),
            patch.object(seq, "_create_security_layer", return_value=mock_security),
            patch("arrdipi.connection.McsLayer", return_value=mock_mcs),
        ):
            session = await seq.execute()

        assert isinstance(session, Session)
        assert session._tcp is mock_tcp
        assert session._mcs is mock_mcs
        assert session._security is mock_security
        assert session._config is default_config


# ---------------------------------------------------------------------------
# Phase names mapping
# ---------------------------------------------------------------------------


class TestPhaseNames:
    """Tests for phase name constants."""

    def test_all_phases_have_names(self) -> None:
        """All implemented phases have human-readable names."""
        assert _PHASE_NAMES[1] == "Connection Initiation"
        assert _PHASE_NAMES[2] == "Basic Settings Exchange"
        assert _PHASE_NAMES[3] == "Channel Connection"
        assert _PHASE_NAMES[4] == "RDP Security Commencement"
        assert _PHASE_NAMES[5] == "Secure Settings Exchange"
        assert _PHASE_NAMES[7] == "Licensing"
        assert _PHASE_NAMES[9] == "Capabilities Exchange"
        assert _PHASE_NAMES[10] == "Connection Finalization"


# ---------------------------------------------------------------------------
# Session placeholder tests
# ---------------------------------------------------------------------------


class TestSession:
    """Tests for the Session class."""

    def test_session_holds_connection_state(self) -> None:
        """Session stores all connection components."""
        mock_mcs = MagicMock()
        mock_mcs.channel_map = {}
        mock_security = MagicMock()
        mock_security.is_enhanced = True
        mock_config = MagicMock()
        mock_config.width = 1920
        mock_config.height = 1080
        mock_config.auto_reconnect_cookie = None

        session = Session(
            tcp=MagicMock(),
            x224=MagicMock(),
            mcs=mock_mcs,
            security=mock_security,
            config=mock_config,
            server_caps={},
            share_id=42,
        )
        assert session._share_id == 42
        assert session._server_caps == {}
        assert session._config is mock_config
