"""10-phase RDP connection sequence orchestrator.

Orchestrates the full RDP connection sequence per [MS-RDPBCGR] Section 1.3.1.1.
Each phase is a separate private method for clarity and testability.

Requirements addressed: Req 4 (AC 1–7), Req 5, Req 6, Req 7, Req 8
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field
from typing import Any

from arrdipi.errors import ConnectionPhaseError, FinalizationTimeoutError
from arrdipi.mcs.gcc import (
    ClientCoreData,
    ClientSecurityData,
    ServerCoreData,
    ServerNetworkData,
    ServerSecurityData,
)
from arrdipi.mcs.layer import McsLayer
from arrdipi.pdu.capabilities import (
    ClientCapabilitiesConfig,
    ConfirmActivePdu,
    DemandActivePdu,
    build_client_capabilities,
)
from arrdipi.pdu.finalization import (
    ControlAction,
    ControlPdu,
    FontListPdu,
    FontMapPdu,
    SynchronizePdu,
)
from arrdipi.pdu.info import (
    ClientInfoPdu,
    ExtendedInfoPacket,
    InfoFlags,
    TimezoneInfo,
)
from arrdipi.pdu.types import (
    CapabilitySetType,
    CompressionType,
    NegotiationProtocol,
    PerformanceFlags,
    SecurityProtocol,
)
from arrdipi.security.base import SecurityLayer
from arrdipi.security.enhanced import TlsSecurityLayer
from arrdipi.security.licensing import LicensingHandler
from arrdipi.security.nla import NlaSecurityLayer
from arrdipi.security.standard import StandardSecurityLayer
from arrdipi.session import Session
from arrdipi.transport.tcp import TcpTransport
from arrdipi.transport.x224 import X224Layer


# Security header flag for licensing PDUs
SEC_LICENSE_PKT = 0x0080
# Security header flag for info PDU
SEC_INFO_PKT = 0x0040


@dataclass
class DrivePath:
    """A drive path mapping for RDPDR file system redirection."""

    name: str
    path: str
    read_only: bool = False


@dataclass
class SessionConfig:
    """Configuration for an RDP connection session.

    Contains all parameters needed to establish an RDP connection including
    host, credentials, security settings, display resolution, timeouts,
    channel names, and drive paths.
    """

    host: str
    port: int = 3389
    username: str = ""
    password: str = ""
    domain: str = ""
    security: SecurityProtocol = SecurityProtocol.AUTO
    width: int = 1920
    height: int = 1080
    color_depth: int = 32
    verify_cert: bool = True
    connect_timeout: float = 5.0
    finalization_timeout: float = 10.0
    performance_flags: PerformanceFlags = PerformanceFlags(0)
    auto_reconnect_cookie: bytes | None = None
    compression_type: CompressionType = CompressionType.TYPE_64K
    channel_names: list[str] = field(
        default_factory=lambda: ["cliprdr", "rdpsnd", "rdpdr", "drdynvc"]
    )
    drive_paths: list[DrivePath] = field(default_factory=list)


# Phase names for error reporting
_PHASE_NAMES: dict[int, str] = {
    1: "Connection Initiation",
    2: "Basic Settings Exchange",
    3: "Channel Connection",
    4: "RDP Security Commencement",
    5: "Secure Settings Exchange",
    7: "Licensing",
    9: "Capabilities Exchange",
    10: "Connection Finalization",
}


class ConnectionSequence:
    """Orchestrates the 10-phase RDP connection sequence.

    Each phase is a separate private method. Phases 6 and 8 (auto-detection,
    multitransport) are optional and skipped in this implementation.

    (Req 4, AC 1–7)
    """

    def __init__(self, config: SessionConfig) -> None:
        self._config = config
        self._current_phase: int = 0
        self._tcp: TcpTransport | None = None
        self._x224: X224Layer | None = None
        self._mcs: McsLayer | None = None
        self._security: SecurityLayer | None = None
        self._server_core: ServerCoreData | None = None
        self._server_security: ServerSecurityData | None = None
        self._server_network: ServerNetworkData | None = None

    async def execute(self) -> Session:
        """Run all 10 phases and return a connected Session.

        Raises ConnectionPhaseError on failure with phase number, name,
        and cause (Req 4, AC 6).

        Returns:
            A Session object representing the active RDP session (Req 4, AC 7).
        """
        try:
            # Phase 1: Connection Initiation (Req 1)
            self._current_phase = 1
            tcp, x224, selected_protocol = await self._phase1_connection_initiation()
            self._tcp = tcp
            self._x224 = x224

            # Create security layer based on negotiated protocol
            security_layer = self._create_security_layer(selected_protocol)
            self._security = security_layer

            # Security establishment: TLS/NLA handshake if needed (Req 4, AC 2–3)
            await security_layer.establish(x224, tcp)

            # Phase 2: Basic Settings Exchange (Req 2)
            self._current_phase = 2
            await self._phase2_basic_settings_exchange()

            # Phase 3: Channel Connection (Req 2)
            self._current_phase = 3
            await self._phase3_channel_connection()

            # Phase 4: RDP Security Commencement (Req 9)
            # Skipped for Enhanced Security (Req 4, AC 4–5)
            self._current_phase = 4
            if not security_layer.is_enhanced:
                await self._phase4_security_commencement()

            # Phase 5: Secure Settings Exchange (Req 5)
            self._current_phase = 5
            await self._phase5_secure_settings_exchange()

            # Phase 6: Optional Connect-Time Auto-Detection (skipped)
            # Phase 7: Licensing (Req 6)
            self._current_phase = 7
            await self._phase7_licensing()

            # Phase 8: Optional Multitransport Bootstrapping (skipped)
            # Phase 9: Capabilities Exchange (Req 7)
            self._current_phase = 9
            share_id, server_caps = await self._phase9_capabilities_exchange()

            # Phase 10: Connection Finalization (Req 8)
            self._current_phase = 10
            await self._phase10_connection_finalization()

            return Session(
                tcp=tcp,
                x224=x224,
                mcs=self._mcs,  # type: ignore[arg-type]
                security=security_layer,
                config=self._config,
                server_caps=server_caps,
                share_id=share_id,
            )

        except ConnectionPhaseError:
            # Re-raise if already wrapped
            raise
        except Exception as e:
            phase_name = _PHASE_NAMES.get(self._current_phase, "Unknown")
            raise ConnectionPhaseError(
                phase_number=self._current_phase,
                phase_name=phase_name,
                cause=e,
            ) from e

    async def _phase1_connection_initiation(
        self,
    ) -> tuple[TcpTransport, X224Layer, NegotiationProtocol]:
        """Phase 1: TCP connect + X.224 negotiation.

        Establishes TCP connection and performs X.224 protocol negotiation.
        (Req 1, Req 4 AC 1)

        Returns:
            Tuple of (TcpTransport, X224Layer, selected NegotiationProtocol).
        """
        tcp = await TcpTransport.connect(
            host=self._config.host,
            port=self._config.port,
            timeout=self._config.connect_timeout,
        )

        x224 = X224Layer(tcp)

        # Build cookie
        cookie = f"Cookie: mstshash={self._config.username or 'user'}\r\n"

        # Determine requested protocols based on security config
        requested_protocols = self._get_requested_protocols()

        selected_protocol = await x224.negotiate(cookie, requested_protocols)
        return tcp, x224, selected_protocol

    def _get_requested_protocols(self) -> NegotiationProtocol:
        """Determine the negotiation protocol flags based on security config."""
        match self._config.security:
            case SecurityProtocol.RDP:
                return NegotiationProtocol.PROTOCOL_RDP
            case SecurityProtocol.TLS:
                return NegotiationProtocol.PROTOCOL_SSL
            case SecurityProtocol.NLA:
                return NegotiationProtocol.PROTOCOL_HYBRID
            case SecurityProtocol.AUTO:
                # Request all protocols; server picks the best
                return (
                    NegotiationProtocol.PROTOCOL_HYBRID
                    | NegotiationProtocol.PROTOCOL_SSL
                )

    def _create_security_layer(
        self, protocol: NegotiationProtocol
    ) -> SecurityLayer:
        """Factory: instantiate the correct SecurityLayer subclass.

        Args:
            protocol: The negotiated protocol from X.224.

        Returns:
            The appropriate SecurityLayer instance.
        """
        if protocol & NegotiationProtocol.PROTOCOL_HYBRID:
            return NlaSecurityLayer(
                username=self._config.username,
                password=self._config.password,
                domain=self._config.domain,
                verify_cert=self._config.verify_cert,
                server_hostname=self._config.host,
            )
        elif protocol & NegotiationProtocol.PROTOCOL_SSL:
            return TlsSecurityLayer(
                verify_cert=self._config.verify_cert,
                server_hostname=self._config.host,
            )
        else:
            # Standard RDP Security (PROTOCOL_RDP = 0)
            return StandardSecurityLayer()

    async def _phase2_basic_settings_exchange(self) -> None:
        """Phase 2: MCS Connect Initial/Response with GCC.

        Sends client data blocks and receives server data blocks.
        (Req 2, AC 1–2; Req 4, AC 1)
        """
        assert self._x224 is not None

        mcs = McsLayer(self._x224)
        self._mcs = mcs

        # Build client core data
        client_core = ClientCoreData(
            desktop_width=self._config.width,
            desktop_height=self._config.height,
            color_depth=0xCA01,  # RNS_UD_COLOR_8BPP (actual depth in high_color_depth)
            high_color_depth=self._config.color_depth,
            supported_color_depths=0x000F,  # 15/16/24/32
            client_name=self._config.username[:15] or "arrdipi",
            early_capability_flags=0x0001,  # RNS_UD_CS_SUPPORT_ERRINFO_PDU
        )

        # Build client security data
        client_security = ClientSecurityData(
            encryption_methods=0x0000003B,  # 40-bit + 128-bit + 56-bit + FIPS
            ext_encryption_methods=0,
        )

        # Send Connect Initial, receive Connect Response
        server_core, server_security, server_network = await mcs.connect_initial(
            client_core=client_core,
            client_security=client_security,
            channel_names=self._config.channel_names,
        )

        self._server_core = server_core
        self._server_security = server_security
        self._server_network = server_network

    async def _phase3_channel_connection(self) -> None:
        """Phase 3: Erect Domain, Attach User, Channel Joins.

        (Req 2, AC 3–5; Req 4, AC 1)
        """
        assert self._mcs is not None
        assert self._server_network is not None

        # Erect Domain + Attach User
        user_channel_id = await self._mcs.erect_domain_and_attach_user()

        # Build list of channels to join: user channel, I/O channel, + VCs
        channel_ids = [
            user_channel_id,
            self._server_network.mcs_channel_id,
            *self._server_network.channel_ids,
        ]

        await self._mcs.join_channels(channel_ids)

    async def _phase4_security_commencement(self) -> None:
        """Phase 4: Security Exchange PDU for Standard RDP Security.

        Performs RSA key exchange. Skipped for Enhanced Security (Req 4, AC 4–5).
        (Req 9, AC 1–3)
        """
        assert self._mcs is not None
        assert self._security is not None
        assert self._server_security is not None
        assert isinstance(self._security, StandardSecurityLayer)

        # Initialize keys from server security data
        encrypted_client_random = self._security.init_keys(
            server_random=self._server_security.server_random,
            server_certificate=self._server_security.server_certificate,
        )

        # Build and send Security Exchange PDU
        # Format: security header (flags=SEC_EXCHANGE_PKT) + length + encrypted random
        # SEC_EXCHANGE_PKT = 0x0001
        sec_exchange_flags = 0x0001
        header = struct.pack("<HH", sec_exchange_flags, 0)
        # Length of encrypted client random (u32 LE) + the encrypted data
        length_field = struct.pack("<I", len(encrypted_client_random))
        pdu_data = header + length_field + encrypted_client_random

        # Send on I/O channel
        io_channel_id = self._server_network.mcs_channel_id  # type: ignore[union-attr]
        await self._mcs.send_to_channel(io_channel_id, pdu_data)

    async def _phase5_secure_settings_exchange(self) -> None:
        """Phase 5: Send Client Info PDU.

        Sends credentials, timezone, performance flags, auto-reconnect cookie,
        and compression type. (Req 5, AC 1–6; Req 4, AC 1)
        """
        assert self._mcs is not None
        assert self._security is not None
        assert self._server_network is not None

        # Build flags
        flags = (
            InfoFlags.INFO_MOUSE
            | InfoFlags.INFO_UNICODE
            | InfoFlags.INFO_LOGONNOTIFY
            | InfoFlags.INFO_LOGONERRORS
            | InfoFlags.INFO_DISABLECTRLALTDEL
            | InfoFlags.INFO_ENABLEWINDOWSKEY
            | InfoFlags.INFO_MOUSE_HAS_WHEEL
        )

        if self._config.password:
            flags |= InfoFlags.INFO_AUTOLOGON

        if self._config.compression_type != CompressionType.TYPE_8K:
            flags |= InfoFlags.INFO_COMPRESSION

        # Build extended info
        extended_info = ExtendedInfoPacket(
            client_address="0.0.0.0",
            client_dir="C:\\Windows\\System32\\mstsc.exe",
            client_timezone=TimezoneInfo(bias=0),
            performance_flags=self._config.performance_flags,
            auto_reconnect_cookie=self._config.auto_reconnect_cookie,
        )

        # Build Client Info PDU
        info_pdu = ClientInfoPdu(
            flags=flags,
            domain=self._config.domain,
            username=self._config.username,
            password=self._config.password,
            extra_info=extended_info,
            security_flags=SEC_INFO_PKT,
        )

        # Serialize and send
        pdu_data = info_pdu.serialize()

        # For Standard Security, the info PDU is encrypted by the security layer
        if not self._security.is_enhanced:
            # wrap_pdu handles encryption + MAC for Standard Security
            pdu_data = self._security.wrap_pdu(pdu_data[4:])  # strip existing sec header
            # Re-add SEC_INFO_PKT flag in the security header
            pdu_data = struct.pack("<HH", SEC_INFO_PKT, 0) + pdu_data[4:]

        io_channel_id = self._server_network.mcs_channel_id
        await self._mcs.send_to_channel(io_channel_id, pdu_data)

    async def _phase7_licensing(self) -> None:
        """Phase 7: Licensing exchange.

        Delegates to LicensingHandler. (Req 6, AC 1–4; Req 4, AC 1)
        """
        assert self._mcs is not None
        assert self._security is not None
        assert self._server_network is not None

        handler = LicensingHandler(
            username=self._config.username,
            machine_name="arrdipi",
        )

        io_channel_id = self._server_network.mcs_channel_id

        async def recv_licensing() -> bytes:
            """Receive a licensing PDU from the I/O channel."""
            while True:
                channel_id, data = await self._mcs.recv_pdu()  # type: ignore[union-attr]
                if channel_id == io_channel_id:
                    # Strip security header to get licensing data
                    payload, flags = self._security.unwrap_pdu(data)  # type: ignore[union-attr]
                    return payload

        async def send_licensing(data: bytes) -> None:
            """Send a licensing PDU on the I/O channel."""
            # Wrap with security header (SEC_LICENSE_PKT flag)
            header = struct.pack("<HH", SEC_LICENSE_PKT, 0)
            pdu_data = header + data
            await self._mcs.send_to_channel(io_channel_id, pdu_data)  # type: ignore[union-attr]

        await handler.handle_licensing(recv_licensing, send_licensing)

    async def _phase9_capabilities_exchange(
        self,
    ) -> tuple[int, dict[CapabilitySetType, Any]]:
        """Phase 9: Receive Demand Active, send Confirm Active.

        (Req 7, AC 1–4; Req 4, AC 1)

        Returns:
            Tuple of (share_id, server_capabilities dict).
        """
        assert self._mcs is not None
        assert self._security is not None
        assert self._server_network is not None

        io_channel_id = self._server_network.mcs_channel_id

        # Receive Demand Active PDU from server
        while True:
            channel_id, data = await self._mcs.recv_pdu()
            if channel_id == io_channel_id:
                # Strip security header
                payload, _flags = self._security.unwrap_pdu(data)
                # Parse Demand Active PDU (skip ShareControl header: 6 bytes)
                # ShareControlHeader: totalLength(u16) + pduType(u16) + pduSource(u16)
                if len(payload) >= 6:
                    pdu_type = struct.unpack_from("<H", payload, 2)[0] & 0x000F
                    if pdu_type == 0x0001:  # DEMAND_ACTIVE
                        demand_active = DemandActivePdu.parse(payload[6:])
                        break

        # Build client capabilities
        caps_config = ClientCapabilitiesConfig(
            width=self._config.width,
            height=self._config.height,
            color_depth=self._config.color_depth,
        )
        client_caps_list = build_client_capabilities(
            demand_active.capability_sets, caps_config
        )

        # Build Confirm Active PDU
        confirm_active = ConfirmActivePdu(
            share_id=demand_active.share_id,
            originator_id=0x03EA,
            source_descriptor=b"MSTSC\x00",
            capability_sets=dict(client_caps_list),
        )

        # Serialize and wrap in ShareControl header
        confirm_payload = confirm_active.serialize()
        # ShareControlHeader: totalLength(u16) + pduType(u16) + pduSource(u16)
        total_length = len(confirm_payload) + 6
        share_control_header = struct.pack(
            "<HHH",
            total_length,
            0x0003,  # CONFIRM_ACTIVE (with version bits)
            self._mcs.user_channel_id,
        )
        full_pdu = share_control_header + confirm_payload

        # Wrap with security header and send
        if self._security.is_enhanced:
            sec_header = struct.pack("<HH", 0, 0)
            pdu_data = sec_header + full_pdu
        else:
            pdu_data = self._security.wrap_pdu(full_pdu)

        await self._mcs.send_to_channel(io_channel_id, pdu_data)

        return demand_active.share_id, demand_active.capability_sets

    async def _phase10_connection_finalization(self) -> None:
        """Phase 10: Send/receive finalization PDUs with configurable timeout.

        Sends: Synchronize, Control (Cooperate), Control (Request Control), Font List.
        Receives: Server Synchronize, Server Control (Cooperate),
                  Server Control (Granted Control), Font Map.

        (Req 8, AC 1–5; Req 4, AC 1)
        """
        assert self._mcs is not None
        assert self._security is not None
        assert self._server_network is not None

        io_channel_id = self._server_network.mcs_channel_id
        user_channel_id = self._mcs.user_channel_id

        # --- Send client finalization PDUs ---

        # Client Synchronize PDU
        sync_pdu = SynchronizePdu(message_type=1, target_user=user_channel_id)
        await self._send_data_pdu(
            io_channel_id, ShareDataPduType_SYNCHRONIZE, sync_pdu.serialize()
        )

        # Client Control (Cooperate) PDU
        control_cooperate = ControlPdu(
            action=ControlAction.COOPERATE, grant_id=0, control_id=0
        )
        await self._send_data_pdu(
            io_channel_id, ShareDataPduType_CONTROL, control_cooperate.serialize()
        )

        # Client Control (Request Control) PDU
        control_request = ControlPdu(
            action=ControlAction.REQUEST_CONTROL, grant_id=0, control_id=0
        )
        await self._send_data_pdu(
            io_channel_id, ShareDataPduType_CONTROL, control_request.serialize()
        )

        # Client Font List PDU
        font_list = FontListPdu(
            number_fonts=0, total_num_fonts=0, list_flags=0x0003, entry_size=0x0032
        )
        await self._send_data_pdu(
            io_channel_id, ShareDataPduType_FONT_LIST, font_list.serialize()
        )

        # --- Receive server finalization PDUs with timeout ---
        received_sync = False
        received_control_cooperate = False
        received_control_granted = False
        received_font_map = False

        try:
            deadline = asyncio.get_event_loop().time() + self._config.finalization_timeout

            while not (
                received_sync
                and received_control_cooperate
                and received_control_granted
                and received_font_map
            ):
                remaining_time = deadline - asyncio.get_event_loop().time()
                if remaining_time <= 0:
                    missing = self._get_missing_finalization_pdu(
                        received_sync,
                        received_control_cooperate,
                        received_control_granted,
                        received_font_map,
                    )
                    raise FinalizationTimeoutError(
                        missing_pdu=missing,
                        timeout=self._config.finalization_timeout,
                    )

                channel_id, data = await asyncio.wait_for(
                    self._mcs.recv_pdu(), timeout=remaining_time
                )

                if channel_id != io_channel_id:
                    continue

                # Strip security header
                payload, _flags = self._security.unwrap_pdu(data)

                # Parse ShareControl header
                if len(payload) < 6:
                    continue

                _total_len = struct.unpack_from("<H", payload, 0)[0]
                pdu_type = struct.unpack_from("<H", payload, 2)[0] & 0x000F

                if pdu_type != 0x0007:  # DATA PDU
                    continue

                # Parse ShareData header to get the sub-type
                # ShareDataHeader starts after ShareControlHeader (6 bytes)
                share_data = payload[6:]
                if len(share_data) < 12:
                    continue

                # shareId(4) + pad1(1) + streamId(1) + uncompressedLength(2) +
                # pduType2(1) + compressedType(1) + compressedLength(2)
                pdu_type2 = share_data[8]

                if pdu_type2 == 0x1F:  # SYNCHRONIZE
                    received_sync = True
                elif pdu_type2 == 0x14:  # CONTROL
                    # Parse control action
                    control_data = share_data[12:]
                    if len(control_data) >= 2:
                        action = struct.unpack_from("<H", control_data, 0)[0]
                        if action == ControlAction.COOPERATE:
                            received_control_cooperate = True
                        elif action == ControlAction.GRANTED_CONTROL:
                            received_control_granted = True
                elif pdu_type2 == 0x28:  # FONT_MAP
                    received_font_map = True

        except asyncio.TimeoutError:
            missing = self._get_missing_finalization_pdu(
                received_sync,
                received_control_cooperate,
                received_control_granted,
                received_font_map,
            )
            raise FinalizationTimeoutError(
                missing_pdu=missing,
                timeout=self._config.finalization_timeout,
            )

    async def _send_data_pdu(
        self, channel_id: int, pdu_type2: int, payload: bytes
    ) -> None:
        """Send a Share Data PDU on the specified channel.

        Wraps the payload in ShareControl + ShareData headers and security header.
        """
        assert self._mcs is not None
        assert self._security is not None

        # Build ShareData header
        # shareId(4) + pad1(1) + streamId(1) + uncompressedLength(2) +
        # pduType2(1) + compressedType(1) + compressedLength(2)
        share_data_header = struct.pack(
            "<IBBHBBH",
            0,  # shareId (will be filled by server context, 0 is fine for client)
            0,  # pad1
            1,  # streamId (STREAM_LOW)
            len(payload),  # uncompressedLength
            pdu_type2,  # pduType2
            0,  # compressedType
            0,  # compressedLength
        )

        # Build ShareControl header
        inner_data = share_data_header + payload
        total_length = len(inner_data) + 6  # +6 for ShareControlHeader itself
        share_control_header = struct.pack(
            "<HHH",
            total_length,
            0x0007,  # DATA PDU type (with version bits)
            self._mcs.user_channel_id,
        )

        full_pdu = share_control_header + inner_data

        # Wrap with security header
        if self._security.is_enhanced:
            sec_header = struct.pack("<HH", 0, 0)
            pdu_data = sec_header + full_pdu
        else:
            pdu_data = self._security.wrap_pdu(full_pdu)

        await self._mcs.send_to_channel(channel_id, pdu_data)

    @staticmethod
    def _get_missing_finalization_pdu(
        sync: bool, cooperate: bool, granted: bool, font_map: bool
    ) -> str:
        """Get the name of the first missing finalization PDU."""
        if not sync:
            return "Server Synchronize PDU"
        if not cooperate:
            return "Server Control (Cooperate) PDU"
        if not granted:
            return "Server Control (Granted Control) PDU"
        if not font_map:
            return "Server Font Map PDU"
        return "Unknown"


# ShareDataPduType constants used in finalization
ShareDataPduType_SYNCHRONIZE = 0x1F
ShareDataPduType_CONTROL = 0x14
ShareDataPduType_FONT_LIST = 0x27
