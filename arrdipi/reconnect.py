"""Auto-reconnect handler for RDP sessions.

Implements automatic reconnection using the auto-reconnect cookie from
the Save Session Info PDU, per [MS-RDPBCGR] Section 5.5.

The auto-reconnect cookie is a 28-byte ARC_SC_PRIVATE_PACKET structure
received from the server. On disconnection, the client can use this cookie
along with an HMAC-MD5 computation to prove its identity without resending
credentials.

Requirements addressed: Req 26 (AC 1–5)
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC

if TYPE_CHECKING:
    from arrdipi.connection import ConnectionSequence, SessionConfig
    from arrdipi.session import Session

logger = logging.getLogger(__name__)

# ARC_SC_PRIVATE_PACKET structure size (28 bytes):
# cbLen(4) + Version(4) + LogonId(4) + ArcRandomBits(16)
ARC_SC_PRIVATE_PACKET_SIZE = 28


@dataclass
class AutoReconnectCookie:
    """Parsed auto-reconnect cookie from Save Session Info PDU.

    Structure per [MS-RDPBCGR] 2.2.4.2:
    - cb_len: Length of the packet (4 bytes, u32 LE)
    - version: Version (4 bytes, u32 LE, must be 1)
    - logon_id: Logon ID (4 bytes, u32 LE)
    - arc_random_bits: Random bits for HMAC (16 bytes)
    """

    cb_len: int
    version: int
    logon_id: int
    arc_random_bits: bytes

    @classmethod
    def parse(cls, data: bytes) -> AutoReconnectCookie:
        """Parse an ARC_SC_PRIVATE_PACKET from raw bytes.

        Args:
            data: Raw bytes of the auto-reconnect cookie (at least 28 bytes).

        Returns:
            Parsed AutoReconnectCookie instance.

        Raises:
            ValueError: If data is too short or version is unsupported.
        """
        if len(data) < ARC_SC_PRIVATE_PACKET_SIZE:
            raise ValueError(
                f"Auto-reconnect cookie too short: {len(data)} bytes, "
                f"expected at least {ARC_SC_PRIVATE_PACKET_SIZE}"
            )

        cb_len, version, logon_id = struct.unpack_from("<III", data, 0)
        arc_random_bits = data[12:28]

        if version != 1:
            raise ValueError(f"Unsupported auto-reconnect cookie version: {version}")

        return cls(
            cb_len=cb_len,
            version=version,
            logon_id=logon_id,
            arc_random_bits=arc_random_bits,
        )

    def serialize(self) -> bytes:
        """Serialize the cookie back to bytes.

        Returns:
            28-byte ARC_SC_PRIVATE_PACKET.
        """
        header = struct.pack("<III", self.cb_len, self.version, self.logon_id)
        return header + self.arc_random_bits


class ReconnectHandler:
    """Handles automatic reconnection using the auto-reconnect cookie.

    Stores the cookie received from the server's Save Session Info PDU,
    computes the HMAC for identity verification, and manages reconnection
    attempts with configurable retry limits.

    (Req 26, AC 1–5)
    """

    def __init__(self, config: SessionConfig, max_attempts: int = 3) -> None:
        """Initialize the ReconnectHandler.

        Args:
            config: The session configuration for reconnection.
            max_attempts: Maximum number of reconnection attempts before
                giving up (Req 26, AC 5). Defaults to 3.
        """
        self._config = config
        self._max_attempts = max_attempts
        self._cookie: AutoReconnectCookie | None = None
        self._attempts: int = 0
        self._client_random: bytes = b""

    @property
    def cookie(self) -> AutoReconnectCookie | None:
        """The stored auto-reconnect cookie, or None if not available."""
        return self._cookie

    @property
    def has_cookie(self) -> bool:
        """Whether an auto-reconnect cookie is available."""
        return self._cookie is not None

    @property
    def max_attempts(self) -> int:
        """The configured maximum number of reconnection attempts."""
        return self._max_attempts

    @property
    def attempts(self) -> int:
        """The number of reconnection attempts made so far."""
        return self._attempts

    def store_cookie(self, cookie: bytes) -> None:
        """Store the auto-reconnect cookie from Save Session Info PDU.

        Parses the raw cookie bytes into an AutoReconnectCookie structure
        and stores it for use in subsequent reconnection attempts.

        (Req 26, AC 1)

        Args:
            cookie: Raw bytes of the ARC_SC_PRIVATE_PACKET (28 bytes).

        Raises:
            ValueError: If the cookie data is invalid.
        """
        self._cookie = AutoReconnectCookie.parse(cookie)
        self._attempts = 0  # Reset attempts on new cookie
        logger.info(
            "Stored auto-reconnect cookie (logon_id=%d)", self._cookie.logon_id
        )

    def set_client_random(self, client_random: bytes) -> None:
        """Store the client random used during the original connection.

        The client random is needed for HMAC computation during reconnection.

        Args:
            client_random: The 32-byte client random from the security exchange.
        """
        self._client_random = client_random

    def compute_hmac(self, cookie: bytes, client_random: bytes) -> bytes:
        """Compute the auto-reconnect HMAC per [MS-RDPBCGR] Section 5.5.

        The HMAC is computed as:
            HMAC-MD5(arc_random_bits, client_random)

        where arc_random_bits is the 16-byte random from the cookie and
        client_random is the 32-byte random generated during the original
        connection's security exchange.

        (Req 26, AC 3)

        Args:
            cookie: The 16-byte ARC random bits from the auto-reconnect cookie.
            client_random: The 32-byte client random from the security exchange.

        Returns:
            16-byte HMAC-MD5 digest.
        """
        h = HMAC(cookie, hashes.MD5())
        h.update(client_random)
        return h.finalize()

    async def attempt_reconnect(self) -> Session | None:
        """Attempt reconnection with the stored auto-reconnect cookie.

        Initiates a new ConnectionSequence with the cookie set in the
        Client Info PDU's Extended Info Packet. If the server rejects
        the reconnection, falls back to full authentication.

        Returns None if max_attempts is exceeded.

        (Req 26, AC 2, 4, 5)

        Returns:
            A new Session on success, or None if max attempts exceeded.
        """
        if self._cookie is None:
            logger.warning("No auto-reconnect cookie available")
            return None

        if self._attempts >= self._max_attempts:
            logger.warning(
                "Max reconnection attempts (%d) exceeded", self._max_attempts
            )
            return None

        self._attempts += 1
        logger.info(
            "Attempting auto-reconnect (attempt %d/%d)",
            self._attempts,
            self._max_attempts,
        )

        # Compute the HMAC for the reconnection cookie
        hmac_value = self.compute_hmac(
            self._cookie.arc_random_bits, self._client_random
        )

        # Build the auto-reconnect cookie bytes for the Client Info PDU
        # The cookie sent in the Client Info PDU includes the HMAC
        reconnect_cookie_data = self._cookie.serialize() + hmac_value

        # Create a new config with the auto-reconnect cookie
        from arrdipi.connection import ConnectionSequence, SessionConfig

        reconnect_config = SessionConfig(
            host=self._config.host,
            port=self._config.port,
            username=self._config.username,
            password=self._config.password,
            domain=self._config.domain,
            security=self._config.security,
            width=self._config.width,
            height=self._config.height,
            color_depth=self._config.color_depth,
            verify_cert=self._config.verify_cert,
            connect_timeout=self._config.connect_timeout,
            finalization_timeout=self._config.finalization_timeout,
            performance_flags=self._config.performance_flags,
            auto_reconnect_cookie=reconnect_cookie_data,
            compression_type=self._config.compression_type,
            channel_names=list(self._config.channel_names),
            drive_paths=list(self._config.drive_paths),
        )

        try:
            sequence = ConnectionSequence(reconnect_config)
            session = await sequence.execute()
            logger.info("Auto-reconnect successful")
            return session
        except Exception as e:
            logger.warning("Auto-reconnect failed: %s", e)
            # Fall back to full authentication (Req 26, AC 4)
            return await self._fallback_full_auth()

    async def _fallback_full_auth(self) -> Session | None:
        """Fall back to full authentication on server rejection.

        Creates a new connection without the auto-reconnect cookie,
        using the original credentials for full authentication.

        (Req 26, AC 4)

        Returns:
            A new Session on success, or None if the fallback also fails.
        """
        logger.info("Falling back to full authentication")

        from arrdipi.connection import ConnectionSequence, SessionConfig

        # Create config without auto-reconnect cookie
        fallback_config = SessionConfig(
            host=self._config.host,
            port=self._config.port,
            username=self._config.username,
            password=self._config.password,
            domain=self._config.domain,
            security=self._config.security,
            width=self._config.width,
            height=self._config.height,
            color_depth=self._config.color_depth,
            verify_cert=self._config.verify_cert,
            connect_timeout=self._config.connect_timeout,
            finalization_timeout=self._config.finalization_timeout,
            performance_flags=self._config.performance_flags,
            auto_reconnect_cookie=None,  # No cookie — full auth
            compression_type=self._config.compression_type,
            channel_names=list(self._config.channel_names),
            drive_paths=list(self._config.drive_paths),
        )

        try:
            sequence = ConnectionSequence(fallback_config)
            session = await sequence.execute()
            logger.info("Full authentication reconnect successful")
            return session
        except Exception as e:
            logger.error("Full authentication reconnect failed: %s", e)
            return None
