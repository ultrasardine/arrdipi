"""TLS (Enhanced RDP Security) layer implementation.

Upgrades the TCP transport to TLS after X.224 negotiation. Once TLS is
active, encryption/decryption are identity functions because TLS operates
at the transport level. The security header still carries flags but no
encryption payload.

Requirements addressed: Req 10 (AC 1–4)
"""

from __future__ import annotations

import logging
import ssl
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from arrdipi.security.base import SecurityLayer

if TYPE_CHECKING:
    from arrdipi.transport.tcp import TcpTransport
    from arrdipi.transport.x224 import X224Layer

logger = logging.getLogger(__name__)

# Security header size for Enhanced Security: flags (u16 LE) + flagsHi (u16 LE)
_SECURITY_HEADER_SIZE = 4


@dataclass
class TlsSecurityLayer(SecurityLayer):
    """Enhanced RDP Security via TLS.

    After X.224 negotiation selects TLS, this layer upgrades the TCP
    connection to TLS. All subsequent traffic is encrypted by the TLS
    transport, so encrypt/decrypt are identity functions.

    Attributes:
        verify_cert: Whether to verify the server's TLS certificate.
            Defaults to True. When False, a warning is logged.
        server_hostname: The server hostname for SNI and cert verification.
            Set during establish().
    """

    verify_cert: bool = True
    server_hostname: str = field(default="", repr=False)

    async def establish(self, x224: X224Layer, tcp: TcpTransport) -> None:
        """Upgrade TCP to TLS using ssl.create_default_context().

        Creates an SSLContext with system CA certificates. If verify_cert
        is False, disables hostname checking and certificate verification,
        and logs a warning.

        Args:
            x224: The X.224 layer (unused for TLS, but part of the interface).
            tcp: The TCP transport to upgrade to TLS.
        """
        ctx = ssl.create_default_context()

        if not self.verify_cert:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            logger.warning("TLS certificate verification disabled")

        # Derive hostname from the TCP transport's peer if not already set
        hostname = self.server_hostname or ""
        await tcp.upgrade_to_tls(ctx, server_hostname=hostname)

    def encrypt(self, data: bytes) -> bytes:
        """Identity function — TLS handles encryption at transport level.

        Args:
            data: Raw PDU payload bytes.

        Returns:
            The same data unchanged.
        """
        return data

    def decrypt(self, data: bytes) -> bytes:
        """Identity function — TLS handles decryption at transport level.

        Args:
            data: Encrypted PDU payload bytes (already decrypted by TLS).

        Returns:
            The same data unchanged.
        """
        return data

    def wrap_pdu(self, data: bytes) -> bytes:
        """Prepend a 4-byte security header with flags=0, flagsHi=0.

        For Enhanced Security, the security header contains only flags
        (no MAC or encrypted payload). The header is:
        - flags (u16 LE): 0
        - flagsHi (u16 LE): 0

        Args:
            data: PDU payload bytes.

        Returns:
            4-byte security header + payload.
        """
        header = struct.pack("<HH", 0, 0)
        return header + data

    def unwrap_pdu(self, data: bytes) -> tuple[bytes, int]:
        """Strip the 4-byte security header and return payload with flags.

        Reads the flags field from the first 2 bytes (u16 LE) and returns
        the remaining data as the payload.

        Args:
            data: Raw bytes including security header + payload.

        Returns:
            Tuple of (payload bytes after header, security flags as int).
        """
        flags = struct.unpack_from("<H", data, 0)[0]
        payload = data[_SECURITY_HEADER_SIZE:]
        return payload, flags

    @property
    def is_enhanced(self) -> bool:
        """TLS is an Enhanced Security protocol.

        Returns:
            Always True.
        """
        return True
