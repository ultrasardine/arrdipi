"""SecurityLayer abstract base class for all RDP security mechanisms.

Defines the interface that Standard RDP Security, TLS (Enhanced Security),
and NLA/CredSSP implementations must satisfy. Each security layer handles
key establishment, encryption/decryption, and PDU header wrapping.

Requirements addressed: Req 9, Req 10, Req 11 (common interface)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from arrdipi.transport.tcp import TcpTransport
    from arrdipi.transport.x224 import X224Layer


class SecurityLayer(ABC):
    """Abstract base for all RDP security mechanisms.

    Subclasses implement the specific handshake, encryption, and PDU
    framing logic for their security mode (Standard, TLS, NLA).
    """

    @abstractmethod
    async def establish(self, x224: X224Layer, tcp: TcpTransport) -> None:
        """Perform security handshake after X.224 negotiation.

        For TLS: upgrade TCP to TLS.
        For NLA: upgrade TCP to TLS, then perform CredSSP.
        For Standard: no-op (key exchange happens later in phase 4).

        Args:
            x224: The X.224 layer for protocol communication.
            tcp: The underlying TCP transport to upgrade.
        """
        ...

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt outbound PDU data.

        No-op for Enhanced Security (TLS handles it at transport level).
        For Standard Security, applies RC4 encryption.

        Args:
            data: Raw PDU payload bytes.

        Returns:
            Encrypted bytes (or unchanged for Enhanced Security).
        """
        ...

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        """Decrypt inbound PDU data.

        No-op for Enhanced Security (TLS handles it at transport level).
        For Standard Security, applies RC4 decryption.

        Args:
            data: Encrypted PDU payload bytes.

        Returns:
            Decrypted bytes (or unchanged for Enhanced Security).
        """
        ...

    @abstractmethod
    def wrap_pdu(self, data: bytes) -> bytes:
        """Add security header to outbound PDU.

        Prepends the appropriate security header (flags, optional MAC)
        before the PDU payload.

        Args:
            data: PDU payload bytes.

        Returns:
            Security header + payload bytes.
        """
        ...

    @abstractmethod
    def unwrap_pdu(self, data: bytes) -> tuple[bytes, int]:
        """Strip security header from inbound PDU.

        Removes the security header and returns the payload along with
        the security flags from the header.

        Args:
            data: Raw bytes including security header + payload.

        Returns:
            Tuple of (payload bytes, security flags).
        """
        ...

    @property
    @abstractmethod
    def is_enhanced(self) -> bool:
        """Whether this is an Enhanced Security layer (TLS or NLA).

        Returns:
            True for TLS and NLA, False for Standard RDP Security.
        """
        ...
