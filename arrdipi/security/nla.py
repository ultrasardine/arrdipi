"""NLA / CredSSP security layer implementation via pyspnego.

Performs TLS upgrade followed by CredSSP handshake per [MS-CSSP] Section 3.1.5.
Uses the pyspnego library for SPNEGO/NTLM/Kerberos token generation.

Requirements addressed: Req 11 (AC 1–6)
"""

from __future__ import annotations

import hashlib
import logging
import os
import ssl
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import spnego

from arrdipi.errors import AuthenticationError, NegotiationError
from arrdipi.pdu.credssp import (
    TSCredentials,
    TSPasswordCreds,
    TSRequest,
)
from arrdipi.security.base import SecurityLayer

if TYPE_CHECKING:
    from arrdipi.transport.tcp import TcpTransport
    from arrdipi.transport.x224 import X224Layer

logger = logging.getLogger(__name__)

# Security header size for Enhanced Security: flags (u16 LE) + flagsHi (u16 LE)
_SECURITY_HEADER_SIZE = 4


@dataclass
class NlaSecurityLayer(SecurityLayer):
    """NLA/CredSSP security layer using pyspnego for authentication.

    Performs TLS upgrade then CredSSP handshake. Once established,
    encryption/decryption are identity functions (TLS handles transport
    encryption). The security header is the same 4-byte Enhanced Security header.

    Attributes:
        username: Username for authentication.
        password: Password for authentication.
        domain: Windows domain name.
        verify_cert: Whether to verify the server's TLS certificate.
        server_hostname: Server hostname for SNI and Kerberos SPN.
        protocol: SPNEGO protocol - "ntlm" or "negotiate" (for Kerberos).
    """

    username: str = ""
    password: str = ""
    domain: str = ""
    verify_cert: bool = True
    server_hostname: str = field(default="", repr=False)
    protocol: str = "ntlm"

    async def establish(self, x224: X224Layer, tcp: TcpTransport) -> None:
        """Upgrade TCP to TLS, then perform CredSSP handshake.

        1. Upgrade TCP to TLS (same as TlsSecurityLayer).
        2. Perform CredSSP handshake using pyspnego.

        Args:
            x224: The X.224 layer (unused for NLA, but part of the interface).
            tcp: The TCP transport to upgrade to TLS.

        Raises:
            AuthenticationError: If credentials are invalid (Req 11, AC 5).
            NegotiationError: If SPNEGO/Kerberos negotiation fails (Req 11, AC 6).
        """
        # Step 1: TLS upgrade
        await self._upgrade_tls(tcp)

        # Step 2: CredSSP handshake
        await self._credssp_handshake(tcp)

    async def _upgrade_tls(self, tcp: TcpTransport) -> None:
        """Upgrade TCP connection to TLS."""
        ctx = ssl.create_default_context()

        if not self.verify_cert:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            logger.warning("TLS certificate verification disabled for NLA")

        hostname = self.server_hostname or ""
        await tcp.upgrade_to_tls(ctx, server_hostname=hostname)

    async def _credssp_handshake(self, tcp: TcpTransport) -> None:
        """Perform CredSSP handshake per [MS-CSSP] Section 3.1.5.

        Exchange TSRequest messages using spnego.client() for token generation.
        The handshake flow:
        1. Client sends TSRequest with SPNEGO token (negoTokens)
        2. Server responds with TSRequest containing SPNEGO token
        3. Client sends TSRequest with SPNEGO token + encrypted server public key
        4. Server responds with TSRequest containing encrypted server public key
        5. Client sends TSRequest with encrypted TSCredentials

        Args:
            tcp: The TLS-upgraded TCP transport.

        Raises:
            AuthenticationError: On invalid credentials (AC 5).
            NegotiationError: On SPNEGO/Kerberos failure (AC 6).
        """
        # Create SPNEGO client context
        try:
            spnego_client = spnego.client(
                username=self.username,
                password=self.password,
                hostname=self.server_hostname,
                service="TERMSRV",
                protocol=self.protocol,
            )
        except Exception as e:
            raise NegotiationError(f"Failed to create SPNEGO context: {e}") from e

        # Generate client nonce for CredSSP version >= 5
        client_nonce = os.urandom(32)

        # Get the server's TLS public key for binding
        server_pub_key = self._get_server_public_key(tcp)

        # Phase 1: Initial SPNEGO token exchange
        server_token: bytes | None = None
        try:
            out_token = spnego_client.step(server_token)
        except Exception as e:
            raise NegotiationError(f"SPNEGO initial token generation failed: {e}") from e

        # Send first TSRequest with negoToken
        ts_request = TSRequest(
            nego_tokens=[out_token] if out_token else [],
            client_nonce=client_nonce,
        )
        await tcp.send(ts_request.serialize())

        # Phase 2: Exchange tokens until SPNEGO completes
        while not spnego_client.complete:
            # Receive server response
            response_data = await self._recv_tsrequest(tcp)
            server_ts_request = TSRequest.parse(response_data)

            # Check for error code from server
            if server_ts_request.error_code:
                raise AuthenticationError(
                    error_code=server_ts_request.error_code,
                    message="Server rejected credentials",
                )

            # Get server's SPNEGO token
            if not server_ts_request.nego_tokens:
                raise NegotiationError("Server response missing SPNEGO token")

            server_token = server_ts_request.nego_tokens[0]

            # Generate next client token
            try:
                out_token = spnego_client.step(server_token)
            except Exception as e:
                raise NegotiationError(
                    f"SPNEGO token exchange failed: {e}"
                ) from e

            if spnego_client.complete:
                # Authentication complete - send pubKeyAuth
                encrypted_pub_key = spnego_client.wrap(server_pub_key).data
                ts_request = TSRequest(
                    nego_tokens=[out_token] if out_token else [],
                    pub_key_auth=encrypted_pub_key,
                    client_nonce=client_nonce,
                )
            else:
                ts_request = TSRequest(
                    nego_tokens=[out_token] if out_token else [],
                    client_nonce=client_nonce,
                )

            await tcp.send(ts_request.serialize())

        # Phase 3: Receive server's pubKeyAuth response
        response_data = await self._recv_tsrequest(tcp)
        server_ts_request = TSRequest.parse(response_data)

        if server_ts_request.error_code:
            raise AuthenticationError(
                error_code=server_ts_request.error_code,
                message="Server rejected credentials during key verification",
            )

        # Phase 4: Send encrypted TSCredentials
        await self._send_credentials(tcp, spnego_client, client_nonce)

    def _get_server_public_key(self, tcp: TcpTransport) -> bytes:
        """Extract the server's TLS public key from the SSL socket.

        Returns the DER-encoded SubjectPublicKeyInfo from the server certificate.
        """
        transport = tcp.writer.transport
        ssl_object = transport.get_extra_info("ssl_object")
        if ssl_object is None:
            # Fallback: return empty bytes (will fail during handshake)
            return b""
        peer_cert_der = ssl_object.getpeercert(binary_form=True)
        if peer_cert_der is None:
            return b""
        # Extract SubjectPublicKeyInfo from the certificate
        from cryptography import x509

        cert = x509.load_der_x509_certificate(peer_cert_der)
        return cert.public_key().public_bytes(
            encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.DER,
            format=__import__("cryptography").hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    async def _recv_tsrequest(self, tcp: TcpTransport) -> bytes:
        """Receive a complete TSRequest from the transport.

        Reads the ASN.1 DER-encoded TSRequest by parsing the length prefix.
        """
        # Read the first byte (SEQUENCE tag)
        header = await tcp.recv(1)
        if not header or header[0] != 0x30:
            raise NegotiationError("Invalid TSRequest: expected SEQUENCE tag")

        # Read length
        length_byte = await tcp.recv(1)
        if length_byte[0] < 0x80:
            total_length = length_byte[0]
            return header + length_byte + await tcp.recv(total_length)
        else:
            num_length_bytes = length_byte[0] & 0x7F
            length_data = await tcp.recv(num_length_bytes)
            total_length = int.from_bytes(length_data, "big")
            content = await tcp.recv(total_length)
            return header + length_byte + length_data + content

    async def _send_credentials(
        self, tcp: TcpTransport, spnego_client: spnego.ContextProxy, client_nonce: bytes
    ) -> None:
        """Encrypt and send TSCredentials to the server (Req 11, AC 4).

        Builds TSPasswordCreds with domain/username/password, wraps in
        TSCredentials, encrypts with SPNEGO session key, and sends as
        TSRequest.authInfo.
        """
        # Build TSPasswordCreds
        password_creds = TSPasswordCreds(
            domain_name=self.domain,
            user_name=self.username,
            password=self.password,
        )

        # Build TSCredentials (credType=1 for password)
        ts_credentials = TSCredentials(
            cred_type=1,
            credentials=password_creds.serialize(),
        )

        # Encrypt credentials with SPNEGO session security
        encrypted_creds = spnego_client.wrap(ts_credentials.serialize()).data

        # Send final TSRequest with authInfo
        ts_request = TSRequest(
            auth_info=encrypted_creds,
            client_nonce=client_nonce,
        )
        await tcp.send(ts_request.serialize())

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
        (no MAC or encrypted payload).

        Args:
            data: PDU payload bytes.

        Returns:
            4-byte security header + payload.
        """
        header = struct.pack("<HH", 0, 0)
        return header + data

    def unwrap_pdu(self, data: bytes) -> tuple[bytes, int]:
        """Strip the 4-byte security header and return payload with flags.

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
        """NLA is an Enhanced Security protocol.

        Returns:
            Always True.
        """
        return True
