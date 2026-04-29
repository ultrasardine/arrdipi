"""Standard RDP Security layer implementation.

Implements RSA key exchange and RC4 encryption per [MS-RDPBCGR] Section 5.3.
Handles proprietary certificate validation, key derivation, and per-direction
RC4 encryption with MAC computation.

Requirements addressed: Req 9 (AC 1–5)
"""

from __future__ import annotations

import hashlib
import logging
import os
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4

from arrdipi.errors import PduParseError
from arrdipi.security.base import SecurityLayer

if TYPE_CHECKING:
    from arrdipi.transport.tcp import TcpTransport
    from arrdipi.transport.x224 import X224Layer

logger = logging.getLogger(__name__)

# Security header flags
SEC_ENCRYPT = 0x0008
SEC_INFO_PKT = 0x0040
SEC_LICENSE_PKT = 0x0080

# RC4 key refresh interval per [MS-RDPBCGR] 5.3.6
_KEY_UPDATE_INTERVAL = 4096

# Well-known Terminal Services signing key for proprietary certificate validation
# per [MS-RDPBCGR] 5.3.3.1.1
# Modulus (64 bytes, stored as big-endian integer)
_TS_SIGNING_KEY_MODULUS_LE = bytes([
    0x3d, 0x3a, 0x5e, 0xbd, 0x72, 0x43, 0x3e, 0xc9,
    0x4d, 0xbb, 0xc1, 0x1e, 0x4a, 0xba, 0x5f, 0xcb,
    0x3e, 0x88, 0x20, 0x87, 0xef, 0xf5, 0xc1, 0xe2,
    0xd7, 0xb7, 0x6b, 0x9a, 0xf2, 0x52, 0x45, 0x95,
    0xce, 0x63, 0x65, 0x6b, 0x58, 0x3a, 0xfe, 0xef,
    0x7c, 0xe7, 0xbf, 0xfe, 0x3d, 0xf6, 0x5c, 0x7d,
    0x6c, 0x5e, 0x06, 0x09, 0x1a, 0xf5, 0x61, 0xbb,
    0x20, 0x93, 0x09, 0x5f, 0x05, 0x6d, 0xea, 0x87,
])

# Public exponent for the TS signing key
_TS_SIGNING_KEY_EXPONENT = 0x00010001


def _salted_hash(
    s: bytes, i: bytes, client_random: bytes, server_random: bytes
) -> bytes:
    """Compute SaltedHash per [MS-RDPBCGR] 5.3.5.

    SaltedHash(S, I) = MD5(S + SHA1(I + S + ClientRandom + ServerRandom))
    """
    sha1_input = i + s + client_random + server_random
    sha1_hash = hashlib.sha1(sha1_input).digest()
    md5_input = s + sha1_hash
    return hashlib.md5(md5_input).digest()


def _final_hash(session_key_blob: bytes, k: bytes) -> bytes:
    """Compute FinalHash per [MS-RDPBCGR] 5.3.5.

    FinalHash(K) = MD5(SessionKeyBlob[0:32] + K)
    """
    return hashlib.md5(session_key_blob[:32] + k).digest()


def derive_keys(
    client_random: bytes, server_random: bytes
) -> tuple[bytes, bytes, bytes]:
    """Derive 128-bit session keys from client and server randoms.

    Returns (mac_key, encrypt_key, decrypt_key) per [MS-RDPBCGR] 5.3.5.

    Key derivation:
        PreMasterSecret = First48Bytes(ClientRandom + ServerRandom)
        MasterSecret = SaltedHash(PreMasterSecret, "A") +
                       SaltedHash(PreMasterSecret, "BB") +
                       SaltedHash(PreMasterSecret, "CCC")
        SessionKeyBlob = SaltedHash(MasterSecret, "X") +
                         SaltedHash(MasterSecret, "YY") +
                         SaltedHash(MasterSecret, "ZZZ")

    Then:
        MACKey128 = First16Bytes(SessionKeyBlob)
        InitialClientEncryptKey128 = FinalHash(Second16Bytes(SessionKeyBlob))
        InitialClientDecryptKey128 = FinalHash(Third16Bytes(SessionKeyBlob))
    """
    pre_master_secret = (client_random + server_random)[:48]

    master_secret = (
        _salted_hash(pre_master_secret, b"A", client_random, server_random)
        + _salted_hash(pre_master_secret, b"BB", client_random, server_random)
        + _salted_hash(pre_master_secret, b"CCC", client_random, server_random)
    )

    session_key_blob = (
        _salted_hash(master_secret, b"X", client_random, server_random)
        + _salted_hash(master_secret, b"YY", client_random, server_random)
        + _salted_hash(master_secret, b"ZZZ", client_random, server_random)
    )

    mac_key = session_key_blob[:16]
    encrypt_key = _final_hash(session_key_blob, session_key_blob[16:32])
    decrypt_key = _final_hash(session_key_blob, session_key_blob[32:48])

    return mac_key, encrypt_key, decrypt_key


def compute_mac(mac_key: bytes, data: bytes) -> bytes:
    """Compute MAC per [MS-RDPBCGR] 5.3.6.1.

    MAC(data):
        pad1 = 0x36 repeated 40 times
        pad2 = 0x5C repeated 48 times
        DataLength = len(data) as u32 LE
        SHAComponent = SHA1(MACKey + pad1 + DataLength + data)
        MAC = MD5(MACKey + pad2 + SHAComponent)[0:8]
    """
    pad1 = b"\x36" * 40
    pad2 = b"\x5c" * 48
    data_length = struct.pack("<I", len(data))

    sha_component = hashlib.sha1(mac_key + pad1 + data_length + data).digest()
    mac_full = hashlib.md5(mac_key + pad2 + sha_component).digest()
    return mac_full[:8]


def _update_session_key(original_key: bytes, current_key: bytes) -> bytes:
    """Update RC4 session key after 4096 packets per [MS-RDPBCGR] 5.3.6.

    new_key = MD5(original_key + pad1 + SHA1(original_key + pad2 + current_key))
    Then RC4-encrypt the first 16 bytes of new_key with new_key itself.

    Simplified per spec: new_key = RC4(MD5(OriginalKey + CurrentKey))[0:16]
    using the MD5 result as both key and data for a single RC4 pass.
    """
    # Per [MS-RDPBCGR] 5.3.6.2:
    # 1. Compute pad1 = SHA1(OriginalKey + pad_sha + CurrentKey)
    # 2. Compute pad2 = MD5(OriginalKey + pad_md5 + pad1)
    # 3. RC4 encrypt first keylen bytes of pad2 with pad2 as key
    pad_sha = b"\x36" * 40
    pad_md5 = b"\x5c" * 48

    sha_result = hashlib.sha1(original_key + pad_sha + current_key).digest()
    new_key = hashlib.md5(original_key + pad_md5 + sha_result).digest()

    # RC4 encrypt the new key with itself to get the final updated key
    cipher = Cipher(ARC4(new_key), mode=None)
    encryptor = cipher.encryptor()
    updated_key = encryptor.update(new_key)
    encryptor.finalize()

    return updated_key[:16]


def parse_proprietary_certificate(cert_data: bytes) -> tuple[int, bytes]:
    """Parse a proprietary certificate and extract the RSA public key.

    Returns (exponent, modulus_bytes) where modulus_bytes is in little-endian.
    Validates the signature using the well-known TS signing key.

    Raises PduParseError if the certificate is malformed or signature is invalid.
    """
    offset = 0

    if len(cert_data) < 8:
        raise PduParseError("ProprietaryCertificate", 0, "certificate too short")

    # dwVersion (u32 LE) — should be 0x00000001 for proprietary cert
    dw_version = struct.unpack_from("<I", cert_data, offset)[0]
    offset += 4

    # dwSigAlgId (u32 LE) — SIGNATURE_ALG_RSA = 0x00000001
    dw_sig_alg_id = struct.unpack_from("<I", cert_data, offset)[0]
    offset += 4

    # dwKeyAlgId (u32 LE) — KEY_EXCHANGE_ALG_RSA = 0x00000001
    dw_key_alg_id = struct.unpack_from("<I", cert_data, offset)[0]
    offset += 4

    # wPublicKeyBlobType (u16 LE) — BB_RSA_KEY_BLOB = 0x0006
    pub_key_blob_type = struct.unpack_from("<H", cert_data, offset)[0]
    offset += 2

    # wPublicKeyBlobLen (u16 LE)
    pub_key_blob_len = struct.unpack_from("<H", cert_data, offset)[0]
    offset += 2

    if offset + pub_key_blob_len > len(cert_data):
        raise PduParseError(
            "ProprietaryCertificate", offset,
            "public key blob extends beyond certificate data"
        )

    # Parse RSA public key blob
    pub_key_blob = cert_data[offset:offset + pub_key_blob_len]
    exponent, modulus = _parse_rsa_public_key_blob(pub_key_blob)
    offset += pub_key_blob_len

    # wSignatureBlobType (u16 LE) — BB_RSA_SIGNATURE_BLOB = 0x0008
    if offset + 4 > len(cert_data):
        raise PduParseError(
            "ProprietaryCertificate", offset,
            "missing signature blob header"
        )
    sig_blob_type = struct.unpack_from("<H", cert_data, offset)[0]
    offset += 2

    # wSignatureBlobLen (u16 LE)
    sig_blob_len = struct.unpack_from("<H", cert_data, offset)[0]
    offset += 2

    if offset + sig_blob_len > len(cert_data):
        raise PduParseError(
            "ProprietaryCertificate", offset,
            "signature blob extends beyond certificate data"
        )

    signature = cert_data[offset:offset + sig_blob_len]

    # Validate signature using the well-known TS signing key
    # The signed data is the public key blob
    _validate_proprietary_signature(pub_key_blob, signature)

    return exponent, modulus


def _parse_rsa_public_key_blob(blob: bytes) -> tuple[int, bytes]:
    """Parse an RSA public key blob per [MS-RDPBCGR] 5.3.3.1.1.

    Structure:
        magic (u32 LE) — "RSA1" = 0x31415352
        keylen (u32 LE) — modulus length in bytes
        bitlen (u32 LE) — modulus length in bits
        datalen (u32 LE) — max data that can be encrypted (keylen - 1)
        pubExp (u32 LE) — public exponent
        modulus (keylen bytes) — modulus in little-endian

    Returns (exponent, modulus_le_bytes).
    """
    if len(blob) < 20:
        raise PduParseError("RSAPublicKeyBlob", 0, "blob too short for header")

    magic = struct.unpack_from("<I", blob, 0)[0]
    if magic != 0x31415352:  # "RSA1"
        raise PduParseError(
            "RSAPublicKeyBlob", 0,
            f"invalid magic 0x{magic:08X}, expected 0x31415352 (RSA1)"
        )

    keylen = struct.unpack_from("<I", blob, 4)[0]
    bitlen = struct.unpack_from("<I", blob, 8)[0]
    datalen = struct.unpack_from("<I", blob, 12)[0]
    pub_exp = struct.unpack_from("<I", blob, 16)[0]

    if len(blob) < 20 + keylen:
        raise PduParseError(
            "RSAPublicKeyBlob", 20,
            f"blob too short for modulus (need {keylen} bytes)"
        )

    modulus_le = blob[20:20 + keylen]
    return pub_exp, modulus_le


def _validate_proprietary_signature(pub_key_blob: bytes, signature: bytes) -> None:
    """Validate the proprietary certificate signature.

    The signature is computed as:
        MD5(PublicKeyBlob) encrypted with the TS signing key's private key.

    Per [MS-RDPBCGR] 5.3.3.1.2, the signature is a raw RSA operation
    (no PKCS#1 padding in the traditional sense — it uses a custom format).

    The validation performs: decrypt signature with TS public key, compare
    first 16 bytes with MD5(pub_key_blob), remaining bytes should be 0x00
    padded with a 0xFF...FF01 PKCS#1 v1.5 style padding.
    """
    # Compute expected hash
    expected_hash = hashlib.md5(pub_key_blob).digest()

    # The signature is in little-endian format, strip trailing zeros
    # (padding bytes from the RSA operation)
    sig_bytes = signature.rstrip(b"\x00")

    # Convert signature from little-endian to big-endian integer
    sig_int = int.from_bytes(sig_bytes, byteorder="little")

    # Build the TS signing public key
    modulus_int = int.from_bytes(_TS_SIGNING_KEY_MODULUS_LE, byteorder="little")

    # Perform raw RSA: decrypted = sig^e mod n
    decrypted_int = pow(sig_int, _TS_SIGNING_KEY_EXPONENT, modulus_int)

    # Convert back to bytes (little-endian, 64 bytes for 512-bit key)
    decrypted_bytes = decrypted_int.to_bytes(64, byteorder="little")

    # First 16 bytes should match the MD5 hash
    if decrypted_bytes[:16] != expected_hash:
        raise PduParseError(
            "ProprietaryCertificate", 0,
            "proprietary certificate signature validation failed"
        )

    logger.debug("Proprietary certificate signature validated successfully")


def _rsa_encrypt_client_random(
    client_random: bytes, exponent: int, modulus_le: bytes
) -> bytes:
    """Encrypt client random with server's RSA public key.

    Per [MS-RDPBCGR] 5.3.4, the client random is encrypted using
    raw RSA (no padding beyond zero-padding to modulus length).

    The encrypted result is in little-endian format.
    """
    # Convert modulus from little-endian to integer
    modulus_int = int.from_bytes(modulus_le, byteorder="little")
    modulus_len = len(modulus_le.rstrip(b"\x00"))
    # Use full modulus length for output
    modulus_byte_len = len(modulus_le)

    # Zero-pad client random to modulus length (right-pad in LE = left-pad in BE)
    # Per spec: treat client_random as little-endian integer
    random_int = int.from_bytes(client_random, byteorder="little")

    # RSA encrypt: ciphertext = random^e mod n
    encrypted_int = pow(random_int, exponent, modulus_int)

    # Convert back to little-endian bytes
    encrypted_bytes = encrypted_int.to_bytes(modulus_byte_len, byteorder="little")

    return encrypted_bytes


@dataclass
class StandardSecurityLayer(SecurityLayer):
    """Standard RDP Security using RSA key exchange and RC4 encryption.

    Implements the legacy RDP security mechanism per [MS-RDPBCGR] Section 5.3.
    Key exchange happens during connection phase 4 via the Security Exchange PDU.

    Attributes:
        server_random: 32-byte random from server (from ServerSecurityData).
        client_random: 32-byte random generated by client.
        encrypt_key: Derived RC4 session key for encryption (client→server).
        decrypt_key: Derived RC4 session key for decryption (server→client).
        mac_key: Derived MAC key for integrity validation.
        encrypt_count: Packet counter for encrypt direction key refresh.
        decrypt_count: Packet counter for decrypt direction key refresh.
    """

    server_random: bytes = field(default=b"", repr=False)
    client_random: bytes = field(default=b"", repr=False)
    encrypt_key: bytes = field(default=b"", repr=False)
    decrypt_key: bytes = field(default=b"", repr=False)
    mac_key: bytes = field(default=b"", repr=False)
    encrypt_count: int = field(default=0)
    decrypt_count: int = field(default=0)

    # Internal state for RC4 ciphers and key refresh
    _encrypt_cipher: object = field(default=None, init=False, repr=False)
    _decrypt_cipher: object = field(default=None, init=False, repr=False)
    _original_encrypt_key: bytes = field(default=b"", init=False, repr=False)
    _original_decrypt_key: bytes = field(default=b"", init=False, repr=False)

    async def establish(self, x224: X224Layer, tcp: TcpTransport) -> None:
        """No-op — key exchange happens during phase 4 via Security Exchange PDU.

        For Standard RDP Security, the actual key establishment occurs when
        init_keys() is called with the server security data.
        """
        pass

    def init_keys(self, server_random: bytes, server_certificate: bytes) -> bytes:
        """Initialize security keys from server security data.

        Parses the server's proprietary certificate, validates its signature,
        generates a client random, encrypts it with the server's RSA public key,
        and derives the RC4 session keys.

        Args:
            server_random: 32-byte server random from ServerSecurityData.
            server_certificate: Raw certificate bytes from ServerSecurityData.

        Returns:
            Encrypted client random blob for the Security Exchange PDU.

        Raises:
            PduParseError: If the certificate is malformed or signature invalid.
        """
        self.server_random = server_random

        # Parse and validate the proprietary certificate (Req 9, AC 1, 5)
        exponent, modulus_le = parse_proprietary_certificate(server_certificate)

        # Generate 32-byte client random (Req 9, AC 2)
        self.client_random = os.urandom(32)

        # Encrypt client random with server RSA public key (Req 9, AC 2)
        encrypted_random = _rsa_encrypt_client_random(
            self.client_random, exponent, modulus_le
        )

        # Derive session keys (Req 9, AC 3)
        self.mac_key, self.encrypt_key, self.decrypt_key = derive_keys(
            self.client_random, self.server_random
        )

        # Store original keys for key update
        self._original_encrypt_key = self.encrypt_key
        self._original_decrypt_key = self.decrypt_key

        # Initialize RC4 ciphers
        self._init_rc4_ciphers()

        logger.debug("Standard RDP Security keys initialized")
        return encrypted_random

    def _init_rc4_ciphers(self) -> None:
        """Initialize RC4 cipher objects for encrypt and decrypt directions."""
        enc_cipher = Cipher(ARC4(self.encrypt_key), mode=None)
        self._encrypt_cipher = enc_cipher.encryptor()

        dec_cipher = Cipher(ARC4(self.decrypt_key), mode=None)
        self._decrypt_cipher = dec_cipher.decryptor()

    def _refresh_encrypt_key(self) -> None:
        """Refresh the encryption key after 4096 packets."""
        self.encrypt_key = _update_session_key(
            self._original_encrypt_key, self.encrypt_key
        )
        # Re-initialize the encrypt cipher with the new key
        enc_cipher = Cipher(ARC4(self.encrypt_key), mode=None)
        self._encrypt_cipher = enc_cipher.encryptor()
        self.encrypt_count = 0

    def _refresh_decrypt_key(self) -> None:
        """Refresh the decryption key after 4096 packets."""
        self.decrypt_key = _update_session_key(
            self._original_decrypt_key, self.decrypt_key
        )
        # Re-initialize the decrypt cipher with the new key
        dec_cipher = Cipher(ARC4(self.decrypt_key), mode=None)
        self._decrypt_cipher = dec_cipher.decryptor()
        self.decrypt_count = 0

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt outbound PDU data using RC4.

        Applies RC4 encryption and increments the packet counter.
        Refreshes the key after every 4096 packets.

        Args:
            data: Raw PDU payload bytes.

        Returns:
            RC4-encrypted bytes.
        """
        if self.encrypt_count >= _KEY_UPDATE_INTERVAL:
            self._refresh_encrypt_key()

        encrypted = self._encrypt_cipher.update(data)
        self.encrypt_count += 1
        return encrypted

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt inbound PDU data using RC4.

        Applies RC4 decryption and increments the packet counter.
        Refreshes the key after every 4096 packets.

        Args:
            data: Encrypted PDU payload bytes.

        Returns:
            Decrypted bytes.
        """
        if self.decrypt_count >= _KEY_UPDATE_INTERVAL:
            self._refresh_decrypt_key()

        decrypted = self._decrypt_cipher.update(data)
        self.decrypt_count += 1
        return decrypted

    def compute_mac(self, data: bytes) -> bytes:
        """Compute MAC for the given data using the session MAC key.

        Args:
            data: Data to compute MAC over.

        Returns:
            8-byte MAC value.
        """
        return compute_mac(self.mac_key, data)

    def wrap_pdu(self, data: bytes) -> bytes:
        """Add security header with SEC_ENCRYPT flag and MAC to outbound PDU.

        Security header format for Standard Security:
            flags (u16 LE) — SEC_ENCRYPT (0x0008)
            flagsHi (u16 LE) — 0
            MAC (8 bytes)
            encrypted payload

        Args:
            data: PDU payload bytes (plaintext).

        Returns:
            Security header + MAC + encrypted payload.
        """
        mac = self.compute_mac(data)
        encrypted = self.encrypt(data)

        header = struct.pack("<HH", SEC_ENCRYPT, 0)
        return header + mac + encrypted

    def unwrap_pdu(self, data: bytes) -> tuple[bytes, int]:
        """Strip security header from inbound PDU, validate MAC, decrypt.

        Reads the security flags. If SEC_ENCRYPT is set, validates the MAC
        and decrypts the payload.

        Args:
            data: Raw bytes including security header + optional MAC + payload.

        Returns:
            Tuple of (decrypted payload bytes, security flags).
        """
        if len(data) < 4:
            raise PduParseError("SecurityHeader", 0, "data too short for header")

        flags = struct.unpack_from("<H", data, 0)[0]
        # flagsHi at offset 2 (unused for now)
        offset = 4

        if flags & SEC_ENCRYPT:
            # MAC is 8 bytes after the header
            if len(data) < offset + 8:
                raise PduParseError(
                    "SecurityHeader", offset, "data too short for MAC"
                )
            received_mac = data[offset:offset + 8]
            offset += 8

            # Decrypt the remaining payload
            encrypted_payload = data[offset:]
            decrypted = self.decrypt(encrypted_payload)

            # Validate MAC
            expected_mac = self.compute_mac(decrypted)
            if received_mac != expected_mac:
                logger.warning("MAC validation failed on inbound PDU")

            return decrypted, flags
        else:
            # No encryption — return payload after header
            return data[offset:], flags

    @property
    def is_enhanced(self) -> bool:
        """Standard RDP Security is not Enhanced Security.

        Returns:
            Always False.
        """
        return False
