#!/usr/bin/env python3
"""Debug CredSSP WITH channel bindings and v5+ pubKeyAuth format.

This script tests the correct CredSSP v5+ format where pubKeyAuth is:
    ENCRYPT(SHA256("CredSSP Client-To-Server Binding Hash\0" || nonce || pubkey))
"""

import asyncio
import hashlib
import os
import ssl
import sys

sys.path.insert(0, "/Users/simoesa/Projects/personal/arrdipi")

import spnego

from arrdipi.transport.tcp import TcpTransport
from arrdipi.transport.x224 import X224Layer
from arrdipi.pdu.types import NegotiationProtocol
from arrdipi.pdu.credssp import TSRequest

HOST = "localhost"
PORT = 13391

# CredSSP v5+ magic strings (MS-CSSP 3.1.5.1.2)
CLIENT_SERVER_HASH_MAGIC = b"CredSSP Client-To-Server Binding Hash\0"
SERVER_CLIENT_HASH_MAGIC = b"CredSSP Server-To-Client Binding Hash\0"


def make_channel_bindings(cert_der: bytes) -> spnego.channel_bindings.GssChannelBindings:
    """Create channel bindings per RFC 5929 tls-server-end-point."""
    cert_hash = hashlib.sha256(cert_der).digest()
    application_data = b"tls-server-end-point:" + cert_hash
    return spnego.channel_bindings.GssChannelBindings(application_data=application_data)


def compute_pub_key_auth_v5(
    spnego_client, server_pub_key: bytes, client_nonce: bytes
) -> bytes:
    """Compute pubKeyAuth for CredSSP v5+ (hash-based binding).
    
    Per MS-CSSP 3.1.5.1.2:
        pubKeyAuth = ENCRYPT(SHA256(magic || nonce || pubkey))
    """
    hash_input = CLIENT_SERVER_HASH_MAGIC + client_nonce + server_pub_key
    hash_value = hashlib.sha256(hash_input).digest()
    print(f"   Hash input: {len(hash_input)} bytes (magic:{len(CLIENT_SERVER_HASH_MAGIC)} + nonce:{len(client_nonce)} + pubkey:{len(server_pub_key)})")
    print(f"   SHA256 hash: {hash_value.hex()}")
    return spnego_client.wrap(hash_value).data


async def recv_tsrequest(tcp):
    header = await tcp.recv(1)
    if header[0] != 0x30:
        raise ValueError(f"Expected 0x30, got 0x{header[0]:02x}")
    length_byte = await tcp.recv(1)
    if length_byte[0] < 0x80:
        content = await tcp.recv(length_byte[0])
        return header + length_byte + content
    else:
        num = length_byte[0] & 0x7F
        length_data = await tcp.recv(num)
        total = int.from_bytes(length_data, "big")
        content = await tcp.recv(total)
        return header + length_byte + length_data + content


async def main():
    username = "Administrator"
    password = input("Enter RDP password: ")
    
    print(f"\n{'='*60}")
    print(f"CredSSP v5+ Test (hash-based pubKeyAuth)")
    print(f"{'='*60}")
    
    # Setup
    tcp = await TcpTransport.connect(HOST, PORT, timeout=10)
    x224 = X224Layer(tcp)
    await x224.negotiate(
        f"Cookie: mstshash={username}\r\n",
        NegotiationProtocol.PROTOCOL_HYBRID | NegotiationProtocol.PROTOCOL_SSL
    )
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    await tcp.upgrade_to_tls(ctx, server_hostname=None)
    
    ssl_obj = tcp.writer.transport.get_extra_info("ssl_object")
    print(f"✓ TLS: {ssl_obj.version()}")
    
    # Get server certificate
    cert_der = ssl_obj.getpeercert(binary_form=True)
    
    # Create channel bindings
    cbt = make_channel_bindings(cert_der)
    print(f"✓ Channel bindings created")
    
    # Get server public key in PKCS1 format (NOT SubjectPublicKeyInfo!)
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    cert = x509.load_der_x509_certificate(cert_der)
    server_pub_key = cert.public_key().public_bytes(Encoding.DER, PublicFormat.PKCS1)
    print(f"✓ Server public key (PKCS1): {len(server_pub_key)} bytes")
    
    # Create SPNEGO WITH channel bindings
    print(f"\nCreating SPNEGO context...")
    spnego_client = spnego.client(
        username=username,
        password=password,
        hostname=HOST,
        service="TERMSRV",
        protocol="ntlm",
        channel_bindings=cbt,
    )
    print(f"✓ SPNEGO with channel bindings")
    
    client_nonce = os.urandom(32)
    print(f"✓ Client nonce: {client_nonce.hex()}")
    
    # Initial token
    out_token = spnego_client.step(None)
    print(f"\n1. NEGOTIATE: {len(out_token)} bytes")
    
    ts_request = TSRequest(version=6, nego_tokens=[out_token], client_nonce=client_nonce)
    await tcp.send(ts_request.serialize())
    
    # Receive challenge
    response_data = await recv_tsrequest(tcp)
    response = TSRequest.parse(response_data)
    print(f"2. CHALLENGE: {len(response.nego_tokens[0])} bytes, server version={response.version}")
    
    # Process challenge
    server_token = response.nego_tokens[0]
    out_token = spnego_client.step(server_token)
    print(f"3. AUTHENTICATE: {len(out_token)} bytes")
    
    # --- KEY FIX: Use v5+ hash format for pubKeyAuth ---
    print(f"\n4. Computing pubKeyAuth (v5+ hash format):")
    encrypted_pub_key = compute_pub_key_auth_v5(spnego_client, server_pub_key, client_nonce)
    print(f"   Encrypted: {len(encrypted_pub_key)} bytes")
    
    # Send final message
    ts_request = TSRequest(
        version=6,
        nego_tokens=[out_token] if out_token else [],
        pub_key_auth=encrypted_pub_key,
        client_nonce=client_nonce,
    )
    await tcp.send(ts_request.serialize())
    print(f"5. Sent TSRequest with v5+ pubKeyAuth")
    
    # Wait for response
    print(f"\n6. Waiting for server response...")
    try:
        response_data = await asyncio.wait_for(recv_tsrequest(tcp), timeout=5)
        response = TSRequest.parse(response_data)
        print(f"   ✓ Server responded!")
        print(f"   version={response.version}, error={response.error_code}")
        
        if response.error_code:
            print(f"   ✗ Error: 0x{response.error_code:08X}")
        else:
            print(f"   ✓ pubKeyAuth ACCEPTED!")
            if response.pub_key_auth:
                print(f"   Server pubKeyAuth: {len(response.pub_key_auth)} bytes")
                # Verify server's response (optional)
                try:
                    decrypted = spnego_client.unwrap(response.pub_key_auth).data
                    print(f"   Decrypted: {len(decrypted)} bytes")
                except Exception as e:
                    print(f"   Could not decrypt: {e}")
            
            # Send credentials
            print(f"\n7. Sending credentials...")
            from arrdipi.pdu.credssp import TSCredentials, TSPasswordCreds
            
            password_creds = TSPasswordCreds(
                domain_name="",
                user_name=username,
                password=password,
            )
            ts_credentials = TSCredentials(
                cred_type=1,
                credentials=password_creds.serialize(),
            )
            encrypted_creds = spnego_client.wrap(ts_credentials.serialize()).data
            
            ts_request = TSRequest(
                auth_info=encrypted_creds,
                client_nonce=client_nonce,
            )
            await tcp.send(ts_request.serialize())
            print(f"   ✓ Credentials sent! ({len(encrypted_creds)} bytes encrypted)")
            print(f"\n   *** CredSSP HANDSHAKE COMPLETE! ***")
            
    except asyncio.TimeoutError:
        print(f"   ✗ Timeout - server closed connection (TLS alert)")
    except Exception as e:
        print(f"   ✗ {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
    
    tcp.writer.close()


if __name__ == "__main__":
    asyncio.run(main())
