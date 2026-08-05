#!/usr/bin/env python3
"""Debug Phase 2: CredSSP + MCS Connect Initial.

Tests whether the server accepts our MCS Connect Initial PDU after
successful NLA/CredSSP authentication.
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
from arrdipi.pdu.credssp import TSRequest, TSCredentials, TSPasswordCreds
from arrdipi.mcs.gcc import (
    ClientCoreData,
    ClientSecurityData,
    ClientNetworkData,
    encode_gcc_conference_create_request,
)
from arrdipi.mcs.layer import _build_connect_initial

HOST = "localhost"
PORT = 13389  # Adjust to match your SSM port forward

# CredSSP v5+ magic
CLIENT_SERVER_HASH_MAGIC = b"CredSSP Client-To-Server Binding Hash\0"


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
    print(f"Phase 2 Debug: CredSSP + MCS Connect Initial")
    print(f"{'='*60}")

    # --- Phase 1: Connect + X.224 + TLS ---
    tcp = await TcpTransport.connect(HOST, PORT, timeout=10)
    x224 = X224Layer(tcp)
    requested = NegotiationProtocol.PROTOCOL_HYBRID | NegotiationProtocol.PROTOCOL_SSL
    selected = await x224.negotiate(
        f"Cookie: mstshash={username}\r\n", requested
    )
    print(f"✓ X.224 negotiated: {selected.name} (value={selected.value})")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    await tcp.upgrade_to_tls(ctx, server_hostname=None)
    print(f"✓ TLS upgraded")

    # --- CredSSP ---
    ssl_obj = tcp.writer.transport.get_extra_info("ssl_object")
    cert_der = ssl_obj.getpeercert(binary_form=True)

    # Channel bindings
    cert_hash = hashlib.sha256(cert_der).digest()
    cbt = spnego.channel_bindings.GssChannelBindings(
        application_data=b"tls-server-end-point:" + cert_hash
    )

    # Public key (PKCS1)
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    cert = x509.load_der_x509_certificate(cert_der)
    server_pub_key = cert.public_key().public_bytes(Encoding.DER, PublicFormat.PKCS1)

    spnego_client = spnego.client(
        username=username, password=password,
        hostname=HOST, service="TERMSRV",
        protocol="ntlm", channel_bindings=cbt,
    )

    client_nonce = os.urandom(32)

    # NEGOTIATE
    out_token = spnego_client.step(None)
    ts_request = TSRequest(version=6, nego_tokens=[out_token], client_nonce=client_nonce)
    await tcp.send(ts_request.serialize())

    # CHALLENGE
    resp = TSRequest.parse(await recv_tsrequest(tcp))
    out_token = spnego_client.step(resp.nego_tokens[0])

    # AUTHENTICATE + pubKeyAuth
    hash_input = CLIENT_SERVER_HASH_MAGIC + client_nonce + server_pub_key
    hash_value = hashlib.sha256(hash_input).digest()
    pub_key_auth = spnego_client.wrap(hash_value).data

    ts_request = TSRequest(
        version=6, nego_tokens=[out_token] if out_token else [],
        pub_key_auth=pub_key_auth, client_nonce=client_nonce,
    )
    await tcp.send(ts_request.serialize())

    # Server pubKeyAuth response
    resp = TSRequest.parse(await recv_tsrequest(tcp))
    if resp.error_code:
        print(f"✗ Server error: 0x{resp.error_code:08X}")
        return
    print(f"✓ pubKeyAuth accepted")

    # Send credentials
    password_creds = TSPasswordCreds(domain_name="", user_name=username, password=password)
    ts_credentials = TSCredentials(cred_type=1, credentials=password_creds.serialize())
    encrypted_creds = spnego_client.wrap(ts_credentials.serialize()).data
    ts_request = TSRequest(auth_info=encrypted_creds, client_nonce=client_nonce)
    await tcp.send(ts_request.serialize())
    print(f"✓ Credentials sent")

    # --- Phase 2: MCS Connect Initial ---
    print(f"\n--- Phase 2: MCS Connect Initial ---")

    # Build the same ClientCoreData that connection.py builds
    client_core = ClientCoreData(
        desktop_width=1920,
        desktop_height=1080,
        color_depth=0xCA01,
        high_color_depth=32,
        supported_color_depths=0x000F,
        client_name=username[:15],
        early_capability_flags=0x0001,
        server_selected_protocol=selected.value,  # KEY: must match negotiated protocol
    )
    client_security = ClientSecurityData(
        encryption_methods=0,  # MUST be 0 for Enhanced Security (NLA/TLS)
        ext_encryption_methods=0,
    )
    network = ClientNetworkData(
        channel_names=["cliprdr", "rdpsnd", "rdpdr", "drdynvc"],
        channel_options=[0xC0000000] * 4,
    )

    gcc_data = encode_gcc_conference_create_request(client_core, client_security, network)
    connect_initial_pdu = _build_connect_initial(gcc_data)

    print(f"  ClientCoreData: server_selected_protocol={selected.value}")
    print(f"  GCC data: {len(gcc_data)} bytes")
    print(f"  Connect Initial PDU: {len(connect_initial_pdu)} bytes")
    print(f"  First 20 bytes: {connect_initial_pdu[:20].hex()}")

    # Send via X.224 Data TPDU (same as x224.send_pdu())
    await x224.send_pdu(connect_initial_pdu)
    print(f"  ✓ Sent MCS Connect Initial via X.224")

    # Try to receive response
    print(f"\n  Waiting for MCS Connect Response...")
    try:
        response_data = await asyncio.wait_for(x224.recv_pdu(), timeout=5)
        print(f"  ✓ Got response: {len(response_data)} bytes")
        print(f"  First 20 bytes: {response_data[:20].hex()}")
        
        # Phase 3: Erect Domain + Attach User
        print(f"\n--- Phase 3: Erect Domain + Attach User ---")
        
        # Send Erect Domain Request
        erect_pdu = b"\x04\x01\x00\x01\x00"
        await x224.send_pdu(erect_pdu)
        print(f"  ✓ Sent Erect Domain Request: {erect_pdu.hex()}")
        
        # Send Attach User Request
        attach_pdu = b"\x28"
        await x224.send_pdu(attach_pdu)
        print(f"  ✓ Sent Attach User Request: {attach_pdu.hex()}")
        
        # Receive Attach User Confirm
        confirm_data = await asyncio.wait_for(x224.recv_pdu(), timeout=5)
        print(f"  Got Attach User Confirm: {confirm_data.hex()} ({len(confirm_data)} bytes)")
        
        type_byte = confirm_data[0]
        result = type_byte & 0x03
        print(f"  Type byte: 0x{type_byte:02x}, result={result}")
        if result == 0:
            user_id = int.from_bytes(confirm_data[1:3], 'big') + 1001
            print(f"  ✓ SUCCESS! User channel ID: {user_id}")
        else:
            print(f"  ✗ FAILED: result={result}")
            
    except asyncio.TimeoutError:
        print(f"  ✗ Timeout - no response")
    except asyncio.IncompleteReadError as e:
        print(f"  ✗ Connection closed: {e.partial!r} read, expected {e.expected}")
    except Exception as e:
        print(f"  ✗ Error: {type(e).__name__}: {e}")

    tcp.writer.close()


if __name__ == "__main__":
    asyncio.run(main())
