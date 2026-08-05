#!/usr/bin/env python3
"""Debug Phases 5-9: full connection sequence after CredSSP.

Traces each phase step-by-step to find where the server drops us.
"""

import asyncio
import hashlib
import os
import ssl
import struct
import sys

sys.path.insert(0, "/Users/simoesa/Projects/personal/arrdipi")

import spnego

from arrdipi.transport.tcp import TcpTransport
from arrdipi.transport.x224 import X224Layer
from arrdipi.pdu.types import NegotiationProtocol
from arrdipi.pdu.credssp import TSRequest, TSCredentials, TSPasswordCreds
from arrdipi.mcs.gcc import (
    ClientCoreData, ClientSecurityData, ClientNetworkData,
    encode_gcc_conference_create_request, decode_gcc_conference_create_response,
)
from arrdipi.mcs.layer import (
    _build_connect_initial, _parse_connect_response,
    _build_send_data_request, _parse_send_data_indication,
    _parse_attach_user_confirm, _parse_channel_join_confirm,
    MCS_USER_CHANNEL_BASE,
)
from arrdipi.pdu.info import ClientInfoPdu, ExtendedInfoPacket, InfoFlags, TimezoneInfo
from arrdipi.pdu.types import CompressionType, PerformanceFlags

HOST = "localhost"
PORT = 13390

CLIENT_SERVER_HASH_MAGIC = b"CredSSP Client-To-Server Binding Hash\0"
SEC_INFO_PKT = 0x0040
SEC_LICENSE_PKT = 0x0080


async def do_credssp(tcp, x224, username, password):
    """Complete CredSSP handshake. Returns spnego_client for later use."""
    ssl_obj = tcp.writer.transport.get_extra_info("ssl_object")
    cert_der = ssl_obj.getpeercert(binary_form=True)

    cbt = spnego.channel_bindings.GssChannelBindings(
        application_data=b"tls-server-end-point:" + hashlib.sha256(cert_der).digest()
    )

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

    out_token = spnego_client.step(None)
    ts_req = TSRequest(version=6, nego_tokens=[out_token], client_nonce=client_nonce)
    await tcp.send(ts_req.serialize())

    resp = TSRequest.parse(await recv_tsrequest(tcp))
    out_token = spnego_client.step(resp.nego_tokens[0])

    hash_input = CLIENT_SERVER_HASH_MAGIC + client_nonce + server_pub_key
    pub_key_auth = spnego_client.wrap(hashlib.sha256(hash_input).digest()).data

    ts_req = TSRequest(version=6, nego_tokens=[out_token] if out_token else [],
                       pub_key_auth=pub_key_auth, client_nonce=client_nonce)
    await tcp.send(ts_req.serialize())

    resp = TSRequest.parse(await recv_tsrequest(tcp))
    if resp.error_code:
        raise RuntimeError(f"pubKeyAuth rejected: 0x{resp.error_code:08X}")

    password_creds = TSPasswordCreds(domain_name="", user_name=username, password=password)
    ts_credentials = TSCredentials(cred_type=1, credentials=password_creds.serialize())
    encrypted_creds = spnego_client.wrap(ts_credentials.serialize()).data
    ts_req = TSRequest(auth_info=encrypted_creds, client_nonce=client_nonce)
    await tcp.send(ts_req.serialize())

    return spnego_client


async def recv_tsrequest(tcp):
    header = await tcp.recv(1)
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
    print(f"Full Connection Sequence Debug (Phases 1-9)")
    print(f"{'='*60}")

    # Phase 1: Connect + X.224 + TLS + CredSSP
    tcp = await TcpTransport.connect(HOST, PORT, timeout=10)
    x224 = X224Layer(tcp)
    selected = await x224.negotiate(f"Cookie: mstshash={username}\r\n",
                                     NegotiationProtocol.PROTOCOL_HYBRID | NegotiationProtocol.PROTOCOL_SSL)
    print(f"✓ Phase 1: X.224 negotiated ({selected.name})")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    await tcp.upgrade_to_tls(ctx, server_hostname=None)
    print(f"✓ TLS upgraded")

    await do_credssp(tcp, x224, username, password)
    print(f"✓ CredSSP complete")

    # Phase 2: MCS Connect Initial
    client_core = ClientCoreData(
        desktop_width=1920, desktop_height=1080, color_depth=0xCA01,
        high_color_depth=32, supported_color_depths=0x000F,
        client_name=username[:15], early_capability_flags=0x0001,
        server_selected_protocol=selected.value,
    )
    client_security = ClientSecurityData(encryption_methods=0, ext_encryption_methods=0)
    network = ClientNetworkData(
        channel_names=["cliprdr", "rdpsnd", "rdpdr", "drdynvc"],
        channel_options=[0xC0000000] * 4,
    )
    gcc_data = encode_gcc_conference_create_request(client_core, client_security, network)
    connect_initial_pdu = _build_connect_initial(gcc_data)
    await x224.send_pdu(connect_initial_pdu)

    response_data = await x224.recv_pdu()
    gcc_response = _parse_connect_response(response_data)
    server_core, server_security, server_network = decode_gcc_conference_create_response(gcc_response)
    print(f"✓ Phase 2: MCS Connect (I/O channel={server_network.mcs_channel_id}, channels={server_network.channel_ids})")

    # Phase 3: Erect Domain + Attach User + Channel Joins
    await x224.send_pdu(b"\x04\x01\x00\x01\x00")  # Erect Domain
    await x224.send_pdu(b"\x28")  # Attach User Request

    confirm = await x224.recv_pdu()
    choice = (confirm[0] >> 2) & 0x3F
    initiator_present = (confirm[0] >> 1) & 0x01
    result_bit0 = confirm[0] & 0x01
    result_rest = (confirm[1] >> 4) & 0x0F
    result = (result_bit0 << 4) | result_rest
    user_channel_id = struct.unpack_from(">H", confirm, 2)[0] + MCS_USER_CHANNEL_BASE
    print(f"✓ Phase 3: Attach User (userId={user_channel_id}, result={result})")

    # Join channels
    all_channels = [user_channel_id, server_network.mcs_channel_id] + server_network.channel_ids
    for ch in all_channels:
        join_req = b"\x38" + struct.pack(">H", user_channel_id - MCS_USER_CHANNEL_BASE) + struct.pack(">H", ch)
        await x224.send_pdu(join_req)
        join_confirm = await x224.recv_pdu()
        jc_result_bit0 = join_confirm[0] & 0x01
        jc_result_rest = (join_confirm[1] >> 4) & 0x0F
        jc_result = (jc_result_bit0 << 4) | jc_result_rest
        if jc_result != 0:
            print(f"  ✗ Channel {ch} join failed: result={jc_result}")
            return
    print(f"  Joined {len(all_channels)} channels")

    # Phase 5: Client Info PDU
    io_channel = server_network.mcs_channel_id
    flags = (InfoFlags.INFO_MOUSE | InfoFlags.INFO_UNICODE | InfoFlags.INFO_LOGONNOTIFY
             | InfoFlags.INFO_LOGONERRORS | InfoFlags.INFO_DISABLECTRLALTDEL
             | InfoFlags.INFO_ENABLEWINDOWSKEY | InfoFlags.INFO_MOUSE_HAS_WHEEL)
    if password:
        flags |= InfoFlags.INFO_AUTOLOGON

    extended_info = ExtendedInfoPacket(
        client_address="0.0.0.0",
        client_dir="C:\\Windows\\System32\\mstsc.exe",
        client_timezone=TimezoneInfo(bias=0),
        performance_flags=PerformanceFlags(0),
    )
    info_pdu = ClientInfoPdu(
        flags=flags, domain="", username=username, password=password,
        extra_info=extended_info, security_flags=SEC_INFO_PKT,
    )
    info_data = info_pdu.serialize()
    print(f"\n✓ Phase 5: Client Info PDU ({len(info_data)} bytes)")
    print(f"  Flags: 0x{int(flags):08X}")
    print(f"  Security header: {info_data[:4].hex()}")

    # Send via MCS
    mcs_pdu = _build_send_data_request(user_channel_id, io_channel, info_data)
    await x224.send_pdu(mcs_pdu)
    print(f"  Sent on channel {io_channel}")

    # Phase 7: Licensing
    print(f"\n  Waiting for licensing response...")
    try:
        lic_data_raw = await asyncio.wait_for(x224.recv_pdu(), timeout=10)
        channel_id, lic_payload = _parse_send_data_indication(lic_data_raw)
        print(f"✓ Phase 7: Licensing response ({len(lic_payload)} bytes on channel {channel_id})")

        # Parse security header
        sec_flags = struct.unpack_from("<H", lic_payload, 0)[0]
        print(f"  Security flags: 0x{sec_flags:04X}")

        # Licensing preamble starts after 4-byte security header
        lic_body = lic_payload[4:]
        if len(lic_body) >= 4:
            msg_type = lic_body[0]
            lic_flags = lic_body[1]
            msg_size = struct.unpack_from("<H", lic_body, 2)[0]
            print(f"  Licensing: msgType=0x{msg_type:02X}, flags=0x{lic_flags:02X}, size={msg_size}")

            if msg_type == 0xFF:  # ERROR_ALERT
                error_code = struct.unpack_from("<I", lic_body, 4)[0]
                state_trans = struct.unpack_from("<I", lic_body, 8)[0]
                print(f"  Error code: 0x{error_code:08X} (0x07=STATUS_VALID_CLIENT)")
                print(f"  State transition: 0x{state_trans:08X}")

                if error_code == 0x07:
                    print(f"  ✓ Licensing complete (STATUS_VALID_CLIENT)")
                else:
                    print(f"  ✗ Licensing error!")
                    return
            else:
                print(f"  ✗ Unexpected licensing message type")
                return
        else:
            print(f"  ✗ Licensing body too short: {lic_body.hex()}")
            return

    except asyncio.IncompleteReadError as e:
        print(f"  ✗ Connection closed during licensing: {e.partial!r}")
        return
    except Exception as e:
        print(f"  ✗ Error: {type(e).__name__}: {e}")
        return

    # Phase 9: Wait for Demand Active PDU
    print(f"\n  Waiting for Demand Active PDU...")
    try:
        demand_raw = await asyncio.wait_for(x224.recv_pdu(), timeout=10)
        channel_id, demand_payload = _parse_send_data_indication(demand_raw)
        print(f"✓ Phase 9: Demand Active ({len(demand_payload)} bytes on channel {channel_id})")
        print(f"  First 20 bytes: {demand_payload[:20].hex()}")
    except asyncio.IncompleteReadError as e:
        print(f"  ✗ Connection closed waiting for Demand Active: {e.partial!r}")
        print(f"    This means the server rejected something in Phase 5 or 7")
    except asyncio.TimeoutError:
        print(f"  ✗ Timeout waiting for Demand Active")
    except Exception as e:
        print(f"  ✗ Error: {type(e).__name__}: {e}")

    tcp.writer.close()


if __name__ == "__main__":
    asyncio.run(main())
