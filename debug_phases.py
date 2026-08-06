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
PORT = 13389

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

        # Parse Share Control Header (6 bytes)
        total_len = struct.unpack_from("<H", demand_payload, 0)[0]
        pdu_type = struct.unpack_from("<H", demand_payload, 2)[0]
        pdu_source = struct.unpack_from("<H", demand_payload, 4)[0]
        print(f"  ShareControl: totalLen={total_len}, pduType=0x{pdu_type:04X}, source={pdu_source}")
        
        # Parse Demand Active body (after 6-byte ShareControl header)
        from arrdipi.pdu.capabilities import DemandActivePdu, ConfirmActivePdu, build_client_capabilities, ClientCapabilitiesConfig
        demand = DemandActivePdu.parse(demand_payload[6:])
        print(f"  shareId=0x{demand.share_id:08X}, caps={len(demand.capability_sets)}")
        # Dump server's capability types
        print(f"  Server cap types: {[f'0x{int(t):04X}' for t in demand.capability_sets.keys()]}")
        
        # Also dump raw cap types from the demand active to catch ones we don't parse
        raw_body = demand_payload[6:]  # after ShareControl
        d_offset = 4 + 2 + 2  # shareId + srcDescLen + combCapsLen
        src_len = struct.unpack_from('<H', raw_body, 4)[0]
        d_offset += src_len  # skip source descriptor
        raw_num_caps = struct.unpack_from('<H', raw_body, d_offset)[0]
        d_offset += 4  # numCaps + pad
        print(f"  Raw server caps ({raw_num_caps} total):")
        for ri in range(raw_num_caps):
            if d_offset + 4 > len(raw_body):
                break
            rct = struct.unpack_from('<H', raw_body, d_offset)[0]
            rcl = struct.unpack_from('<H', raw_body, d_offset+2)[0]
            print(f"    type=0x{rct:04X} len={rcl}")
            d_offset += rcl

        # Build and send Confirm Active — echo back ALL server caps
        caps_config = ClientCapabilitiesConfig(width=1920, height=1080, color_depth=32)
        client_caps = build_client_capabilities(demand.capability_sets, caps_config)
        
        # Build raw caps: echo back the server's EXACT capabilities unmodified
        # This is the simplest test to see if the structure is correct
        from arrdipi.pdu.capabilities import _serialize_capability_set, _extract_raw_capability_sets
        from arrdipi.pdu.types import CapabilitySetType
        
        # Extract raw server caps from the demand active body
        raw_body = demand_payload[6:]  # after ShareControl
        src_len = struct.unpack_from('<H', raw_body, 4)[0]
        comb_len = struct.unpack_from('<H', raw_body, 6)[0]
        d_off = 4 + 2 + 2 + src_len + 4  # shareId+srcLen+combLen+srcDesc+numCaps+pad
        raw_caps_data = raw_body[d_off:d_off + comb_len - 4]
        raw_num = struct.unpack_from('<H', raw_body, 4 + 2 + 2 + src_len)[0]
        
        # Just echo ALL server caps back verbatim
        raw_caps_combined = raw_caps_data
        num_caps = raw_num

        confirm = ConfirmActivePdu(
            share_id=demand.share_id, originator_id=0x03EA,
            source_descriptor=b"MSTSC\x00",
            raw_caps_override=bytes(raw_caps_combined),
            num_caps_override=num_caps,
        )
        confirm_data = confirm.serialize()
        
        # Wrap in ShareControl header
        sc_total = len(confirm_data) + 6
        share_control = struct.pack("<HHH", sc_total, 0x0013, user_channel_id) + confirm_data
        
        # Dump the full PDU for debugging
        print(f"  Confirm Active hex dump (first 80 bytes):")
        print(f"  SC header: {share_control[:6].hex()}")
        print(f"  Body[0:20]: {confirm_data[:20].hex()}")
        # Show each cap header
        offset = 10 + 6  # shareId(4)+orig(2)+srcLen(2)+combLen(2) + srcDesc(6)
        num_c = struct.unpack_from('<H', confirm_data, offset)[0]
        print(f"  numCaps={num_c} at offset {offset}")
        cap_off = offset + 4
        for ci in range(num_c):
            ct = struct.unpack_from('<H', confirm_data, cap_off)[0]
            cl = struct.unpack_from('<H', confirm_data, cap_off+2)[0]
            print(f"    Cap type=0x{ct:04X} len={cl} data={confirm_data[cap_off:cap_off+min(cl,16)].hex()}")
            cap_off += cl
        
        # Send via MCS
        mcs_pdu = _build_send_data_request(user_channel_id, io_channel, share_control)
        await x224.send_pdu(mcs_pdu)
        print(f"  ✓ Sent Confirm Active ({len(share_control)} bytes)")

        # Phase 10: Send finalization PDUs
        print(f"\n--- Phase 10: Connection Finalization ---")
        share_id = demand.share_id
        
        def build_data_pdu(pdu_type2: int, payload: bytes) -> bytes:
            """Wrap payload in ShareData + ShareControl headers."""
            # ShareData header (12 bytes)
            uncompressed_len = 12 + len(payload)
            share_data = struct.pack("<IBBHBBH",
                share_id, 0, 1, uncompressed_len, pdu_type2, 0, 0)
            inner = share_data + payload
            # ShareControl header (6 bytes)
            total = len(inner) + 6
            share_ctrl = struct.pack("<HHH", total, 0x0017, user_channel_id)
            return share_ctrl + inner

        # Synchronize
        sync_payload = struct.pack("<HH", 1, user_channel_id)
        sync_pdu = build_data_pdu(0x1F, sync_payload)
        mcs_pdu = _build_send_data_request(user_channel_id, io_channel, sync_pdu)
        await x224.send_pdu(mcs_pdu)
        print(f"  ✓ Sent Synchronize")

        # Control Cooperate
        ctrl_coop = struct.pack("<HHI", 4, 0, 0)  # COOPERATE=4
        ctrl_pdu = build_data_pdu(0x14, ctrl_coop)
        mcs_pdu = _build_send_data_request(user_channel_id, io_channel, ctrl_pdu)
        await x224.send_pdu(mcs_pdu)
        print(f"  ✓ Sent Control Cooperate")

        # Control Request Control
        ctrl_req = struct.pack("<HHI", 1, 0, 0)  # REQUEST_CONTROL=1
        ctrl_pdu = build_data_pdu(0x14, ctrl_req)
        mcs_pdu = _build_send_data_request(user_channel_id, io_channel, ctrl_pdu)
        await x224.send_pdu(mcs_pdu)
        print(f"  ✓ Sent Control Request")

        # Font List
        font_list = struct.pack("<HHHH", 0, 0, 3, 0x0032)
        font_pdu = build_data_pdu(0x27, font_list)
        mcs_pdu = _build_send_data_request(user_channel_id, io_channel, font_pdu)
        await x224.send_pdu(mcs_pdu)
        print(f"  ✓ Sent Font List")

        # Wait for server finalization responses
        print(f"\n  Waiting for server finalization PDUs...")
        for i in range(4):
            try:
                resp_raw = await asyncio.wait_for(x224.recv_pdu(), timeout=10)
                ch, resp_payload = _parse_send_data_indication(resp_raw)
                # Parse ShareControl
                sc_type = struct.unpack_from("<H", resp_payload, 2)[0] & 0x000F
                if sc_type == 7:  # DATA PDU
                    pdu_type2 = resp_payload[6 + 4 + 1 + 1 + 2]  # = offset 14
                    print(f"  ✓ Server PDU #{i+1}: pduType2=0x{pdu_type2:02X} ({len(resp_payload)} bytes)")
                    # If SET_ERROR_INFO (0x2F), decode the error code
                    if pdu_type2 == 0x2F:
                        # Error code is at offset 6(SC) + 12(SD) = 18
                        if len(resp_payload) >= 22:
                            error_code = struct.unpack_from("<I", resp_payload, 18)[0]
                            print(f"    Error Info code: 0x{error_code:08X}")
                            if error_code == 0:
                                print(f"    → ERRINFO_NONE (no error, session ready)")
                            else:
                                print(f"    → Server error! See MS-RDPBCGR 2.2.5.1.1")
                else:
                    print(f"  ✓ Server PDU #{i+1}: scType={sc_type} ({len(resp_payload)} bytes)")
            except asyncio.IncompleteReadError as e:
                print(f"  ✗ Connection closed at PDU #{i+1}: {e.partial!r}")
                break
            except asyncio.TimeoutError:
                print(f"  ✗ Timeout at PDU #{i+1}")
                break
            except Exception as e:
                print(f"  ✗ Error at PDU #{i+1}: {type(e).__name__}: {e}")
                break
        
        print(f"\n  *** CONNECTION SEQUENCE COMPLETE! ***")

    except asyncio.IncompleteReadError as e:
        print(f"  ✗ Connection closed waiting for Demand Active: {e.partial!r}")
    except asyncio.TimeoutError:
        print(f"  ✗ Timeout waiting for Demand Active")
    except Exception as e:
        print(f"  ✗ Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()

    tcp.writer.close()


if __name__ == "__main__":
    asyncio.run(main())
