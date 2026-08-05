#!/usr/bin/env python3
"""Debug NLA/CredSSP handshake - the step AFTER TLS."""

import asyncio
import ssl
import sys

sys.path.insert(0, "/Users/simoesa/Projects/personal/arrdipi")

from arrdipi.transport.tcp import TcpTransport
from arrdipi.transport.x224 import X224Layer
from arrdipi.pdu.types import NegotiationProtocol
from arrdipi.security.nla import NlaSecurityLayer

HOST = "localhost"
PORT = 13389  # Adjust to match your SSM port forward

# Test credentials (can be fake for now - we just want to see where it fails)
USERNAME = "Administrator"
PASSWORD = input("Enter RDP password: ")
DOMAIN = ""


async def test_full_nla():
    """Test the full NLA sequence including CredSSP."""
    print("="*60)
    print("TEST: Full NLA/CredSSP sequence")
    print("="*60)
    
    try:
        # Step 1: Connect
        print(f"\n1. Connecting to {HOST}:{PORT}...")
        tcp = await TcpTransport.connect(HOST, PORT, timeout=10)
        print("   ✓ TcpTransport connected")
        
        # Step 2: X.224 negotiation
        print("\n2. X.224 negotiation...")
        x224 = X224Layer(tcp)
        cookie = f"Cookie: mstshash={USERNAME}\r\n"
        requested = NegotiationProtocol.PROTOCOL_HYBRID | NegotiationProtocol.PROTOCOL_SSL
        
        selected = await x224.negotiate(cookie, requested)
        print(f"   ✓ Selected protocol: {selected.name}")
        
        # Step 3: Create NLA layer and call establish()
        print("\n3. NLA establish (TLS + CredSSP)...")
        nla = NlaSecurityLayer(
            username=USERNAME,
            password=PASSWORD,
            domain=DOMAIN,
            verify_cert=False,
            server_hostname=HOST,
            protocol="ntlm",
        )
        
        try:
            await nla.establish(x224, tcp)
            print("   ✓ NLA establish SUCCEEDED!")
        except Exception as e:
            print(f"   ✗ NLA establish FAILED: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
        
        await tcp.close()
        
    except Exception as e:
        import traceback
        print(f"\n✗ Error: {type(e).__name__}: {e}")
        traceback.print_exc()


async def test_tls_then_manual_credssp():
    """Test TLS upgrade then manually try to send CredSSP."""
    print("\n" + "="*60)
    print("TEST: TLS upgrade then inspect CredSSP step")
    print("="*60)
    
    try:
        # Step 1: Connect
        print(f"\n1. Connecting to {HOST}:{PORT}...")
        tcp = await TcpTransport.connect(HOST, PORT, timeout=10)
        print("   ✓ Connected")
        
        # Step 2: X.224 negotiation
        print("\n2. X.224 negotiation...")
        x224 = X224Layer(tcp)
        cookie = f"Cookie: mstshash={USERNAME}\r\n"
        requested = NegotiationProtocol.PROTOCOL_HYBRID | NegotiationProtocol.PROTOCOL_SSL
        
        selected = await x224.negotiate(cookie, requested)
        print(f"   ✓ Selected: {selected.name}")
        
        # Step 3: TLS upgrade manually
        print("\n3. TLS upgrade...")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        await tcp.upgrade_to_tls(ctx, server_hostname=None)
        print("   ✓ TLS upgrade succeeded")
        
        ssl_obj = tcp.writer.transport.get_extra_info("ssl_object")
        if ssl_obj:
            print(f"   Version: {ssl_obj.version()}")
        
        # Step 4: Try to read - server might send something first
        print("\n4. Checking if server sends data first...")
        try:
            data = await asyncio.wait_for(tcp.reader.read(1024), timeout=2)
            if data:
                print(f"   ← Server sent {len(data)} bytes: {data[:50].hex()}...")
            else:
                print("   Server sent nothing (EOF)")
        except asyncio.TimeoutError:
            print("   Server waiting for client (no data yet)")
        
        # Step 5: Try creating SPNEGO context
        print("\n5. Creating SPNEGO context...")
        import spnego
        try:
            spnego_client = spnego.client(
                username=USERNAME,
                password=PASSWORD,
                hostname=HOST,
                service="TERMSRV",
                protocol="ntlm",
            )
            print("   ✓ SPNEGO context created")
            
            # Generate initial token
            out_token = spnego_client.step(None)
            print(f"   ✓ Initial NTLM token: {len(out_token)} bytes")
            print(f"   Token preview: {out_token[:20].hex()}...")
            
        except Exception as e:
            print(f"   ✗ SPNEGO failed: {e}")
        
        await tcp.close()
        
    except Exception as e:
        import traceback
        print(f"\n✗ Error: {type(e).__name__}: {e}")
        traceback.print_exc()


async def main():
    print("NLA/CredSSP Debug")
    print(f"Target: {HOST}:{PORT}")
    print(f"User: {USERNAME}\n")
    
    await test_full_nla()
    
    await asyncio.sleep(1)
    
    await test_tls_then_manual_credssp()


if __name__ == "__main__":
    asyncio.run(main())
