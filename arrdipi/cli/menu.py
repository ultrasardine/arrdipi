"""Interactive terminal menu for navigating arrdipi features.

Provides a rich, navigable CLI menu that showcases all library capabilities
including protocol layers, security modes, codecs, virtual channels, and more.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
from typing import Callable

import arrdipi

# ── ANSI helpers ──────────────────────────────────────────────────────────────

BOLD = "\033[1m"
DIM = "\033[2m"
ITALIC = "\033[3m"
UNDERLINE = "\033[4m"
RESET = "\033[0m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
MAGENTA = "\033[35m"
BLUE = "\033[34m"
WHITE = "\033[97m"


def _clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def _term_width() -> int:
    return shutil.get_terminal_size((80, 24)).columns


def _center(text: str, width: int | None = None) -> str:
    w = width or _term_width()
    return text.center(w)


def _hr(char: str = "─", width: int | None = None) -> str:
    w = width or _term_width()
    return DIM + char * w + RESET


def _header(title: str) -> str:
    w = _term_width()
    lines = [
        "",
        _hr("━"),
        _center(f"{BOLD}{CYAN}{title}{RESET}"),
        _hr("━"),
        "",
    ]
    return "\n".join(lines)


def _menu_item(key: str, label: str) -> str:
    return f"  {CYAN}{BOLD}[{key}]{RESET}  {label}"


def _section(title: str) -> str:
    return f"\n  {YELLOW}{BOLD}{title}{RESET}\n"


def _info_row(label: str, value: str) -> str:
    return f"  {DIM}{label:<28}{RESET}{value}"


def _prompt(text: str = "Select an option") -> str:
    return input(f"\n  {GREEN}▸ {text}: {RESET}")


def _pause() -> None:
    input(f"\n  {DIM}Press Enter to go back...{RESET}")


# ── Screens ───────────────────────────────────────────────────────────────────


def _screen_main_menu() -> str | None:
    """Main menu — top-level navigation."""
    _clear()
    print(_header("arrdipi — Pure Python RDP Client"))
    print(f"  {DIM}Version {arrdipi.__version__} • Python {platform.python_version()} • {platform.system()}{RESET}")
    print()

    print(_section("Explore"))
    print(_menu_item("1", "Protocol Stack Overview"))
    print(_menu_item("2", "Security Modes"))
    print(_menu_item("3", "Graphics & Codecs"))
    print(_menu_item("4", "Virtual Channels"))
    print(_menu_item("5", "Input Handling"))
    print()
    print(_section("Tools"))
    print(_menu_item("6", "Connection Config Builder"))
    print(_menu_item("7", "Run Test Suite"))
    print(_menu_item("8", "Package Info & Dependencies"))
    print()
    print(_section("Actions"))
    print(_menu_item("c", "Connect to RDP Server (CLI)"))
    print(_menu_item("q", "Quit"))

    choice = _prompt()
    return choice.strip().lower()


def _screen_protocol_stack() -> None:
    """Protocol stack overview."""
    _clear()
    print(_header("Protocol Stack"))

    print(_section("Data Flow Pipeline"))
    print(f"  {BOLD}Inbound:{RESET}  TCP → X.224/TPKT → Security → MCS demux → Decompress → PDU parse → Handler")
    print(f"  {BOLD}Outbound:{RESET} Handler → PDU serialize → Compress → MCS mux → Security → X.224/TPKT → TCP")

    print(_section("Layer Details"))

    layers = [
        ("TCP Transport", "asyncio TCP stream reader/writer with TLS upgrade", "arrdipi.transport.tcp"),
        ("X.224 / TPKT", "Connection negotiation, TPKT framing (ITU-T X.224)", "arrdipi.transport.x224"),
        ("Security", "Standard RDP / TLS / NLA+CredSSP", "arrdipi.security.*"),
        ("MCS (T.125)", "Channel multiplexing, domain management", "arrdipi.mcs.layer"),
        ("GCC Conference", "Client/server data block encoding", "arrdipi.mcs.gcc"),
        ("PDU Framework", "Dataclass-based parse/serialize with round-trip correctness", "arrdipi.pdu.*"),
        ("Bulk Compression", "MPPC 64KB sliding window (RFC 2118)", "arrdipi.codec.mppc"),
        ("Session", "Dispatch loop, input methods, event callbacks", "arrdipi.session"),
    ]

    for name, desc, module in layers:
        print(f"  {CYAN}{BOLD}{name:<22}{RESET}{desc}")
        print(f"  {DIM}{'':22}{module}{RESET}")
        print()

    print(_section("Connection Sequence (10 Phases)"))
    phases = [
        ("Phase 1", "Connection Initiation", "TCP + X.224 negotiation"),
        ("Phase 2", "Basic Settings Exchange", "MCS Connect Initial/Response with GCC"),
        ("Phase 3", "Channel Connection", "Erect Domain, Attach User, Channel Joins"),
        ("Phase 4", "Security Commencement", "RSA key exchange (Standard RDP only)"),
        ("Phase 5", "Secure Settings Exchange", "Client Info PDU (credentials, timezone)"),
        ("Phase 6", "Auto-Detection", "Optional — skipped"),
        ("Phase 7", "Licensing", "MS-RDPELE license exchange"),
        ("Phase 8", "Multitransport", "Optional — skipped"),
        ("Phase 9", "Capabilities Exchange", "Demand Active / Confirm Active"),
        ("Phase 10", "Finalization", "Synchronize, Control, Font List/Map"),
    ]
    for num, name, desc in phases:
        print(f"  {MAGENTA}{num:<10}{RESET}{BOLD}{name:<28}{RESET}{DIM}{desc}{RESET}")

    _pause()


def _screen_security() -> None:
    """Security modes detail."""
    _clear()
    print(_header("Security Modes"))

    modes = [
        (
            "Standard RDP Security",
            "arrdipi.security.standard",
            [
                "RSA key exchange with server public key",
                "RC4 stream cipher encryption (per-direction keys)",
                "Key derivation: SaltedHash per [MS-RDPBCGR] 5.3.5",
                "Proprietary certificate signature validation",
                "RC4 key refresh every 4096 packets",
                "HMAC-MD5 MAC for integrity",
            ],
        ),
        (
            "TLS (Enhanced Security)",
            "arrdipi.security.enhanced",
            [
                "TLS 1.0–1.3 via ssl.create_default_context()",
                "Configurable certificate verification",
                "Transport-level encryption (encrypt/decrypt are identity)",
                "Security header with flags only (no payload encryption)",
            ],
        ),
        (
            "NLA / CredSSP",
            "arrdipi.security.nla",
            [
                "TLS upgrade + CredSSP handshake per [MS-CSSP]",
                "SPNEGO/NTLM/Kerberos via pyspnego",
                "TSRequest message exchange (3-round)",
                "TSCredentials delegation after handshake",
                "NTLM (default) or Kerberos (negotiate)",
            ],
        ),
        (
            "Licensing Exchange",
            "arrdipi.security.licensing",
            [
                "MS-RDPELE license request/response",
                "Platform challenge computation",
                "STATUS_VALID_CLIENT fast path (common)",
                "Full multi-round exchange support",
            ],
        ),
    ]

    for name, module, features in modes:
        print(f"  {CYAN}{BOLD}{name}{RESET}")
        print(f"  {DIM}{module}{RESET}")
        for feat in features:
            print(f"    {GREEN}•{RESET} {feat}")
        print()

    _pause()


def _screen_graphics() -> None:
    """Graphics and codecs."""
    _clear()
    print(_header("Graphics & Codecs"))

    print(_section("Framebuffer"))
    print(_info_row("Surface", "RGBA bytearray-backed framebuffer"))
    print(_info_row("Dirty rect tracking", "Automatic, with asyncio.Lock"))
    print(_info_row("Module", "arrdipi.graphics.surface"))
    print()

    print(_section("Bitmap Codecs"))
    codecs = [
        ("RLE", "Run-Length Encoding", "8/16/24/32-bit color depths, interleaved decompression", "arrdipi.codec.rle"),
        ("RemoteFX", "Wavelet-based codec", "RLGR1/RLGR3 entropy, inverse DWT, YCbCr→RGB", "arrdipi.codec.remotefx"),
        ("NSCodec", "Near-lossless codec", "Lossy and lossless modes, RGB output", "arrdipi.codec.nscodec"),
        ("H.264", "AVC via PyAV/FFmpeg", "NAL unit decoding, AVC420/AVC444 profiles", "arrdipi.codec.h264"),
        ("MPPC", "Bulk compression", "64KB sliding window, RFC 2118 based", "arrdipi.codec.mppc"),
    ]
    for name, desc, detail, module in codecs:
        print(f"  {CYAN}{BOLD}{name:<12}{RESET}{desc}")
        print(f"  {DIM}{'':12}{detail}{RESET}")
        print(f"  {DIM}{'':12}{module}{RESET}")
        print()

    print(_section("Rendering Engines"))
    engines = [
        ("GDI Orders", "Primary/secondary/alternate drawing orders, delta encoding, bitmap+glyph cache", "arrdipi.graphics.gdi"),
        ("GFX Pipeline", "RDPGFX dynamic channel, surface/cache management, frame acknowledge", "arrdipi.graphics.gfx"),
        ("Pointer", "Color/new/cached/large pointer support, cursor cache", "arrdipi.graphics.pointer"),
    ]
    for name, desc, module in engines:
        print(f"  {CYAN}{BOLD}{name:<16}{RESET}{desc}")
        print(f"  {DIM}{'':16}{module}{RESET}")
        print()

    _pause()


def _screen_channels() -> None:
    """Virtual channels."""
    _clear()
    print(_header("Virtual Channels"))

    print(_section("Channel Infrastructure"))
    print(_info_row("Static VC", "Chunking/reassembly with FIRST/LAST flags"))
    print(_info_row("Dynamic VC (DRDYNVC)", "Runtime channel creation over static VC"))
    print(_info_row("Max chunk size", "Configurable, per-channel"))
    print()

    print(_section("Implemented Channels"))
    channels = [
        ("cliprdr", "Clipboard", "Static", [
            "CF_UNICODETEXT format support",
            "Bidirectional text sharing",
            "Monitor Ready handshake",
            "Format list negotiation",
        ]),
        ("rdpsnd", "Audio Output", "Static", [
            "PCM audio format negotiation",
            "Wave/Wave2 PDU decoding",
            "sounddevice.OutputStream playback",
            "Wave Confirm acknowledgment",
        ]),
        ("AUDIO_INPUT", "Audio Input", "Dynamic", [
            "sounddevice.InputStream capture",
            "PCM sample streaming",
            "Open/Close lifecycle",
        ]),
        ("rdpdr", "Drive Redirection", "Static", [
            "File system I/O (Create, Read, Write, Close)",
            "Directory queries",
            "Read-only enforcement",
            "NTSTATUS error codes",
        ]),
        ("Microsoft::Windows::RDS::Graphics", "GFX Pipeline", "Dynamic", [
            "H.264 Wire-to-Surface",
            "Surface create/delete/map",
            "Bitmap cache management",
            "Frame acknowledge with queue depth",
        ]),
    ]

    for vc_name, display_name, vc_type, features in channels:
        type_color = MAGENTA if vc_type == "Dynamic" else BLUE
        print(f"  {CYAN}{BOLD}{display_name:<20}{RESET}{type_color}[{vc_type}]{RESET}  {DIM}{vc_name}{RESET}")
        for feat in features:
            print(f"    {GREEN}•{RESET} {feat}")
        print()

    _pause()


def _screen_input() -> None:
    """Input handling."""
    _clear()
    print(_header("Input Handling"))

    print(_section("Input Methods (Session API)"))
    methods = [
        ("send_key(scan_code, is_released, is_extended)", "Keyboard scancode event"),
        ("send_unicode_key(code_point, is_released)", "Unicode character event"),
        ("send_mouse_move(x, y)", "Absolute mouse position"),
        ("send_mouse_button(x, y, button, is_released)", "Mouse button press/release"),
        ("send_mouse_scroll(x, y, delta, is_horizontal)", "Mouse wheel scroll"),
    ]
    for sig, desc in methods:
        print(f"  {CYAN}{sig}{RESET}")
        print(f"  {DIM}  {desc}{RESET}")
        print()

    print(_section("Encoding Modes"))
    print(_info_row("Fast-Path", "Preferred when server supports it (lower overhead)"))
    print(_info_row("Slow-Path", "Fallback with full ShareData headers"))
    print(_info_row("Detection", "GeneralCapabilitySet.extra_flags & FASTPATH_OUTPUT_SUPPORTED"))
    print()

    print(_section("Fast-Path Event Types"))
    print(f"  {GREEN}•{RESET} FastPathKeyboardEvent  — scancode + release/extended flags")
    print(f"  {GREEN}•{RESET} FastPathMouseEvent     — pointer flags + coordinates")
    print(f"  {GREEN}•{RESET} FastPathUnicodeEvent   — Unicode code point + release flag")
    print()

    print(_section("Slow-Path Event Types"))
    print(f"  {GREEN}•{RESET} KeyboardEvent          — scancode with KBDFLAGS_DOWN/RELEASE/EXTENDED")
    print(f"  {GREEN}•{RESET} UnicodeKeyboardEvent   — Unicode code point")
    print(f"  {GREEN}•{RESET} MouseEvent             — pointer flags + coordinates")
    print(f"  {GREEN}•{RESET} ExtendedMouseEvent     — extended button support")

    _pause()


def _screen_config_builder() -> None:
    """Interactive connection config builder."""
    _clear()
    print(_header("Connection Config Builder"))
    print(f"  {DIM}Build a SessionConfig interactively. The generated Python code{RESET}")
    print(f"  {DIM}can be copied into your script.{RESET}")
    print()

    def _ask(prompt_text: str, default: str = "") -> str:
        suffix = f" [{default}]" if default else ""
        val = input(f"  {GREEN}▸{RESET} {prompt_text}{suffix}: ").strip()
        return val or default

    host = _ask("Host", "")
    if not host:
        print(f"\n  {RED}Host is required.{RESET}")
        _pause()
        return

    port = _ask("Port", "3389")
    username = _ask("Username", "")
    domain = _ask("Domain", "")
    security = _ask("Security (auto/rdp/tls/nla)", "auto")
    width = _ask("Width", "1920")
    height = _ask("Height", "1080")
    verify_cert = _ask("Verify TLS certificate (yes/no)", "yes")
    timeout = _ask("Connect timeout (seconds)", "5.0")

    # Build the code snippet
    verify_str = "True" if verify_cert.lower() in ("yes", "y", "true", "1") else "False"

    print()
    print(_hr())
    print(_section("Generated Python Code"))
    print(f"  {DIM}# Copy this into your async script{RESET}")
    print()
    code = f"""\
  {CYAN}import asyncio{RESET}
  {CYAN}import arrdipi{RESET}

  {CYAN}async def{RESET} {BOLD}main{RESET}():
      session = {CYAN}await{RESET} arrdipi.connect(
          host={GREEN}"{host}"{RESET},
          port={MAGENTA}{port}{RESET},
          username={GREEN}"{username}"{RESET},
          password={GREEN}"<your-password>"{RESET},
          domain={GREEN}"{domain}"{RESET},
          security={GREEN}"{security}"{RESET},
          width={MAGENTA}{width}{RESET},
          height={MAGENTA}{height}{RESET},
          verify_cert={MAGENTA}{verify_str}{RESET},
          connect_timeout={MAGENTA}{timeout}{RESET},
      )
      {DIM}# Use session.send_key(), session.surface, etc.{RESET}
      {CYAN}await{RESET} session.disconnect()

  asyncio.run(main())"""
    print(code)
    print()
    print(_hr())

    print(_section("Equivalent CLI Command"))
    cmd_parts = ["arrdipi connect"]
    cmd_parts.append(f"--host {host}")
    cmd_parts.append(f"--port {port}")
    if username:
        cmd_parts.append(f"--user {username}")
    if domain:
        cmd_parts.append(f"--domain {domain}")
    cmd_parts.append(f"--security {security}")
    cmd_parts.append(f"--width {width}")
    cmd_parts.append(f"--height {height}")

    print(f"  {CYAN}{' '.join(cmd_parts)}{RESET}")
    print(f"  {DIM}(set ARRDIPI_PASSWORD env var for the password){RESET}")

    _pause()


def _screen_run_tests() -> None:
    """Run the test suite."""
    _clear()
    print(_header("Test Suite"))
    print(f"  {DIM}Running: uv run pytest -v{RESET}")
    print(_hr())
    print()

    exit_code = os.system("uv run pytest -v")

    print()
    print(_hr())
    if exit_code == 0:
        print(f"  {GREEN}{BOLD}All tests passed ✓{RESET}")
    else:
        print(f"  {RED}{BOLD}Some tests failed ✗{RESET}")

    _pause()


def _screen_package_info() -> None:
    """Package info and dependencies."""
    _clear()
    print(_header("Package Info & Dependencies"))

    print(_section("Package"))
    print(_info_row("Name", "arrdipi"))
    print(_info_row("Version", arrdipi.__version__))
    print(_info_row("Python", platform.python_version()))
    print(_info_row("Platform", f"{platform.system()} {platform.machine()}"))
    print(_info_row("License", "Proprietary"))
    print(_info_row("Entry point", "arrdipi.cli.main:main"))
    print()

    print(_section("Runtime Dependencies"))
    deps = [
        ("cryptography", "TLS, RSA, RC4, HMAC — low-level crypto"),
        ("pyspnego", "NLA/CredSSP SPNEGO/NTLM/Kerberos tokens"),
        ("av (PyAV)", "H.264 frame decoding via FFmpeg"),
        ("pygame", "CLI graphical window for desktop display"),
        ("sounddevice", "Cross-platform audio I/O"),
    ]
    for name, purpose in deps:
        print(f"  {CYAN}{name:<20}{RESET}{purpose}")

    print()
    print(_section("Dev Dependencies"))
    dev_deps = [
        ("pytest", "Test framework"),
        ("pytest-asyncio", "Async test support"),
    ]
    for name, purpose in dev_deps:
        print(f"  {CYAN}{name:<20}{RESET}{purpose}")

    print()
    print(_section("Protocol References"))
    refs = [
        "[MS-RDPBCGR]  Core protocol, connection sequence, PDUs",
        "[MS-RDPELE]   Licensing extension",
        "[MS-RDPECLIP]  Clipboard virtual channel",
        "[MS-RDPEA]    Audio output virtual channel",
        "[MS-RDPEAI]   Audio input virtual channel",
        "[MS-RDPEDYC]  Dynamic virtual channels",
        "[MS-RDPEFS]   File system redirection",
        "[MS-RDPEGFX]  Graphics pipeline (H.264)",
        "[MS-RDPRFX]   RemoteFX codec",
        "[MS-RDPNSC]   NSCodec",
        "[MS-RDPEGDI]  GDI drawing orders",
        "[MS-CSSP]     CredSSP / NLA",
        "ITU-T X.224   Transport layer",
        "ITU-T T.125   MCS protocol",
    ]
    for ref in refs:
        print(f"  {DIM}{ref}{RESET}")

    print()
    print(_section("Error Hierarchy"))
    errors = [
        ("ArrdipiError", "Base exception"),
        ("  ConnectionTimeoutError", "TCP connect timeout"),
        ("  NegotiationFailureError", "X.224 negotiation failure"),
        ("  ConnectionPhaseError", "Connection sequence phase failure"),
        ("  ChannelJoinError", "MCS channel join denied"),
        ("  AuthenticationError", "NLA/CredSSP auth failure"),
        ("  NegotiationError", "SPNEGO/Kerberos failure"),
        ("  PduParseError", "Malformed PDU data"),
        ("  DecompressionError", "MPPC decompression failure"),
        ("  RleDecodeError", "RLE bitmap decode failure"),
        ("  FinalizationTimeoutError", "Finalization PDU timeout"),
    ]
    for name, desc in errors:
        print(f"  {RED}{name:<32}{RESET}{DIM}{desc}{RESET}")

    _pause()


def _screen_connect_cli() -> None:
    """Launch the connect CLI."""
    _clear()
    print(_header("Connect to RDP Server"))
    print(f"  {DIM}This will launch the arrdipi connect command.{RESET}")
    print(f"  {DIM}You can also run it directly: arrdipi connect --host <host> --user <user>{RESET}")
    print()

    host = input(f"  {GREEN}▸{RESET} Host: ").strip()
    if not host:
        print(f"\n  {RED}Host is required.{RESET}")
        _pause()
        return

    user = input(f"  {GREEN}▸{RESET} Username: ").strip()
    if not user:
        print(f"\n  {RED}Username is required.{RESET}")
        _pause()
        return

    port = input(f"  {GREEN}▸{RESET} Port [3389]: ").strip() or "3389"
    security = input(f"  {GREEN}▸{RESET} Security (auto/rdp/tls/nla) [auto]: ").strip() or "auto"

    # Password — don't echo
    import getpass
    password = getpass.getpass(f"  {GREEN}▸{RESET} Password: ")

    print()
    print(f"  {DIM}Connecting to {host}:{port} as {user} ({security})...{RESET}")
    print(_hr())
    print()

    cmd = f'uv run arrdipi connect --host {host} --port {port} --user {user} --security {security}'
    os.environ["ARRDIPI_PASSWORD"] = password
    try:
        os.system(cmd)
    finally:
        # Clean up password from env
        os.environ.pop("ARRDIPI_PASSWORD", None)

    _pause()


# ── Menu loop ─────────────────────────────────────────────────────────────────

_SCREENS: dict[str, Callable[[], None]] = {
    "1": _screen_protocol_stack,
    "2": _screen_security,
    "3": _screen_graphics,
    "4": _screen_channels,
    "5": _screen_input,
    "6": _screen_config_builder,
    "7": _screen_run_tests,
    "8": _screen_package_info,
    "c": _screen_connect_cli,
}


def run_menu() -> None:
    """Run the interactive terminal menu loop."""
    while True:
        try:
            choice = _screen_main_menu()

            if choice in ("q", "quit", "exit"):
                _clear()
                print(f"\n  {DIM}Goodbye.{RESET}\n")
                break

            handler = _SCREENS.get(choice or "")
            if handler:
                handler()
            elif choice:
                print(f"\n  {RED}Unknown option: {choice}{RESET}")
                _pause()

        except KeyboardInterrupt:
            _clear()
            print(f"\n  {DIM}Goodbye.{RESET}\n")
            break
        except EOFError:
            break
