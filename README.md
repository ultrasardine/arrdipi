# arrdipi

[![CI](https://github.com/arrdipi/arrdipi/actions/workflows/ci.yml/badge.svg)](https://github.com/arrdipi/arrdipi/actions/workflows/ci.yml)
[![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code style: PEP 8](https://img.shields.io/badge/code%20style-PEP%208-orange.svg)](https://peps.python.org/pep-0008/)

A pure Python RDP (Remote Desktop Protocol) client library. Implements the full RDP protocol stack from scratch — no FreeRDP or other C libraries required.

arrdipi provides both a **programmatic async Python API** for building custom RDP clients, automation, and scripting, and a **CLI** that opens a graphical window to display the remote desktop.

## Features

### Security Modes

- **Standard RDP Security** — RSA key exchange + RC4 encryption per [MS-RDPBCGR] §5.3
- **TLS** — Enhanced security with TLS 1.0–1.3, configurable certificate verification
- **NLA/CredSSP** — Network Level Authentication via NTLM or Kerberos (using `pyspnego`)

### Graphics Codecs

- **RLE** — Run-length encoded bitmaps at 8/16/24/32-bit color depths
- **RemoteFX** — Wavelet-based codec with RLGR1/RLGR3 entropy coding
- **NSCodec** — Lossless and near-lossless bitmap compression
- **H.264/AVC** — Hardware-accelerated decoding via the GFX pipeline (PyAV/FFmpeg)
- **GDI Orders** — Server-side drawing primitives (DstBlt, PatBlt, ScrBlt, MemBlt, OpaqueRect, LineTo, GlyphIndex, etc.)

### Virtual Channels

- **Clipboard** (cliprdr) — Bidirectional clipboard text sharing
- **Audio Output** (rdpsnd) — Server-to-client audio playback via sounddevice
- **Audio Input** (AUDIN) — Client-to-server microphone capture
- **Drive Redirection** (rdpdr) — Share local directories with the remote session
- **Dynamic Channels** (drdynvc) — Runtime channel creation for GFX pipeline and extensions

### Additional

- Full 10-phase RDP connection sequence per [MS-RDPBCGR] §1.3.1.1
- Fast-path input/output for low-latency interaction
- Auto-reconnect with server-issued cookies
- Pointer/cursor caching and rendering (up to 384×384)
- MPPC bulk data compression (64KB sliding window)
- asyncio-native — all I/O is non-blocking
- Cross-platform: Windows, macOS, Linux
- Python 3.13+

## Installation

```bash
# Using uv (recommended)
uv add git+https://github.com/ultrasardine/arrdipi.git

# Using pip
pip install git+https://github.com/ultrasardine/arrdipi.git
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `cryptography` | TLS, RSA, RC4, HMAC primitives |
| `pyspnego` | NLA/CredSSP SPNEGO/NTLM/Kerberos |
| `av` (PyAV) | H.264 frame decoding via FFmpeg |
| `pygame` | CLI graphical desktop window |
| `sounddevice` | Audio playback and capture |

## Quick Start

### Interactive Menu

The fastest way to explore arrdipi is the built-in interactive terminal menu:

```bash
# Launch the menu (any of these work)
make menu
uv run arrdipi menu
uv run arrdipi          # menu is the default when no subcommand is given
uv run python main.py
```

The menu lets you browse the protocol stack, security modes, graphics codecs, virtual channels, input handling, and more. It also includes a connection config builder that generates ready-to-use Python code and CLI commands.

### Python API

The primary entry point is the async `connect()` function:

```python
import asyncio
import arrdipi


async def main():
    session = await arrdipi.connect(
        host="192.168.1.100",
        port=3389,
        username="admin",
        password="secret",
        domain="WORKGROUP",
        security="nla",       # "auto", "rdp", "tls", or "nla"
        width=1920,
        height=1080,
    )

    try:
        # Start the background dispatch loop
        await session.start()

        # Access the remote desktop framebuffer
        surface = session.surface
        dirty_rects = surface.get_dirty_rects()

        # Send input events
        await session.send_key(scan_code=0x1E, is_released=False)   # 'A' key down
        await session.send_key(scan_code=0x1E, is_released=True)    # 'A' key up
        await session.send_mouse_move(x=500, y=300)
        await session.send_mouse_button(x=500, y=300, button=1, is_released=False)

        # Register event callbacks
        session.on_graphics_update(my_graphics_handler)
        session.on_disconnect(my_disconnect_handler)
    finally:
        await session.disconnect()


asyncio.run(main())
```

### CLI

```bash
# Basic connection
arrdipi connect --host 192.168.1.100 --user admin --password secret

# NLA with custom resolution
arrdipi connect --host server.local --user admin --security nla --width 2560 --height 1440

# Password from environment variable
export ARRDIPI_PASSWORD="my-secret-password"
arrdipi connect --host 10.0.0.5 --user admin

# Drive redirection (read-write and read-only)
arrdipi connect --host server --user admin \
    --drive "shared:/home/user/files" \
    --drive "docs:/tmp/docs:ro"
```

## Python API Reference

### `arrdipi.connect()`

Creates a connection to an RDP server and returns a `Session`.

```python
session = await arrdipi.connect(
    host="10.0.0.1",
    port=3389,                    # default: 3389
    username="user",
    password="pass",
    domain="",                    # default: ""
    security="auto",              # "auto", "rdp", "tls", "nla"
    width=1920,                   # default: 1920
    height=1080,                  # default: 1080
    verify_cert=True,             # default: True
    connect_timeout=5.0,          # default: 5.0 seconds
    channel_names=["cliprdr", "rdpsnd", "rdpdr", "drdynvc"],  # default
    drive_paths=[DrivePath(name="share", path="/local/path")], # default: []
)
```

### `Session`

The `Session` object represents an active RDP connection.

**Lifecycle:**

| Method | Description |
|--------|-------------|
| `await session.start()` | Initialize channels and start the background dispatch loop |
| `await session.disconnect()` | Send Shutdown Request and close cleanly |
| `await session.close()` | Idempotent close — cancel dispatch, close TCP |

**Input methods** (prefer fast-path when server supports it):

| Method | Description |
|--------|-------------|
| `await session.send_key(scan_code, is_released, is_extended=False)` | Keyboard scancode event |
| `await session.send_unicode_key(code_point, is_released=False)` | Unicode character event |
| `await session.send_mouse_move(x, y)` | Absolute mouse position |
| `await session.send_mouse_button(x, y, button, is_released)` | Mouse button press/release |
| `await session.send_mouse_scroll(x, y, delta, is_horizontal=False)` | Mouse wheel scroll |

**Properties:**

| Property | Type | Description |
|----------|------|-------------|
| `session.surface` | `GraphicsSurface` | RGBA framebuffer of the remote desktop |
| `session.pointer` | `PointerHandler` | Cursor cache and position |
| `session.clipboard` | `ClipboardChannel` | Clipboard sharing channel |
| `session.audio_output` | `AudioOutputChannel` | Audio playback channel |
| `session.audio_input` | `AudioInputChannel` | Audio capture channel |
| `session.drive` | `DriveChannel` | Drive redirection channel |
| `session.closed` | `bool` | Whether the session has been closed |

**Event callbacks:**

```python
# Graphics update — receives list of dirty Rect(x, y, w, h)
session.on_graphics_update(async_callback)

# Clipboard changed — receives clipboard data
session.on_clipboard_changed(async_callback)

# Disconnect — receives optional reason string
session.on_disconnect(async_callback)
```

### `GraphicsSurface`

The in-memory RGBA framebuffer representing the remote desktop display.

```python
surface = session.surface

# Read pixel data from a region
pixels = surface.read_pixels(x=0, y=0, w=100, h=100)

# Write pixel data to a region
surface.write_pixels(x=0, y=0, w=100, h=100, pixels=rgba_bytes)

# Get and clear dirty rectangles
dirty_rects = surface.get_dirty_rects()  # list[Rect]

# Direct buffer access (read-only memoryview)
buffer = surface.get_buffer()
```

### `DrivePath`

Configuration for drive redirection:

```python
from arrdipi import DrivePath

drives = [
    DrivePath(name="shared", path="/home/user/shared", read_only=False),
    DrivePath(name="docs", path="/home/user/docs", read_only=True),
]
```

### Error Types

All exceptions inherit from `ArrdipiError`:

| Exception | When |
|-----------|------|
| `ConnectionTimeoutError` | TCP connection exceeds timeout |
| `NegotiationFailureError` | X.224 negotiation rejected by server |
| `ConnectionPhaseError` | Any connection sequence phase fails (includes phase number and name) |
| `ChannelJoinError` | MCS channel join denied |
| `AuthenticationError` | NLA/CredSSP credentials rejected |
| `NegotiationError` | SPNEGO/Kerberos negotiation failure |
| `PduParseError` | Malformed PDU data (includes PDU type, byte offset, description) |
| `DecompressionError` | MPPC bulk decompression failure |
| `RleDecodeError` | RLE bitmap decode failure (includes rectangle index and byte offset) |
| `FinalizationTimeoutError` | Server finalization PDUs not received within timeout |

```python
import arrdipi

try:
    session = await arrdipi.connect(host="10.0.0.1", username="admin", password="wrong")
except arrdipi.AuthenticationError as e:
    print(f"Auth failed (code 0x{e.error_code:08X}): {e}")
except arrdipi.ConnectionPhaseError as e:
    print(f"Failed at phase {e.phase_number} ({e.phase_name}): {e.cause}")
except arrdipi.ConnectionTimeoutError as e:
    print(f"Timeout connecting to {e.host}:{e.port} after {e.timeout}s")
except arrdipi.ArrdipiError as e:
    print(f"RDP error: {e}")
```

## CLI Reference

### Subcommands

| Command | Description |
|---------|-------------|
| `arrdipi` | Launch the interactive terminal menu (default) |
| `arrdipi menu` | Launch the interactive terminal menu |
| `arrdipi connect` | Connect to an RDP server with a graphical window |

### Connect Options

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | *(required)* | RDP server hostname or IP |
| `--user` | *(required)* | Username for authentication |
| `--password` | `ARRDIPI_PASSWORD` env | Password (flag takes precedence over env var) |
| `--port` | `3389` | RDP server port |
| `--domain` | `""` | Windows domain |
| `--security` | `auto` | Security mode: `auto`, `rdp`, `tls`, `nla` |
| `--width` | `1920` | Desktop width in pixels |
| `--height` | `1080` | Desktop height in pixels |
| `--drive` | — | Drive redirection: `NAME:PATH` or `NAME:PATH:ro` (repeatable) |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `ARRDIPI_PASSWORD` | Default password when `--password` is not provided. The `--password` flag always takes precedence. |

## Architecture

### Data Flow Pipeline

arrdipi implements the RDP protocol as a layered pipeline. Each layer has a well-defined interface and communicates only with its immediate neighbors:

```
Inbound:  TCP → X.224/TPKT → Security → MCS demux → Decompression → PDU parse → Handler
Outbound: Handler → PDU serialize → Compression → MCS mux → Security → X.224/TPKT → TCP
```

### Connection Sequence

The connection follows the 10-phase sequence defined in [MS-RDPBCGR] §1.3.1.1:

| Phase | Name | What Happens |
|-------|------|-------------|
| 1 | Connection Initiation | TCP connect + X.224 protocol negotiation |
| 2 | Basic Settings Exchange | MCS Connect Initial/Response with GCC client/server data blocks |
| 3 | Channel Connection | Erect Domain, Attach User, join user/IO/virtual channels |
| 4 | Security Commencement | RSA key exchange via Security Exchange PDU (Standard RDP only; skipped for TLS/NLA) |
| 5 | Secure Settings Exchange | Client Info PDU with credentials, timezone, performance flags |
| 6 | Auto-Detection | Optional bandwidth/latency detection (skipped) |
| 7 | Licensing | MS-RDPELE license exchange (STATUS_VALID_CLIENT fast path) |
| 8 | Multitransport | Optional UDP bootstrapping (skipped) |
| 9 | Capabilities Exchange | Server Demand Active → Client Confirm Active |
| 10 | Finalization | Synchronize, Control (Cooperate/Request/Granted), Font List/Map |

### Protocol Stack

| Layer | Module | Responsibility |
|-------|--------|----------------|
| Transport | `transport/tcp.py` | asyncio TCP streams, in-place TLS upgrade |
| Framing | `transport/x224.py` | TPKT headers (RFC 1006), X.224 connection negotiation |
| Security | `security/standard.py` | RSA + RC4 encryption, key derivation, MAC |
| Security | `security/enhanced.py` | TLS via `ssl.create_default_context()` |
| Security | `security/nla.py` | CredSSP handshake via `pyspnego` |
| Security | `security/licensing.py` | MS-RDPELE license exchange |
| MCS | `mcs/layer.py` | T.125 domain management, channel multiplexing |
| MCS | `mcs/gcc.py` | GCC Conference Create Request/Response encoding |
| PDU | `pdu/base.py` | `Pdu` ABC, `ByteReader`/`ByteWriter`, `PduParseError` |
| PDU | `pdu/core.py` | ShareControl/ShareData headers |
| PDU | `pdu/capabilities.py` | Capability set types and negotiation |
| PDU | `pdu/fastpath.py` | Fast-path input/output framing |
| Codec | `codec/rle.py` | RLE bitmap decompression (8/16/24/32-bit) |
| Codec | `codec/remotefx.py` | RemoteFX wavelet codec (DWT, RLGR, YCbCr→RGB) |
| Codec | `codec/nscodec.py` | NSCodec lossy/lossless decompression |
| Codec | `codec/h264.py` | H.264 NAL unit decoding via PyAV |
| Codec | `codec/mppc.py` | MPPC bulk compression (64KB sliding window) |
| Graphics | `graphics/surface.py` | RGBA framebuffer with dirty rect tracking |
| Graphics | `graphics/gdi.py` | GDI drawing order processor with delta encoding |
| Graphics | `graphics/pointer.py` | Cursor cache and shape decoding |
| Graphics | `graphics/gfx.py` | RDPGFX pipeline (surfaces, caches, frame ack) |
| Channels | `channels/static.py` | Static VC chunking/reassembly |
| Channels | `channels/dynamic.py` | DRDYNVC multiplexing |
| Channels | `channels/clipboard.py` | CLIPRDR clipboard sharing |
| Channels | `channels/audio_output.py` | RDPSND audio playback |
| Channels | `channels/audio_input.py` | AUDIN microphone capture |
| Channels | `channels/drive.py` | RDPDR file system redirection |
| Session | `session.py` | Dispatch loop, input methods, event callbacks |
| Connection | `connection.py` | 10-phase connection sequence orchestrator |
| Reconnect | `reconnect.py` | Auto-reconnect cookie + retry logic |

### Package Layout

```
arrdipi/
├── __init__.py          # Public API: connect(), Session, exports
├── connection.py        # 10-phase connection sequence orchestrator
├── session.py           # Session lifecycle, dispatch loop, event callbacks
├── reconnect.py         # Auto-reconnect cookie + retry logic
├── errors.py            # Error hierarchy (ArrdipiError and subclasses)
├── transport/           # TCP + X.224/TPKT framing
├── security/            # Standard RDP, TLS, NLA/CredSSP, licensing
├── mcs/                 # T.125 MCS channel multiplexing + GCC encoding
├── pdu/                 # PDU dataclass framework (parse/serialize)
├── codec/               # RLE, RemoteFX, NSCodec, MPPC, H.264
├── graphics/            # Surface framebuffer, GDI orders, pointer, GFX pipeline
├── channels/            # Static/dynamic VCs, clipboard, audio, drive
└── cli/                 # Entry point, interactive menu, pygame window
```

### PDU Design Pattern

Every protocol message is a Python `@dataclass` with `parse()` and `serialize()` methods:

```python
@dataclass
class MyPdu(Pdu):
    field_a: int
    field_b: bytes

    @classmethod
    def parse(cls, data: bytes) -> MyPdu:
        reader = ByteReader(data)
        return cls(
            field_a=reader.read_u16_le(),
            field_b=reader.read_bytes(reader.remaining()),
        )

    def serialize(self) -> bytes:
        writer = ByteWriter()
        writer.write_u16_le(self.field_a)
        writer.write_bytes(self.field_b)
        return writer.to_bytes()
```

Round-trip invariant: `Pdu.parse(pdu.serialize()) == pdu` for all PDU types.

## Development

### Setup

```bash
# Clone the repository
git clone <repo-url>
cd arrdipi

# Install dependencies (requires uv)
uv sync

# Run the test suite
uv run pytest

# Run with verbose output
uv run pytest -v
```

### Makefile

The project includes a Makefile for common tasks:

```bash
make help       # Show all available targets
make install    # Install dependencies (uv sync)
make test       # Run the test suite
make test-v     # Run tests with verbose output
make run        # Run the application (python main.py)
make menu       # Open the interactive terminal menu
make cli-help   # Show CLI connect help
make check      # Verify the package imports correctly
make clean      # Remove build artifacts and caches
```

### Requirements

- Python 3.13+
- [uv](https://docs.astral.sh/uv/) package manager

### Running Tests

```bash
# Full suite
uv run pytest

# Single file
uv run pytest tests/test_connection.py

# Verbose with output
uv run pytest -v

# Via Makefile
make test
```

The test suite covers all protocol layers, PDU round-trip correctness, codec behavior, channel lifecycle, CLI argument parsing, and error handling.

## Protocol References

The implementation follows these Microsoft Open Specifications and ITU-T standards:

| Specification | Scope |
|---------------|-------|
| [MS-RDPBCGR] | Core protocol, connection sequence, PDUs, security, input, basic graphics |
| [MS-RDPELE] | Licensing extension |
| [MS-RDPECLIP] | Clipboard virtual channel |
| [MS-RDPEA] | Audio output virtual channel |
| [MS-RDPEAI] | Audio input virtual channel |
| [MS-RDPEDYC] | Dynamic virtual channels |
| [MS-RDPEFS] | File system redirection |
| [MS-RDPEGFX] | Graphics pipeline (H.264) |
| [MS-RDPRFX] | RemoteFX codec |
| [MS-RDPNSC] | NSCodec |
| [MS-RDPEGDI] | GDI drawing orders |
| [MS-CSSP] | CredSSP / NLA |
| ITU-T X.224 | Connection-mode transport layer |
| ITU-T T.125 | Multipoint Communication Service (MCS) |

## FAQ

### What Python version is required?

Python 3.13 or later. The project uses modern Python features including `match` statements, `Self` type hints, and `dataclass` patterns that require 3.13+.

### Does arrdipi use FreeRDP or any C RDP libraries?

No. The entire RDP protocol stack is implemented in pure Python. External libraries are only used for non-protocol concerns: `cryptography` for TLS/RSA/RC4, `pyspnego` for NTLM/Kerberos tokens, `av` for H.264 decoding, `pygame` for the GUI window, and `sounddevice` for audio.

### What security modes are supported?

Three modes, matching what Windows RDP servers support:
- **Standard RDP Security** — Legacy RSA+RC4 encryption. Works with older servers.
- **TLS** — Enhanced security using TLS 1.0–1.3. Certificate verification is configurable.
- **NLA (CredSSP)** — Network Level Authentication. Authenticates the user before the full connection is established. Supports NTLM (username/password) and Kerberos (when valid tickets exist).

The default mode is `auto`, which negotiates the strongest protocol the server supports (NLA > TLS > Standard).

### How does the connection sequence work?

arrdipi follows the 10-phase connection sequence defined in [MS-RDPBCGR] §1.3.1.1. The `ConnectionSequence` class orchestrates each phase in order. If any phase fails, a `ConnectionPhaseError` is raised with the phase number, name, and underlying cause. See the Architecture section for the full phase breakdown.

### What graphics codecs are supported?

- **RLE** — Basic run-length encoding at all color depths (8/16/24/32-bit)
- **RemoteFX (RFX)** — Wavelet-based codec using RLGR entropy coding and inverse DWT
- **NSCodec** — Near-lossless codec with lossy and lossless modes
- **H.264/AVC** — Modern codec via the RDPGFX pipeline, decoded using PyAV/FFmpeg
- **GDI Orders** — Server-side drawing primitives rendered directly to the framebuffer

### What virtual channels are implemented?

| Channel | Protocol | Type | Purpose |
|---------|----------|------|---------|
| cliprdr | MS-RDPECLIP | Static | Bidirectional clipboard text sharing |
| rdpsnd | MS-RDPEA | Static | Server-to-client audio playback |
| AUDIO_INPUT | MS-RDPEAI | Dynamic | Client-to-server microphone capture |
| rdpdr | MS-RDPEFS | Static | File system / drive redirection |
| drdynvc | MS-RDPEDYC | Static | Dynamic virtual channel transport |
| Microsoft::Windows::RDS::Graphics | MS-RDPEGFX | Dynamic | GFX pipeline (H.264, surface management) |

### How does fast-path vs slow-path work?

Fast-path is an optimized PDU encoding that reduces overhead for high-frequency input and graphics data. arrdipi automatically detects fast-path support from the server's `GeneralCapabilitySet` and uses it when available. All input methods (`send_key`, `send_mouse_move`, etc.) transparently choose the best encoding.

### How does auto-reconnect work?

When the server sends a Save Session Info PDU containing an auto-reconnect cookie, arrdipi stores it via the `ReconnectHandler`. If the connection drops, the handler automatically attempts to reconnect using the cookie (HMAC-based authentication per [MS-RDPBCGR] §5.5). If the server rejects the cookie, it falls back to full authentication. The maximum number of reconnection attempts is configurable.

### Can I use arrdipi without the GUI?

Yes. The `pygame` dependency is only used by the CLI's `DesktopWindow`. The Python API (`arrdipi.connect()`) works without any GUI — you get a `Session` object with a `GraphicsSurface` framebuffer that you can read programmatically. This is useful for automation, testing, and headless scenarios.

### How do I handle errors?

All arrdipi exceptions inherit from `ArrdipiError`. Each error type carries structured context (phase numbers, byte offsets, error codes) so you can handle failures precisely. See the Error Types section for the full hierarchy.

### How is the password handled securely?

Passwords are never logged or stored on disk. The CLI accepts passwords via the `--password` flag or the `ARRDIPI_PASSWORD` environment variable (the flag takes precedence). In the Python API, passwords are passed directly to `connect()`. For NLA connections, credentials are delegated to the server via the encrypted CredSSP channel.

## Contributing

Contributions are welcome! Please read the [Contributing Guide](CONTRIBUTING.md) for details on the development workflow, coding standards, and pull request process.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for the full text.
