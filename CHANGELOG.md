# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-01-01

### Added

- Full RDP protocol stack implemented in pure Python
- Transport layer: TCP with async I/O, X.224/TPKT framing, in-place TLS upgrade
- Security: Standard RDP Security (RSA + RC4), TLS (Enhanced), NLA/CredSSP via pyspnego
- MCS layer: T.125 domain management, channel multiplexing, GCC Conference encoding
- PDU framework: dataclass-based parse/serialize with round-trip correctness
- Connection sequence: 10-phase orchestrator per [MS-RDPBCGR] 1.3.1.1
- Graphics codecs: RLE (8/16/24/32-bit), RemoteFX (RLGR + DWT), NSCodec, H.264 via PyAV
- GDI drawing order processor with delta encoding and bitmap/glyph caches
- RDPGFX pipeline: surface management, cache operations, frame acknowledge
- Pointer/cursor handler: color, new, cached, large pointer support (up to 384x384)
- MPPC bulk data compression (64KB sliding window)
- Fast-path input/output for low-latency interaction
- Static virtual channel chunking and reassembly
- Dynamic virtual channel (DRDYNVC) multiplexing
- Clipboard channel (CLIPRDR): bidirectional text sharing
- Audio output channel (RDPSND): PCM playback via sounddevice
- Audio input channel (AUDIN): microphone capture via sounddevice
- Drive redirection channel (RDPDR): file system I/O with read-only enforcement
- Session lifecycle: dispatch loop, input methods, event callbacks
- Auto-reconnect with server-issued cookies and HMAC authentication
- Public API: `arrdipi.connect()` async function returning a `Session`
- CLI: `arrdipi connect` subcommand with pygame graphical window
- CLI: `arrdipi menu` interactive terminal menu for feature exploration
- Structured error hierarchy with context (phase numbers, byte offsets, error codes)
- Comprehensive test suite (1000+ tests)
- Cross-platform support: Windows, macOS, Linux

[Unreleased]: https://github.com/arrdipi/arrdipi/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/arrdipi/arrdipi/releases/tag/v0.1.0
