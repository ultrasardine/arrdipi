# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0](https://github.com/ultrasardine/arrdipi/compare/arrdipi-v0.1.0...arrdipi-v0.2.0) (2026-08-07)


### Features

* implement fast-path graphics pipeline ([2eefbf7](https://github.com/ultrasardine/arrdipi/commit/2eefbf79bee4f99241fc18978c00091f02ce06cf))
* implement fast-path graphics pipeline ([35764bb](https://github.com/ultrasardine/arrdipi/commit/35764bbae726b4c697d7f4d0ca6f8f6fedd28112))
* initial release of arrdipi — pure Python RDP client library ([a44c58a](https://github.com/ultrasardine/arrdipi/commit/a44c58a8b6be832100ef88bdcfa08f86c84c4a86))


### Bug Fixes

* **capabilities:** echo back ALL server capabilities in Confirm Active ([f7d51af](https://github.com/ultrasardine/arrdipi/commit/f7d51af00f4f87d0ee9b04ee159969470395d837))
* **capabilities:** echo server capabilities verbatim in Confirm Active ([37048da](https://github.com/ultrasardine/arrdipi/commit/37048da4ba904f1e584e177a864bbfa0e810939d))
* **capabilities:** fix General capability size and remove problematic codecs ([405cbd5](https://github.com/ultrasardine/arrdipi/commit/405cbd5c2917bdf0d65a6f4a0b94829750340a0d))
* **capabilities:** revert General cap padding — server expects 20 byte payload ([f78cda8](https://github.com/ultrasardine/arrdipi/commit/f78cda86cd36edf1b2d187aa10a064c4535bb772))
* **ci:** correct release-please config for v4 extra-files ([fd95794](https://github.com/ultrasardine/arrdipi/commit/fd95794b9c42c8e81fa37c66a53cf695dba5c50e))
* **connection:** correct ShareControl pduType values and shareId ([0a1912b](https://github.com/ultrasardine/arrdipi/commit/0a1912b3cb67d1f72ae08b4e5960c60f00346c3a))
* **connection:** correct uncompressedLength in ShareData header ([4d7bfb7](https://github.com/ultrasardine/arrdipi/commit/4d7bfb7fc3b4e52675b7bdee473f23ede21495f0))
* **docs:** use git+https install URLs in README ([8a3e523](https://github.com/ultrasardine/arrdipi/commit/8a3e523c69fe3cd77e727e4a00a2e8a2b1435ec4))
* **mcs:** correct GCC ConferenceCreateRequest PER encoding ([34ae254](https://github.com/ultrasardine/arrdipi/commit/34ae25444c376d29fd553b7579c7c6e906c13fca))
* **mcs:** correct PER encoding of AttachUserConfirm and ChannelJoinConfirm ([31acaac](https://github.com/ultrasardine/arrdipi/commit/31acaac4e31f96ab4b6e38bb48a6354f0d63ee21))
* **mcs:** set serverSelectedProtocol in ClientCoreData after NLA ([8539565](https://github.com/ultrasardine/arrdipi/commit/853956544cb804d4ed311591b958a8fb4f015040))
* **mcs:** use PER-encoded integers in Erect Domain Request ([13f1113](https://github.com/ultrasardine/arrdipi/commit/13f1113c44e309ea2fde672bbef7279c17be7c6d))
* **nla:** always pass server_hostname for SNI, remove broken ctypes ([062c121](https://github.com/ultrasardine/arrdipi/commit/062c1211b878b9b988b351bf6b52006758b7f4b2))
* **nla:** correct CredSSP pubKeyAuth format for successful handshake ([870aaa1](https://github.com/ultrasardine/arrdipi/commit/870aaa1fae6c822f9ca6cc31e6333d7ab495e81e))
* **nla:** re-enable SHA-1 signatures for OpenSSL 3.0 RDP compatibility ([c60e952](https://github.com/ultrasardine/arrdipi/commit/c60e9524cf3d1c0540e89f0c3142a87ad4a19335))
* **nla:** simplify to create_default_context ([b676cc8](https://github.com/ultrasardine/arrdipi/commit/b676cc8182c1cd7aa6baabe14001cbcf21dba316))
* **nla:** skip SNI when verify_cert is False ([61959ee](https://github.com/ultrasardine/arrdipi/commit/61959ee10b4fad70dac2f1b09cce207fee75ff6d))
* **security:** remove erroneous security headers for Enhanced Security ([e3792a6](https://github.com/ultrasardine/arrdipi/commit/e3792a60f63fb0199642548ec9446a65af0afd92))
* **tcp:** revert to start_tls for TLS upgrade ([86caf59](https://github.com/ultrasardine/arrdipi/commit/86caf59f24f5627d2191cc65add7ef7b5de1e9c2))
* **tcp:** simplify upgrade_to_tls without protocol recreation ([340598d](https://github.com/ultrasardine/arrdipi/commit/340598dd44d494544601a56a10118c05584bf441))
* **tcp:** use blocking wrap_socket for TLS upgrade ([8f8cfcb](https://github.com/ultrasardine/arrdipi/commit/8f8cfcbc7fbbc3e5bfb952af4e1f4c3eee22a1f2))
* **tcp:** use create_connection(ssl=) for async TLS handshake ([e92914a](https://github.com/ultrasardine/arrdipi/commit/e92914acae134c1b7c5bbd3c8a8c84fbe8c2e399))
* **tcp:** use socket-level TLS instead of asyncio start_tls ([dda0523](https://github.com/ultrasardine/arrdipi/commit/dda0523cf6db050735966a4c3161084ec5416675))
* **test:** close drive channel handles before temp directory cleanup ([#1](https://github.com/ultrasardine/arrdipi/issues/1)) ([c3f7f8e](https://github.com/ultrasardine/arrdipi/commit/c3f7f8e4cfdf9f65ce9650c294ea9352d6f5d29e))
* **test:** use version format check instead of hardcoded value ([45fb605](https://github.com/ultrasardine/arrdipi/commit/45fb605b541ca482d60bde1c526138cbec9993cb))
* **x224:** handle Fast-Path PDUs in recv_pdu ([23a1a46](https://github.com/ultrasardine/arrdipi/commit/23a1a467810524eaeac51bd95fa7e3da8530e187))

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
