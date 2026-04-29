# Contributing to arrdipi

Thank you for your interest in contributing to arrdipi! This document provides guidelines and information for contributors.

## Getting Started

### Prerequisites

- Python 3.13+
- [uv](https://docs.astral.sh/uv/getting-started/installation/) package manager

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/<your-username>/arrdipi.git
cd arrdipi

# Install all dependencies
uv sync

# Verify everything works
uv run pytest
```

## How to Contribute

### Reporting Bugs

- Use the [Bug Report](https://github.com/arrdipi/arrdipi/issues/new?template=bug_report.yml) issue template
- Include Python version, OS, and steps to reproduce
- Include the full error traceback if applicable

### Suggesting Features

- Use the [Feature Request](https://github.com/arrdipi/arrdipi/issues/new?template=feature_request.yml) issue template
- Describe the use case and expected behavior
- Reference relevant MS-RDP specifications if applicable

### Submitting Changes

1. Fork the repository
2. Create a feature branch from `main`: `git checkout -b feature/your-feature`
3. Make your changes
4. Write or update tests for your changes
5. Run the full test suite: `uv run pytest`
6. Commit with a descriptive message following [Conventional Commits](https://www.conventionalcommits.org/):
   ```
   feat(codec): add RDP 6.1 bulk compression support
   fix(security): handle expired Kerberos tickets gracefully
   docs: update API reference for clipboard channel
   test(mcs): add round-trip test for channel join failure
   ```
7. Push to your fork and open a Pull Request

## Development Guidelines

### Code Style

- Use type hints on all public interfaces
- Follow PEP 8 naming conventions
- Keep functions focused on a single responsibility
- Use `async`/`await` for all I/O-bound operations

### PDU Pattern

All protocol data units follow the same dataclass pattern:

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

Round-trip correctness is mandatory: `Pdu.parse(pdu.serialize()) == pdu`.

### Testing

- Every new feature or bug fix must include tests
- Tests must pass at 100% — no skipped or expected-failure tests
- Use `pytest` and `pytest-asyncio` for async tests
- Place tests in `tests/test_<module>.py` matching the source module
- Use mocks for network I/O; never connect to real RDP servers in tests

```bash
# Run all tests
uv run pytest

# Run a specific test file
uv run pytest tests/test_connection.py

# Run with verbose output
uv run pytest -v
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | Use |
|--------|-----|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `test` | Adding or updating tests |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `perf` | Performance improvement |
| `chore` | Build process, dependency updates, tooling |

### Pull Request Process

1. Ensure all tests pass (`uv run pytest`)
2. Update documentation if your change affects the public API
3. Update the CHANGELOG.md under the `[Unreleased]` section
4. Fill out the PR template completely
5. Request review from a maintainer

## Security

If you discover a security vulnerability, please do **not** open a public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## License

By contributing to arrdipi, you agree that your contributions will be licensed under the [MIT License](LICENSE).
