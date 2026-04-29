"""PDU base framework: ByteReader, ByteWriter, and Pdu abstract base class.

Provides the foundational binary I/O utilities and abstract base for all RDP
PDU types in the arrdipi library.
"""

from __future__ import annotations

import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Self

from arrdipi.errors import PduParseError


class ByteReader:
    """Bounds-checked binary reader wrapping memoryview for zero-copy reads.

    Used by all PDU parse() implementations to safely read binary data with
    automatic offset tracking. Raises PduParseError when reads go out of bounds.
    """

    def __init__(self, data: bytes, pdu_type: str = "Unknown") -> None:
        self._data = memoryview(data)
        self._offset = 0
        self._pdu_type = pdu_type

    @property
    def offset(self) -> int:
        """Current read position in the buffer."""
        return self._offset

    def remaining(self) -> int:
        """Number of bytes remaining to be read."""
        return len(self._data) - self._offset

    def read_u8(self) -> int:
        """Read a single unsigned byte."""
        self._check_bounds(1)
        value = self._data[self._offset]
        self._offset += 1
        return value

    def read_u16_le(self) -> int:
        """Read a 16-bit unsigned integer in little-endian byte order."""
        self._check_bounds(2)
        value = struct.unpack_from("<H", self._data, self._offset)[0]
        self._offset += 2
        return value

    def read_u32_le(self) -> int:
        """Read a 32-bit unsigned integer in little-endian byte order."""
        self._check_bounds(4)
        value = struct.unpack_from("<I", self._data, self._offset)[0]
        self._offset += 4
        return value

    def read_i32_le(self) -> int:
        """Read a 32-bit signed integer in little-endian byte order."""
        self._check_bounds(4)
        value = struct.unpack_from("<i", self._data, self._offset)[0]
        self._offset += 4
        return value

    def read_u64_le(self) -> int:
        """Read a 64-bit unsigned integer in little-endian byte order."""
        self._check_bounds(8)
        value = struct.unpack_from("<Q", self._data, self._offset)[0]
        self._offset += 8
        return value

    def read_bytes(self, n: int) -> bytes:
        """Read exactly n bytes from the buffer."""
        self._check_bounds(n)
        value = bytes(self._data[self._offset : self._offset + n])
        self._offset += n
        return value

    def _check_bounds(self, n: int) -> None:
        """Raise PduParseError if n bytes are not available."""
        if self._offset + n > len(self._data):
            raise PduParseError(
                pdu_type=self._pdu_type,
                offset=self._offset,
                description=(
                    f"need {n} bytes but only {len(self._data) - self._offset} remaining"
                ),
            )


class ByteWriter:
    """Binary writer using an internal bytearray.

    Used by all PDU serialize() implementations to build binary output.
    """

    def __init__(self) -> None:
        self._buf = bytearray()

    def write_u8(self, value: int) -> None:
        """Write a single unsigned byte."""
        self._buf.append(value & 0xFF)

    def write_u16_le(self, value: int) -> None:
        """Write a 16-bit unsigned integer in little-endian byte order."""
        self._buf.extend(struct.pack("<H", value & 0xFFFF))

    def write_u32_le(self, value: int) -> None:
        """Write a 32-bit unsigned integer in little-endian byte order."""
        self._buf.extend(struct.pack("<I", value & 0xFFFFFFFF))

    def write_i32_le(self, value: int) -> None:
        """Write a 32-bit signed integer in little-endian byte order."""
        self._buf.extend(struct.pack("<i", value))

    def write_u64_le(self, value: int) -> None:
        """Write a 64-bit unsigned integer in little-endian byte order."""
        self._buf.extend(struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))

    def write_bytes(self, data: bytes) -> None:
        """Write raw bytes to the buffer."""
        self._buf.extend(data)

    def to_bytes(self) -> bytes:
        """Return the accumulated buffer as an immutable bytes object."""
        return bytes(self._buf)


@dataclass
class Pdu(ABC):
    """Abstract base for all RDP PDU types.

    All PDUs support parse/serialize with round-trip correctness (Req 3, AC 1-5).
    Subclasses must implement both parse() and serialize().
    """

    @classmethod
    @abstractmethod
    def parse(cls, data: bytes) -> Self:
        """Decode binary wire-format into a typed PDU object.

        Raises PduParseError on malformed/truncated data with PDU type,
        byte offset, and description (Req 3, AC 6).
        """
        ...

    @abstractmethod
    def serialize(self) -> bytes:
        """Encode this PDU object into binary wire-format."""
        ...
