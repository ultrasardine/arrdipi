"""Clipboard redirection channel (CLIPRDR).

Implements [MS-RDPECLIP] over the "cliprdr" static virtual channel.
Supports text clipboard exchange and file clipboard streaming.
"""

from __future__ import annotations

import asyncio
import logging
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Self

logger = logging.getLogger(__name__)

# CLIPRDR message types
CLIPRDR_MONITOR_READY = 0x0001
CLIPRDR_FORMAT_LIST = 0x0002
CLIPRDR_FORMAT_LIST_RESPONSE = 0x0003
CLIPRDR_FORMAT_DATA_REQUEST = 0x0004
CLIPRDR_FORMAT_DATA_RESPONSE = 0x0005
CLIPRDR_TEMP_DIRECTORY = 0x0006
CLIPRDR_CAPABILITIES = 0x0007
CLIPRDR_FILECONTENTS_REQUEST = 0x0008
CLIPRDR_FILECONTENTS_RESPONSE = 0x0009

# Clipboard format IDs
CF_UNICODETEXT = 13

# Message flags
CB_RESPONSE_OK = 0x0001
CB_RESPONSE_FAIL = 0x0002
CB_ASCII_NAMES = 0x0004

# General capability set
CB_CAPSTYPE_GENERAL = 0x0001
CB_CAPS_VERSION_2 = 0x0002

# General capability flags
CB_USE_LONG_FORMAT_NAMES = 0x00000002
CB_STREAM_FILECLIP_ENABLED = 0x00000004
CB_FILECLIP_NO_FILE_PATHS = 0x00000008
CB_CAN_LOCK_CLIPDATA = 0x00000010
CB_HUGE_FILE_SUPPORT_ENABLED = 0x00000020

# File clipboard flags
FILECONTENTS_SIZE = 0x00000001
FILECONTENTS_RANGE = 0x00000002

# Well-known shell clipboard format names
FILE_GROUP_DESCRIPTOR_W = "FileGroupDescriptorW"
FILE_GROUP_DESCRIPTOR = "FileGroupDescriptor"
FILE_CONTENTS = "FileContents"
PREFERRED_DROP_EFFECT = "Preferred DropEffect"

# Local custom format IDs used in our Format List
_FORMAT_ID_FILE_GROUP_DESCRIPTOR_W = 0xC001
_FORMAT_ID_FILE_CONTENTS = 0xC002
_FORMAT_ID_PREFERRED_DROP_EFFECT = 0xC003

# FILEDESCRIPTOR details
_FILE_DESCRIPTOR_BYTES = 592
_FD_ATTRIBUTES = 0x00000004
_FD_FILESIZE = 0x00000040
_FILE_ATTRIBUTE_NORMAL = 0x00000080


@dataclass
class ClipboardFormat:
    """A clipboard format entry in a Format List."""

    format_id: int
    format_name: str = ""


@dataclass
class ClipboardFileDescriptor:
    """Parsed descriptor for a clipboard file."""

    index: int
    name: str
    size: int


@dataclass
class MonitorReadyPdu:
    """CLIPRDR Monitor Ready PDU."""

    msg_flags: int = 0

    @classmethod
    def parse(cls, data: bytes) -> Self:
        return cls()

    def serialize(self) -> bytes:
        return struct.pack("<HHI", CLIPRDR_MONITOR_READY, self.msg_flags, 0)


@dataclass
class ClipboardCapabilitiesPdu:
    """CLIPRDR Capabilities PDU."""

    general_flags: int = CB_USE_LONG_FORMAT_NAMES | CB_HUGE_FILE_SUPPORT_ENABLED

    @classmethod
    def parse(cls, data: bytes) -> Self:
        if len(data) < 4:
            return cls()
        offset = 4
        general_flags = 0
        if len(data) >= offset + 8:
            cap_type = struct.unpack_from("<H", data, offset)[0]
            if cap_type == CB_CAPSTYPE_GENERAL and len(data) >= offset + 12:
                general_flags = struct.unpack_from("<I", data, offset + 8)[0]
        return cls(general_flags=general_flags)

    def serialize(self) -> bytes:
        cap_set = struct.pack(
            "<HHII",
            CB_CAPSTYPE_GENERAL,
            12,
            CB_CAPS_VERSION_2,
            self.general_flags,
        )
        body = struct.pack("<HH", 1, 0) + cap_set
        header = struct.pack("<HHI", CLIPRDR_CAPABILITIES, 0, len(body))
        return header + body


@dataclass
class TemporaryDirectoryPdu:
    """CLIPRDR Temporary Directory PDU."""

    temp_dir: str = ""

    @classmethod
    def parse(cls, data: bytes) -> Self:
        if len(data) >= 520:
            path_bytes = data[:520]
            temp_dir = path_bytes.decode("utf-16-le", errors="replace").rstrip("\x00")
            return cls(temp_dir=temp_dir)
        return cls()

    def serialize(self) -> bytes:
        path_encoded = self.temp_dir.encode("utf-16-le")
        path_padded = path_encoded[:518] + b"\x00\x00"
        path_padded = path_padded.ljust(520, b"\x00")
        header = struct.pack("<HHI", CLIPRDR_TEMP_DIRECTORY, 0, len(path_padded))
        return header + path_padded


@dataclass
class FormatListPdu:
    """CLIPRDR Format List PDU."""

    formats: list[ClipboardFormat] = field(default_factory=list)
    use_long_names: bool = True

    @classmethod
    def parse(cls, data: bytes, use_long_names: bool = True) -> Self:
        formats: list[ClipboardFormat] = []
        offset = 0

        if use_long_names:
            while offset + 4 <= len(data):
                format_id = struct.unpack_from("<I", data, offset)[0]
                offset += 4
                name_start = offset
                while offset + 2 <= len(data):
                    char = struct.unpack_from("<H", data, offset)[0]
                    offset += 2
                    if char == 0:
                        break
                name_bytes = data[name_start : offset - 2] if offset > name_start + 2 else b""
                name = name_bytes.decode("utf-16-le", errors="replace") if name_bytes else ""
                formats.append(ClipboardFormat(format_id=format_id, format_name=name))
        else:
            while offset + 36 <= len(data):
                format_id = struct.unpack_from("<I", data, offset)[0]
                offset += 4
                name_bytes = data[offset : offset + 32]
                offset += 32
                name = name_bytes.split(b"\x00")[0].decode("ascii", errors="replace")
                formats.append(ClipboardFormat(format_id=format_id, format_name=name))

        return cls(formats=formats, use_long_names=use_long_names)

    def serialize(self) -> bytes:
        body = bytearray()
        if self.use_long_names:
            for fmt in self.formats:
                body.extend(struct.pack("<I", fmt.format_id))
                body.extend(fmt.format_name.encode("utf-16-le") + b"\x00\x00")
        else:
            for fmt in self.formats:
                body.extend(struct.pack("<I", fmt.format_id))
                name_encoded = fmt.format_name.encode("ascii", errors="replace")[:31]
                body.extend(name_encoded + b"\x00" * (32 - len(name_encoded)))
        flags = 0 if self.use_long_names else CB_ASCII_NAMES
        return struct.pack("<HHI", CLIPRDR_FORMAT_LIST, flags, len(body)) + bytes(body)


@dataclass
class FormatDataRequestPdu:
    """CLIPRDR Format Data Request PDU."""

    requested_format_id: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        if len(data) < 4:
            return cls(requested_format_id=0)
        return cls(requested_format_id=struct.unpack_from("<I", data, 0)[0])

    def serialize(self) -> bytes:
        body = struct.pack("<I", self.requested_format_id)
        return struct.pack("<HHI", CLIPRDR_FORMAT_DATA_REQUEST, 0, len(body)) + body


@dataclass
class FormatDataResponsePdu:
    """CLIPRDR Format Data Response PDU."""

    data: bytes = b""
    is_success: bool = True

    @classmethod
    def parse(cls, data: bytes, msg_flags: int = CB_RESPONSE_OK) -> Self:
        return cls(data=data, is_success=bool(msg_flags & CB_RESPONSE_OK))

    def serialize(self) -> bytes:
        flags = CB_RESPONSE_OK if self.is_success else CB_RESPONSE_FAIL
        return struct.pack("<HHI", CLIPRDR_FORMAT_DATA_RESPONSE, flags, len(self.data)) + self.data


class ClipboardChannel:
    """Clipboard redirection channel over "cliprdr" static VC."""

    def __init__(self, send_fn: Callable[[bytes], Awaitable[None]]) -> None:
        self._send_fn = send_fn
        self._use_long_format_names = True
        self._local_clipboard_text: str = ""
        self._local_clipboard_files: list[Path] = []
        self._server_formats: list[ClipboardFormat] = []
        self._server_clipboard_data: bytes | None = None
        self._data_response_event = asyncio.Event()
        self._file_contents_response_event = asyncio.Event()
        self._server_file_contents_response: tuple[int, bytes] | None = None
        self._file_stream_counter = 0
        self._ready = False
        self._format_list_ack = asyncio.Event()
        self._format_list_ack.set()  # initially set — no pending Format List

    @property
    def ready(self) -> bool:
        return self._ready

    @property
    def server_formats(self) -> list[ClipboardFormat]:
        return self._server_formats

    async def handle_message(self, data: bytes) -> None:
        if len(data) < 8:
            logger.debug("CLIPRDR: message too short (%d bytes), ignoring", len(data))
            return
        msg_type = struct.unpack_from("<H", data, 0)[0]
        msg_flags = struct.unpack_from("<H", data, 2)[0]
        data_len = struct.unpack_from("<I", data, 4)[0]
        body = data[8 : 8 + data_len] if data_len > 0 else b""

        _MSG_NAMES = {
            0x0001: "MONITOR_READY", 0x0002: "FORMAT_LIST", 0x0003: "FORMAT_LIST_RESPONSE",
            0x0004: "FORMAT_DATA_REQUEST", 0x0005: "FORMAT_DATA_RESPONSE",
            0x0006: "TEMP_DIRECTORY", 0x0007: "CAPABILITIES",
            0x0008: "FILECONTENTS_REQUEST", 0x0009: "FILECONTENTS_RESPONSE",
        }
        logger.debug("CLIPRDR recv: %s (0x%04X) flags=0x%04X len=%d ready=%s",
                     _MSG_NAMES.get(msg_type, "UNKNOWN"), msg_type, msg_flags, data_len, self._ready)

        if msg_type == CLIPRDR_MONITOR_READY:
            await self._handle_monitor_ready()
        elif msg_type == CLIPRDR_FORMAT_LIST:
            await self._handle_server_format_list(body, msg_flags)
        elif msg_type == CLIPRDR_FORMAT_LIST_RESPONSE:
            logger.debug("CLIPRDR: Format List Response received (ack)")
            self._format_list_ack.set()
        elif msg_type == CLIPRDR_FORMAT_DATA_REQUEST:
            await self._handle_format_data_request(body)
        elif msg_type == CLIPRDR_FORMAT_DATA_RESPONSE:
            self._handle_format_data_response(body, msg_flags)
        elif msg_type == CLIPRDR_FILECONTENTS_REQUEST:
            await self._handle_file_contents_request(body)
        elif msg_type == CLIPRDR_FILECONTENTS_RESPONSE:
            self._handle_file_contents_response(body, msg_flags)
        elif msg_type == CLIPRDR_CAPABILITIES:
            self._handle_capabilities(body)
        else:
            logger.debug("CLIPRDR recv: unhandled msg_type=0x%04X", msg_type)

    async def _handle_monitor_ready(self) -> None:
        self._ready = True
        logger.info("CLIPRDR: Monitor Ready received, sending Capabilities")
        caps = ClipboardCapabilitiesPdu()
        await self._send_fn(caps.serialize())
        temp_dir = TemporaryDirectoryPdu(temp_dir="")
        await self._send_fn(temp_dir.serialize())
        # Yield to the event loop so the server can process Capabilities before
        # receiving the Format List — some Windows versions require this.
        await asyncio.sleep(0)
        await self._announce_local_formats()

    def _handle_capabilities(self, body: bytes) -> None:
        caps = ClipboardCapabilitiesPdu.parse(body)
        self._use_long_format_names = bool(caps.general_flags & CB_USE_LONG_FORMAT_NAMES)
        logger.debug("CLIPRDR: server Capabilities general_flags=0x%08X use_long_names=%s",
                     caps.general_flags, self._use_long_format_names)

    async def _handle_server_format_list(self, body: bytes, msg_flags: int) -> None:
        use_long_names = not bool(msg_flags & CB_ASCII_NAMES)
        self._server_formats = FormatListPdu.parse(body, use_long_names=use_long_names).formats
        logger.debug("CLIPRDR: server Format List — %d formats: %s",
                     len(self._server_formats),
                     [(f.format_id, f.format_name) for f in self._server_formats])
        response = struct.pack("<HHI", CLIPRDR_FORMAT_LIST_RESPONSE, CB_RESPONSE_OK, 0)
        await self._send_fn(response)

    async def _handle_format_data_request(self, body: bytes) -> None:
        request = FormatDataRequestPdu.parse(body)
        logger.debug("CLIPRDR: server requests format_id=%d, local_text=%r",
                     request.requested_format_id, self._local_clipboard_text[:40] if self._local_clipboard_text else "")
        if request.requested_format_id == CF_UNICODETEXT and self._local_clipboard_text:
            text_data = self._local_clipboard_text.encode("utf-16-le") + b"\x00\x00"
            response = FormatDataResponsePdu(data=text_data, is_success=True)
        elif request.requested_format_id == _FORMAT_ID_FILE_GROUP_DESCRIPTOR_W and self._local_clipboard_files:
            response = FormatDataResponsePdu(
                data=self._serialize_local_file_group_descriptor(),
                is_success=True,
            )
        elif request.requested_format_id == _FORMAT_ID_PREFERRED_DROP_EFFECT and self._local_clipboard_files:
            response = FormatDataResponsePdu(data=struct.pack("<I", 0x00000001), is_success=True)
        else:
            response = FormatDataResponsePdu(data=b"", is_success=False)
        await self._send_fn(response.serialize())

    def _handle_format_data_response(self, body: bytes, msg_flags: int) -> None:
        self._server_clipboard_data = body if (msg_flags & CB_RESPONSE_OK) else None
        logger.debug("CLIPRDR: Format Data Response flags=0x%04X data_len=%d", msg_flags, len(body))
        self._data_response_event.set()

    async def _handle_file_contents_request(self, body: bytes) -> None:
        if len(body) < 24:
            await self._send_file_contents_fail(stream_id=0)
            return

        stream_id = struct.unpack_from("<I", body, 0)[0]
        file_index = struct.unpack_from("<i", body, 4)[0]
        flags = struct.unpack_from("<I", body, 8)[0]
        pos_low = struct.unpack_from("<I", body, 12)[0]
        pos_high = struct.unpack_from("<I", body, 16)[0]
        requested = struct.unpack_from("<I", body, 20)[0]

        if file_index < 0 or file_index >= len(self._local_clipboard_files):
            await self._send_file_contents_fail(stream_id)
            return

        path = self._local_clipboard_files[file_index]
        try:
            if flags == FILECONTENTS_SIZE:
                size = path.stat().st_size
                payload = struct.pack("<I", stream_id) + struct.pack("<Q", size)
                header = struct.pack("<HHI", CLIPRDR_FILECONTENTS_RESPONSE, CB_RESPONSE_OK, len(payload))
                await self._send_fn(header + payload)
                return
            if flags == FILECONTENTS_RANGE:
                offset = (pos_high << 32) | pos_low
                with path.open("rb") as fp:
                    fp.seek(offset)
                    chunk = fp.read(requested)
                payload = struct.pack("<I", stream_id) + chunk
                header = struct.pack("<HHI", CLIPRDR_FILECONTENTS_RESPONSE, CB_RESPONSE_OK, len(payload))
                await self._send_fn(header + payload)
                return
        except OSError:
            pass

        await self._send_file_contents_fail(stream_id)

    async def _send_file_contents_fail(self, stream_id: int) -> None:
        payload = struct.pack("<I", stream_id)
        header = struct.pack("<HHI", CLIPRDR_FILECONTENTS_RESPONSE, CB_RESPONSE_FAIL, len(payload))
        await self._send_fn(header + payload)

    def _handle_file_contents_response(self, body: bytes, msg_flags: int) -> None:
        if len(body) < 4 or not (msg_flags & CB_RESPONSE_OK):
            self._server_file_contents_response = None
        else:
            stream_id = struct.unpack_from("<I", body, 0)[0]
            self._server_file_contents_response = (stream_id, body[4:])
        self._file_contents_response_event.set()

    async def set_clipboard_text(self, text: str) -> None:
        self._local_clipboard_text = text
        await self._announce_local_formats()

    async def set_clipboard_files(self, paths: list[Path]) -> None:
        self._local_clipboard_files = [path.resolve() for path in paths if path.is_file()]
        await self._announce_local_formats()



    async def _announce_local_formats(self) -> None:
        if not self._ready:
            logger.debug("CLIPRDR: _announce_local_formats skipped (not ready)")
            return
        # Wait for any previous Format List to be acknowledged before sending a new one
        try:
            await asyncio.wait_for(self._format_list_ack.wait(), timeout=3.0)
        except asyncio.TimeoutError:
            logger.debug("CLIPRDR: timed out waiting for Format List ack, sending anyway")
        self._format_list_ack.clear()
        formats: list[ClipboardFormat] = []
        if self._local_clipboard_text:
            formats.append(ClipboardFormat(format_id=CF_UNICODETEXT, format_name=""))
        if self._local_clipboard_files:
            formats.extend(
                [
                    ClipboardFormat(_FORMAT_ID_FILE_GROUP_DESCRIPTOR_W, FILE_GROUP_DESCRIPTOR_W),
                    ClipboardFormat(_FORMAT_ID_FILE_CONTENTS, FILE_CONTENTS),
                    ClipboardFormat(_FORMAT_ID_PREFERRED_DROP_EFFECT, PREFERRED_DROP_EFFECT),
                ]
            )
        # Skip sending an empty Format List — Windows does not send FORMAT_LIST_RESPONSE
        # to an empty list, which would permanently block the ack event.
        if not formats:
            logger.debug("CLIPRDR: skipping empty Format List (nothing in local clipboard)")
            self._format_list_ack.set()  # unblock future sends
            return
        logger.debug("CLIPRDR: announcing %d local formats", len(formats))
        format_list = FormatListPdu(formats=formats, use_long_names=self._use_long_format_names)
        await self._send_fn(format_list.serialize())

    async def get_server_clipboard_text(self, timeout: float = 5.0) -> str:
        has_text = any(f.format_id == CF_UNICODETEXT for f in self._server_formats)
        if not has_text:
            return ""
        data = await self._request_server_format_data(CF_UNICODETEXT, timeout=timeout)
        if data is None:
            return ""
        return data.decode("utf-16-le", errors="replace").rstrip("\x00")

    async def get_server_clipboard_files(
        self, destination_dir: Path, timeout: float = 30.0
    ) -> list[Path]:
        descriptor_id = self._find_server_format_id(FILE_GROUP_DESCRIPTOR_W)
        if descriptor_id is None:
            descriptor_id = self._find_server_format_id(FILE_GROUP_DESCRIPTOR)
        file_contents_id = self._find_server_format_id(FILE_CONTENTS)
        if descriptor_id is None or file_contents_id is None:
            return []

        descriptor_blob = await self._request_server_format_data(descriptor_id, timeout=timeout)
        if not descriptor_blob:
            return []
        descriptors = self._parse_file_group_descriptor(descriptor_blob)
        if not descriptors:
            return []

        destination_dir.mkdir(parents=True, exist_ok=True)
        downloaded: list[Path] = []
        chunk_size = 256 * 1024

        for desc in descriptors:
            safe_name = Path(desc.name).name
            if not safe_name or safe_name in (".", ".."):
                continue
            target = (destination_dir / safe_name).resolve()
            if not str(target).startswith(str(destination_dir.resolve())):
                continue
            size = await self._request_server_file_size(desc.index, timeout=timeout)
            if size is None:
                continue
            try:
                with target.open("wb") as fp:
                    position = 0
                    while position < size:
                        requested = min(chunk_size, size - position)
                        chunk = await self._request_server_file_range(
                            desc.index,
                            position,
                            requested,
                            timeout=timeout,
                        )
                        if chunk is None:
                            raise OSError("missing chunk")
                        if not chunk:
                            break
                        fp.write(chunk)
                        position += len(chunk)
                downloaded.append(target)
            except OSError:
                target.unlink(missing_ok=True)
        return downloaded

    async def _request_server_format_data(
        self, format_id: int, timeout: float
    ) -> bytes | None:
        self._data_response_event.clear()
        self._server_clipboard_data = None
        await self._send_fn(FormatDataRequestPdu(requested_format_id=format_id).serialize())
        try:
            await asyncio.wait_for(self._data_response_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            return None
        return self._server_clipboard_data

    async def _request_server_file_size(self, file_index: int, timeout: float) -> int | None:
        data = await self._request_server_file_contents(
            file_index=file_index,
            flags=FILECONTENTS_SIZE,
            position=0,
            requested=8,
            timeout=timeout,
        )
        if data is None or len(data) < 8:
            return None
        return struct.unpack_from("<Q", data, 0)[0]

    async def _request_server_file_range(
        self, file_index: int, position: int, requested: int, timeout: float
    ) -> bytes | None:
        return await self._request_server_file_contents(
            file_index=file_index,
            flags=FILECONTENTS_RANGE,
            position=position,
            requested=requested,
            timeout=timeout,
        )

    async def _request_server_file_contents(
        self,
        file_index: int,
        flags: int,
        position: int,
        requested: int,
        timeout: float,
    ) -> bytes | None:
        self._file_stream_counter += 1
        stream_id = self._file_stream_counter
        self._server_file_contents_response = None
        self._file_contents_response_event.clear()

        body = struct.pack(
            "<IiIIII",
            stream_id,
            file_index,
            flags,
            position & 0xFFFFFFFF,
            (position >> 32) & 0xFFFFFFFF,
            requested,
        )
        header = struct.pack("<HHI", CLIPRDR_FILECONTENTS_REQUEST, 0, len(body))
        await self._send_fn(header + body)

        try:
            await asyncio.wait_for(self._file_contents_response_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

        if self._server_file_contents_response is None:
            return None
        resp_stream_id, data = self._server_file_contents_response
        if resp_stream_id != stream_id:
            return None
        return data

    def _parse_file_group_descriptor(self, blob: bytes) -> list[ClipboardFileDescriptor]:
        if len(blob) < 4:
            return []
        count = struct.unpack_from("<I", blob, 0)[0]
        out: list[ClipboardFileDescriptor] = []
        offset = 4
        for index in range(count):
            if offset + _FILE_DESCRIPTOR_BYTES > len(blob):
                break
            entry = blob[offset : offset + _FILE_DESCRIPTOR_BYTES]
            size_high = struct.unpack_from("<I", entry, 64)[0]
            size_low = struct.unpack_from("<I", entry, 68)[0]
            raw_name = entry[72 : 72 + 520]
            name = raw_name.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
            out.append(
                ClipboardFileDescriptor(
                    index=index,
                    name=name,
                    size=(size_high << 32) | size_low,
                )
            )
            offset += _FILE_DESCRIPTOR_BYTES
        return out

    def _serialize_local_file_group_descriptor(self) -> bytes:
        if not self._local_clipboard_files:
            return b""
        payload = bytearray()
        payload.extend(struct.pack("<I", len(self._local_clipboard_files)))
        for path in self._local_clipboard_files:
            stat = path.stat()
            size = stat.st_size
            entry = bytearray(_FILE_DESCRIPTOR_BYTES)
            struct.pack_into("<I", entry, 0, _FD_ATTRIBUTES | _FD_FILESIZE)
            struct.pack_into("<I", entry, 36, _FILE_ATTRIBUTE_NORMAL)
            struct.pack_into("<I", entry, 64, (size >> 32) & 0xFFFFFFFF)
            struct.pack_into("<I", entry, 68, size & 0xFFFFFFFF)
            file_name = path.name.encode("utf-16-le")[:518]
            entry[72 : 72 + len(file_name)] = file_name
            entry[72 + len(file_name) : 74 + len(file_name)] = b"\x00\x00"
            payload.extend(entry)
        return bytes(payload)

    def _find_server_format_id(self, format_name: str) -> int | None:
        target = format_name.casefold()
        for fmt in self._server_formats:
            if fmt.format_name.casefold() == target:
                return fmt.format_id
        return None
