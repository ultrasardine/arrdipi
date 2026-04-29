"""Drive redirection channel (RDPDR).

Implements [MS-RDPEFS] - Remote Desktop Protocol File System Virtual Channel
Extension. Operates over the "rdpdr" static virtual channel.

Requirements addressed: Req 25 (AC 1-6)
"""

from __future__ import annotations

import os
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from io import IOBase
from typing import Self

from arrdipi.connection import DrivePath

# RDPDR Component type
RDPDR_CTYP_CORE = 0x4472

# RDPDR Packet IDs
PAKID_CORE_SERVER_ANNOUNCE = 0x496E
PAKID_CORE_CLIENT_ANNOUNCE_REPLY = 0x4343
PAKID_CORE_CLIENT_NAME_REQUEST = 0x434E
PAKID_CORE_DEVICE_LIST_ANNOUNCE = 0x4441
PAKID_CORE_DEVICE_IOCOMPLETION = 0x4943
PAKID_CORE_DEVICE_IOREQUEST = 0x4952

# Device type for filesystem drives
RDPDR_DTYP_FILESYSTEM = 0x00000008

# NTSTATUS codes
STATUS_SUCCESS = 0x00000000
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_NO_SUCH_FILE = 0xC000000F
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_NOT_IMPLEMENTED = 0xC0000002
STATUS_UNSUCCESSFUL = 0xC0000001

# I/O Major Function codes
IRP_MJ_CREATE = 0
IRP_MJ_CLOSE = 2
IRP_MJ_READ = 3
IRP_MJ_WRITE = 4
IRP_MJ_QUERY_INFORMATION = 5
IRP_MJ_SET_INFORMATION = 6
IRP_MJ_DIRECTORY_CONTROL = 12

# File Information Classes
FileBasicInformation = 4
FileStandardInformation = 5
FileBothDirectoryInformation = 3

# Create Disposition
FILE_SUPERSEDE = 0
FILE_OPEN = 1
FILE_CREATE = 2
FILE_OPEN_IF = 3
FILE_OVERWRITE = 4
FILE_OVERWRITE_IF = 5

# Desired Access flags
FILE_READ_DATA = 0x00000001
FILE_WRITE_DATA = 0x00000002
FILE_LIST_DIRECTORY = 0x00000001

# Create Options
FILE_DIRECTORY_FILE = 0x00000001
FILE_NON_DIRECTORY_FILE = 0x00000040


@dataclass
class ServerAnnouncePdu:
    """Server Announce Request PDU [MS-RDPEFS] 2.2.2.2."""

    version_major: int = 1
    version_minor: int = 12
    client_id: int = 0

    @classmethod
    def parse(cls, data: bytes) -> Self:
        if len(data) < 8:
            return cls()
        major, minor, client_id = struct.unpack_from("<HHI", data, 0)
        return cls(version_major=major, version_minor=minor, client_id=client_id)

    def serialize(self) -> bytes:
        header = struct.pack("<HH", RDPDR_CTYP_CORE, PAKID_CORE_SERVER_ANNOUNCE)
        body = struct.pack("<HHI", self.version_major, self.version_minor, self.client_id)
        return header + body


@dataclass
class ClientAnnounceReplyPdu:
    """Client Announce Reply PDU [MS-RDPEFS] 2.2.2.3."""

    version_major: int = 1
    version_minor: int = 12
    client_id: int = 0

    @classmethod
    def parse(cls, data: bytes) -> Self:
        if len(data) < 8:
            return cls()
        major, minor, client_id = struct.unpack_from("<HHI", data, 0)
        return cls(version_major=major, version_minor=minor, client_id=client_id)

    def serialize(self) -> bytes:
        header = struct.pack("<HH", RDPDR_CTYP_CORE, PAKID_CORE_CLIENT_ANNOUNCE_REPLY)
        body = struct.pack("<HHI", self.version_major, self.version_minor, self.client_id)
        return header + body


@dataclass
class ClientNameRequestPdu:
    """Client Name Request PDU [MS-RDPEFS] 2.2.2.4."""

    computer_name: str = "arrdipi"
    unicode_flag: int = 1

    @classmethod
    def parse(cls, data: bytes) -> Self:
        if len(data) < 12:
            return cls()
        unicode_flag = struct.unpack_from("<I", data, 0)[0]
        _code_page = struct.unpack_from("<I", data, 4)[0]
        name_len = struct.unpack_from("<I", data, 8)[0]
        name_data = data[12:12 + name_len]
        if unicode_flag == 1:
            name = name_data.decode("utf-16-le", errors="replace").rstrip("\x00")
        else:
            name = name_data.decode("ascii", errors="replace").rstrip("\x00")
        return cls(computer_name=name, unicode_flag=unicode_flag)

    def serialize(self) -> bytes:
        header = struct.pack("<HH", RDPDR_CTYP_CORE, PAKID_CORE_CLIENT_NAME_REQUEST)
        name_encoded = self.computer_name.encode("utf-16-le") + b"\x00\x00"
        body = struct.pack("<III", self.unicode_flag, 0, len(name_encoded))
        return header + body + name_encoded


@dataclass
class ClientDeviceListAnnouncePdu:
    """Client Device List Announce PDU [MS-RDPEFS] 2.2.2.9."""

    drives: list[tuple[int, str, str]] = field(default_factory=list)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        if len(data) < 4:
            return cls()
        count = struct.unpack_from("<I", data, 0)[0]
        offset = 4
        drives: list[tuple[int, str, str]] = []
        for _ in range(count):
            if offset + 20 > len(data):
                break
            device_type = struct.unpack_from("<I", data, offset)[0]
            device_id = struct.unpack_from("<I", data, offset + 4)[0]
            preferred_name = data[offset + 8:offset + 16].split(b"\x00")[0].decode("ascii", errors="replace")
            data_len = struct.unpack_from("<I", data, offset + 16)[0]
            offset += 20
            device_data = data[offset:offset + data_len] if data_len > 0 else b""
            offset += data_len
            drives.append((device_id, preferred_name, device_data.decode("ascii", errors="replace").rstrip("\x00")))
        return cls(drives=drives)

    def serialize(self) -> bytes:
        header = struct.pack("<HH", RDPDR_CTYP_CORE, PAKID_CORE_DEVICE_LIST_ANNOUNCE)
        body = struct.pack("<I", len(self.drives))
        for device_id, name, _path in self.drives:
            preferred = name.encode("ascii")[:7].ljust(8, b"\x00")
            body += struct.pack("<II", RDPDR_DTYP_FILESYSTEM, device_id)
            body += preferred
            body += struct.pack("<I", 0)
        return header + body


@dataclass
class DeviceIoRequestPdu:
    """Device I/O Request PDU [MS-RDPEFS] 2.2.1.4."""

    device_id: int = 0
    file_id: int = 0
    completion_id: int = 0
    major_function: int = 0
    minor_function: int = 0
    payload: bytes = b""

    @classmethod
    def parse(cls, data: bytes) -> Self:
        if len(data) < 20:
            return cls()
        device_id = struct.unpack_from("<I", data, 0)[0]
        file_id = struct.unpack_from("<I", data, 4)[0]
        completion_id = struct.unpack_from("<I", data, 8)[0]
        major_function = struct.unpack_from("<I", data, 12)[0]
        minor_function = struct.unpack_from("<I", data, 16)[0]
        payload = data[20:]
        return cls(
            device_id=device_id,
            file_id=file_id,
            completion_id=completion_id,
            major_function=major_function,
            minor_function=minor_function,
            payload=payload,
        )

    def serialize(self) -> bytes:
        return struct.pack(
            "<IIIII",
            self.device_id,
            self.file_id,
            self.completion_id,
            self.major_function,
            self.minor_function,
        ) + self.payload


@dataclass
class DeviceIoResponsePdu:
    """Device I/O Response PDU [MS-RDPEFS] 2.2.1.5."""

    device_id: int = 0
    completion_id: int = 0
    io_status: int = STATUS_SUCCESS
    payload: bytes = b""

    @classmethod
    def parse(cls, data: bytes) -> Self:
        if len(data) < 12:
            return cls()
        device_id = struct.unpack_from("<I", data, 0)[0]
        completion_id = struct.unpack_from("<I", data, 4)[0]
        io_status = struct.unpack_from("<I", data, 8)[0]
        payload = data[12:]
        return cls(
            device_id=device_id,
            completion_id=completion_id,
            io_status=io_status,
            payload=payload,
        )

    def serialize(self) -> bytes:
        header = struct.pack("<HH", RDPDR_CTYP_CORE, PAKID_CORE_DEVICE_IOCOMPLETION)
        body = struct.pack("<III", self.device_id, self.completion_id, self.io_status)
        return header + body + self.payload


class DriveChannel:
    """Drive redirection channel operating over the "rdpdr" static VC.

    Handles the RDPDR protocol exchange including server announce,
    device list announce, and file I/O requests.

    (Req 25, AC 1-6)
    """

    def __init__(
        self,
        send_fn: Callable[[bytes], Awaitable[None]],
        drives: list[DrivePath] | None = None,
        client_name: str = "arrdipi",
    ) -> None:
        self._send_fn = send_fn
        self._drives = drives or []
        self._client_name = client_name
        self._ready = False
        self._next_handle_id = 1
        self._open_handles: dict[int, IOBase] = {}
        self._handle_paths: dict[int, str] = {}
        self._handle_device: dict[int, int] = {}
        self._device_drive_map: dict[int, DrivePath] = {}
        for i, drive in enumerate(self._drives):
            self._device_drive_map[i] = drive

    @property
    def ready(self) -> bool:
        return self._ready

    @property
    def open_handles(self) -> dict[int, IOBase]:
        return self._open_handles

    async def handle_message(self, data: bytes) -> None:
        if len(data) < 4:
            return
        component = struct.unpack_from("<H", data, 0)[0]
        packet_id = struct.unpack_from("<H", data, 2)[0]
        body = data[4:]

        if packet_id == PAKID_CORE_SERVER_ANNOUNCE:
            await self._handle_server_announce(body)
        elif packet_id == PAKID_CORE_DEVICE_IOREQUEST:
            await self._handle_io_request(body)

    async def _handle_server_announce(self, body: bytes) -> None:
        announce = ServerAnnouncePdu.parse(body)
        reply = ClientAnnounceReplyPdu(
            version_major=announce.version_major,
            version_minor=announce.version_minor,
            client_id=announce.client_id,
        )
        await self._send_fn(reply.serialize())
        name_req = ClientNameRequestPdu(computer_name=self._client_name)
        await self._send_fn(name_req.serialize())
        await self._send_device_list()
        self._ready = True

    async def _send_device_list(self) -> None:
        drives_list: list[tuple[int, str, str]] = []
        for device_id, drive in self._device_drive_map.items():
            drives_list.append((device_id, drive.name, drive.path))
        pdu = ClientDeviceListAnnouncePdu(drives=drives_list)
        await self._send_fn(pdu.serialize())

    async def _handle_io_request(self, body: bytes) -> None:
        request = DeviceIoRequestPdu.parse(body)
        if request.major_function == IRP_MJ_CREATE:
            await self._handle_create(request)
        elif request.major_function == IRP_MJ_CLOSE:
            await self._handle_close(request)
        elif request.major_function == IRP_MJ_READ:
            await self._handle_read(request)
        elif request.major_function == IRP_MJ_WRITE:
            await self._handle_write(request)
        elif request.major_function == IRP_MJ_QUERY_INFORMATION:
            await self._handle_query_information(request)
        elif request.major_function == IRP_MJ_SET_INFORMATION:
            await self._handle_set_information(request)
        elif request.major_function == IRP_MJ_DIRECTORY_CONTROL:
            await self._handle_directory_control(request)
        else:
            response = DeviceIoResponsePdu(
                device_id=request.device_id,
                completion_id=request.completion_id,
                io_status=STATUS_NOT_IMPLEMENTED,
            )
            await self._send_fn(response.serialize())

    def _get_drive_for_device(self, device_id: int) -> DrivePath | None:
        return self._device_drive_map.get(device_id)

    def _resolve_path(self, drive: DrivePath, relative_path: str) -> str:
        cleaned = relative_path.replace("\\", "/").lstrip("/")
        if not cleaned or cleaned == ".":
            return drive.path
        full = os.path.normpath(os.path.join(drive.path, cleaned))
        if not full.startswith(os.path.normpath(drive.path)):
            return drive.path
        return full

    async def _handle_create(self, request: DeviceIoRequestPdu) -> None:
        drive = self._get_drive_for_device(request.device_id)
        if drive is None:
            await self._send_error(request, STATUS_NO_SUCH_FILE)
            return

        payload = request.payload
        if len(payload) < 32:
            await self._send_error(request, STATUS_UNSUCCESSFUL)
            return

        desired_access = struct.unpack_from("<I", payload, 0)[0]
        _alloc_size = struct.unpack_from("<Q", payload, 4)[0]
        _file_attributes = struct.unpack_from("<I", payload, 12)[0]
        _shared_access = struct.unpack_from("<I", payload, 16)[0]
        create_disposition = struct.unpack_from("<I", payload, 20)[0]
        create_options = struct.unpack_from("<I", payload, 24)[0]
        path_length = struct.unpack_from("<I", payload, 28)[0]
        path_data = payload[32:32 + path_length]
        relative_path = path_data.decode("utf-16-le", errors="replace").rstrip("\x00")

        full_path = self._resolve_path(drive, relative_path)
        is_directory = bool(create_options & FILE_DIRECTORY_FILE)
        wants_write = bool(desired_access & FILE_WRITE_DATA)

        if wants_write and drive.read_only:
            await self._send_error(request, STATUS_ACCESS_DENIED)
            return

        try:
            if is_directory:
                if not os.path.isdir(full_path):
                    if create_disposition in (FILE_CREATE, FILE_OPEN_IF, FILE_OVERWRITE_IF):
                        if drive.read_only:
                            await self._send_error(request, STATUS_ACCESS_DENIED)
                            return
                        os.makedirs(full_path, exist_ok=True)
                    else:
                        await self._send_error(request, STATUS_OBJECT_NAME_NOT_FOUND)
                        return
                file_id = self._next_handle_id
                self._next_handle_id += 1
                self._handle_paths[file_id] = full_path
                self._handle_device[file_id] = request.device_id
            else:
                if create_disposition == FILE_OPEN:
                    if not os.path.exists(full_path):
                        await self._send_error(request, STATUS_OBJECT_NAME_NOT_FOUND)
                        return
                    mode = "rb" if not wants_write else "r+b"
                elif create_disposition == FILE_CREATE:
                    if drive.read_only:
                        await self._send_error(request, STATUS_ACCESS_DENIED)
                        return
                    mode = "xb"
                elif create_disposition in (FILE_OPEN_IF, FILE_OVERWRITE_IF, FILE_SUPERSEDE):
                    if drive.read_only and not os.path.exists(full_path):
                        await self._send_error(request, STATUS_ACCESS_DENIED)
                        return
                    if os.path.exists(full_path):
                        mode = "rb" if not wants_write else "r+b"
                    else:
                        if drive.read_only:
                            await self._send_error(request, STATUS_ACCESS_DENIED)
                            return
                        mode = "w+b"
                elif create_disposition == FILE_OVERWRITE:
                    if drive.read_only:
                        await self._send_error(request, STATUS_ACCESS_DENIED)
                        return
                    if not os.path.exists(full_path):
                        await self._send_error(request, STATUS_OBJECT_NAME_NOT_FOUND)
                        return
                    mode = "w+b"
                else:
                    mode = "rb"

                fh = open(full_path, mode)
                file_id = self._next_handle_id
                self._next_handle_id += 1
                self._open_handles[file_id] = fh
                self._handle_paths[file_id] = full_path
                self._handle_device[file_id] = request.device_id

        except FileNotFoundError:
            await self._send_error(request, STATUS_OBJECT_NAME_NOT_FOUND)
            return
        except PermissionError:
            await self._send_error(request, STATUS_ACCESS_DENIED)
            return
        except OSError:
            await self._send_error(request, STATUS_UNSUCCESSFUL)
            return

        resp_payload = struct.pack("<I", file_id) + b"\x00"
        response = DeviceIoResponsePdu(
            device_id=request.device_id,
            completion_id=request.completion_id,
            io_status=STATUS_SUCCESS,
            payload=resp_payload,
        )
        await self._send_fn(response.serialize())

    async def _handle_close(self, request: DeviceIoRequestPdu) -> None:
        file_id = request.file_id
        if file_id in self._open_handles:
            try:
                self._open_handles[file_id].close()
            except OSError:
                pass
            del self._open_handles[file_id]
        self._handle_paths.pop(file_id, None)
        self._handle_device.pop(file_id, None)

        response = DeviceIoResponsePdu(
            device_id=request.device_id,
            completion_id=request.completion_id,
            io_status=STATUS_SUCCESS,
        )
        await self._send_fn(response.serialize())

    async def _handle_read(self, request: DeviceIoRequestPdu) -> None:
        file_id = request.file_id
        fh = self._open_handles.get(file_id)
        if fh is None:
            await self._send_error(request, STATUS_NO_SUCH_FILE)
            return

        payload = request.payload
        if len(payload) < 12:
            await self._send_error(request, STATUS_UNSUCCESSFUL)
            return

        length = struct.unpack_from("<I", payload, 0)[0]
        offset = struct.unpack_from("<Q", payload, 4)[0]

        try:
            fh.seek(offset)
            data = fh.read(length)
        except OSError:
            await self._send_error(request, STATUS_UNSUCCESSFUL)
            return

        resp_payload = struct.pack("<I", len(data)) + data
        response = DeviceIoResponsePdu(
            device_id=request.device_id,
            completion_id=request.completion_id,
            io_status=STATUS_SUCCESS,
            payload=resp_payload,
        )
        await self._send_fn(response.serialize())

    async def _handle_write(self, request: DeviceIoRequestPdu) -> None:
        file_id = request.file_id
        device_id = request.device_id
        drive = self._get_drive_for_device(device_id)

        if drive and drive.read_only:
            await self._send_error(request, STATUS_ACCESS_DENIED)
            return

        fh = self._open_handles.get(file_id)
        if fh is None:
            await self._send_error(request, STATUS_NO_SUCH_FILE)
            return

        payload = request.payload
        if len(payload) < 32:
            await self._send_error(request, STATUS_UNSUCCESSFUL)
            return

        length = struct.unpack_from("<I", payload, 0)[0]
        offset = struct.unpack_from("<Q", payload, 4)[0]
        write_data = payload[32:32 + length]

        try:
            fh.seek(offset)
            written = fh.write(write_data)
            fh.flush()
        except OSError:
            await self._send_error(request, STATUS_UNSUCCESSFUL)
            return

        resp_payload = struct.pack("<I", written) + b"\x00"
        response = DeviceIoResponsePdu(
            device_id=request.device_id,
            completion_id=request.completion_id,
            io_status=STATUS_SUCCESS,
            payload=resp_payload,
        )
        await self._send_fn(response.serialize())

    async def _handle_query_information(self, request: DeviceIoRequestPdu) -> None:
        file_id = request.file_id
        path = self._handle_paths.get(file_id)
        if path is None:
            await self._send_error(request, STATUS_NO_SUCH_FILE)
            return

        payload = request.payload
        if len(payload) < 4:
            await self._send_error(request, STATUS_UNSUCCESSFUL)
            return

        info_class = struct.unpack_from("<I", payload, 0)[0]

        try:
            stat = os.stat(path)
        except FileNotFoundError:
            await self._send_error(request, STATUS_OBJECT_NAME_NOT_FOUND)
            return
        except OSError:
            await self._send_error(request, STATUS_UNSUCCESSFUL)
            return

        if info_class == FileBasicInformation:
            resp_data = struct.pack("<QQQQII", 0, 0, 0, 0, 0, 0)
        elif info_class == FileStandardInformation:
            is_dir = 1 if os.path.isdir(path) else 0
            resp_data = struct.pack("<QQIBB", stat.st_size, stat.st_size, 1, is_dir, 0)
        else:
            resp_data = b""

        resp_payload = struct.pack("<I", len(resp_data)) + resp_data
        response = DeviceIoResponsePdu(
            device_id=request.device_id,
            completion_id=request.completion_id,
            io_status=STATUS_SUCCESS,
            payload=resp_payload,
        )
        await self._send_fn(response.serialize())

    async def _handle_set_information(self, request: DeviceIoRequestPdu) -> None:
        device_id = request.device_id
        drive = self._get_drive_for_device(device_id)

        if drive and drive.read_only:
            await self._send_error(request, STATUS_ACCESS_DENIED)
            return

        response = DeviceIoResponsePdu(
            device_id=request.device_id,
            completion_id=request.completion_id,
            io_status=STATUS_SUCCESS,
        )
        await self._send_fn(response.serialize())

    async def _handle_directory_control(self, request: DeviceIoRequestPdu) -> None:
        file_id = request.file_id
        path = self._handle_paths.get(file_id)
        if path is None:
            await self._send_error(request, STATUS_NO_SUCH_FILE)
            return

        if not os.path.isdir(path):
            await self._send_error(request, STATUS_NO_SUCH_FILE)
            return

        try:
            entries = os.listdir(path)
        except PermissionError:
            await self._send_error(request, STATUS_ACCESS_DENIED)
            return
        except OSError:
            await self._send_error(request, STATUS_UNSUCCESSFUL)
            return

        entry_data = bytearray()
        for entry_name in entries:
            name_encoded = entry_name.encode("utf-16-le") + b"\x00\x00"
            entry_data.extend(struct.pack("<I", len(name_encoded)))
            entry_data.extend(name_encoded)

        resp_payload = struct.pack("<I", len(entry_data)) + bytes(entry_data)
        response = DeviceIoResponsePdu(
            device_id=request.device_id,
            completion_id=request.completion_id,
            io_status=STATUS_SUCCESS,
            payload=resp_payload,
        )
        await self._send_fn(response.serialize())

    async def _send_error(self, request: DeviceIoRequestPdu, status: int) -> None:
        response = DeviceIoResponsePdu(
            device_id=request.device_id,
            completion_id=request.completion_id,
            io_status=status,
        )
        await self._send_fn(response.serialize())
