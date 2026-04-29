"""Tests for the drive redirection channel (RDPDR).

Tests cover: device list announce, read-only enforcement,
I/O request handling, and error code mapping.
"""

from __future__ import annotations

import os
import struct
import tempfile
from unittest.mock import AsyncMock

import pytest

from arrdipi.channels.drive import (
    ClientAnnounceReplyPdu,
    ClientDeviceListAnnouncePdu,
    ClientNameRequestPdu,
    DeviceIoRequestPdu,
    DeviceIoResponsePdu,
    DriveChannel,
    FILE_OPEN,
    FILE_OPEN_IF,
    FILE_READ_DATA,
    FILE_WRITE_DATA,
    IRP_MJ_CLOSE,
    IRP_MJ_CREATE,
    IRP_MJ_DIRECTORY_CONTROL,
    IRP_MJ_QUERY_INFORMATION,
    IRP_MJ_READ,
    IRP_MJ_SET_INFORMATION,
    IRP_MJ_WRITE,
    PAKID_CORE_CLIENT_ANNOUNCE_REPLY,
    PAKID_CORE_CLIENT_NAME_REQUEST,
    PAKID_CORE_DEVICE_IOCOMPLETION,
    PAKID_CORE_DEVICE_IOREQUEST,
    PAKID_CORE_DEVICE_LIST_ANNOUNCE,
    PAKID_CORE_SERVER_ANNOUNCE,
    RDPDR_CTYP_CORE,
    RDPDR_DTYP_FILESYSTEM,
    STATUS_ACCESS_DENIED,
    STATUS_NO_SUCH_FILE,
    STATUS_NOT_IMPLEMENTED,
    STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_SUCCESS,
    ServerAnnouncePdu,
)
from arrdipi.connection import DrivePath


def _make_server_announce(major: int = 1, minor: int = 12, client_id: int = 1) -> bytes:
    """Build a Server Announce PDU."""
    header = struct.pack("<HH", RDPDR_CTYP_CORE, PAKID_CORE_SERVER_ANNOUNCE)
    body = struct.pack("<HHI", major, minor, client_id)
    return header + body


def _make_io_request(
    device_id: int,
    file_id: int,
    completion_id: int,
    major_function: int,
    minor_function: int = 0,
    payload: bytes = b"",
) -> bytes:
    """Build a Device I/O Request PDU."""
    header = struct.pack("<HH", RDPDR_CTYP_CORE, PAKID_CORE_DEVICE_IOREQUEST)
    body = struct.pack(
        "<IIIII",
        device_id,
        file_id,
        completion_id,
        major_function,
        minor_function,
    )
    return header + body + payload


def _make_create_payload(
    path: str,
    desired_access: int = FILE_READ_DATA,
    create_disposition: int = FILE_OPEN,
    create_options: int = 0,
) -> bytes:
    """Build the payload for an IRP_MJ_CREATE request."""
    path_encoded = path.encode("utf-16-le") + b"\x00\x00"
    return struct.pack(
        "<IQIIIII",
        desired_access,
        0,  # alloc_size
        0,  # file_attributes
        0,  # shared_access
        create_disposition,
        create_options,
        len(path_encoded),
    ) + path_encoded


def _make_read_payload(length: int, offset: int = 0) -> bytes:
    """Build the payload for an IRP_MJ_READ request."""
    return struct.pack("<IQ", length, offset) + b"\x00" * 20


def _make_write_payload(data: bytes, offset: int = 0) -> bytes:
    """Build the payload for an IRP_MJ_WRITE request."""
    header = struct.pack("<IQ", len(data), offset)
    padding = b"\x00" * 20
    return header + padding + data


class TestServerAnnouncePdu:
    """Tests for ServerAnnouncePdu parse/serialize."""

    def test_parse(self) -> None:
        data = struct.pack("<HHI", 1, 12, 42)
        pdu = ServerAnnouncePdu.parse(data)
        assert pdu.version_major == 1
        assert pdu.version_minor == 12
        assert pdu.client_id == 42

    def test_serialize(self) -> None:
        pdu = ServerAnnouncePdu(version_major=1, version_minor=12, client_id=5)
        raw = pdu.serialize()
        assert struct.unpack_from("<HH", raw, 0) == (RDPDR_CTYP_CORE, PAKID_CORE_SERVER_ANNOUNCE)
        assert struct.unpack_from("<HHI", raw, 4) == (1, 12, 5)


class TestClientAnnounceReplyPdu:
    """Tests for ClientAnnounceReplyPdu."""

    def test_serialize(self) -> None:
        pdu = ClientAnnounceReplyPdu(version_major=1, version_minor=12, client_id=7)
        raw = pdu.serialize()
        assert struct.unpack_from("<HH", raw, 0) == (RDPDR_CTYP_CORE, PAKID_CORE_CLIENT_ANNOUNCE_REPLY)

    def test_parse_roundtrip(self) -> None:
        pdu = ClientAnnounceReplyPdu(version_major=1, version_minor=6, client_id=99)
        raw = pdu.serialize()
        parsed = ClientAnnounceReplyPdu.parse(raw[4:])
        assert parsed.version_major == 1
        assert parsed.version_minor == 6
        assert parsed.client_id == 99


class TestClientNameRequestPdu:
    """Tests for ClientNameRequestPdu."""

    def test_serialize(self) -> None:
        pdu = ClientNameRequestPdu(computer_name="MYPC")
        raw = pdu.serialize()
        assert struct.unpack_from("<HH", raw, 0) == (RDPDR_CTYP_CORE, PAKID_CORE_CLIENT_NAME_REQUEST)

    def test_parse_roundtrip(self) -> None:
        pdu = ClientNameRequestPdu(computer_name="TestPC")
        raw = pdu.serialize()
        parsed = ClientNameRequestPdu.parse(raw[4:])
        assert parsed.computer_name == "TestPC"


class TestClientDeviceListAnnouncePdu:
    """Tests for ClientDeviceListAnnouncePdu."""

    def test_serialize_with_drives(self) -> None:
        pdu = ClientDeviceListAnnouncePdu(drives=[(0, "C", "/tmp"), (1, "D", "/home")])
        raw = pdu.serialize()
        assert struct.unpack_from("<HH", raw, 0) == (RDPDR_CTYP_CORE, PAKID_CORE_DEVICE_LIST_ANNOUNCE)
        count = struct.unpack_from("<I", raw, 4)[0]
        assert count == 2

    def test_serialize_empty(self) -> None:
        pdu = ClientDeviceListAnnouncePdu(drives=[])
        raw = pdu.serialize()
        count = struct.unpack_from("<I", raw, 4)[0]
        assert count == 0


class TestDeviceIoRequestPdu:
    """Tests for DeviceIoRequestPdu."""

    def test_parse(self) -> None:
        data = struct.pack("<IIIII", 1, 2, 3, IRP_MJ_READ, 0) + b"\x01\x02"
        pdu = DeviceIoRequestPdu.parse(data)
        assert pdu.device_id == 1
        assert pdu.file_id == 2
        assert pdu.completion_id == 3
        assert pdu.major_function == IRP_MJ_READ
        assert pdu.payload == b"\x01\x02"


class TestDeviceIoResponsePdu:
    """Tests for DeviceIoResponsePdu."""

    def test_serialize(self) -> None:
        pdu = DeviceIoResponsePdu(device_id=1, completion_id=5, io_status=STATUS_SUCCESS, payload=b"\xAA")
        raw = pdu.serialize()
        assert struct.unpack_from("<HH", raw, 0) == (RDPDR_CTYP_CORE, PAKID_CORE_DEVICE_IOCOMPLETION)
        assert struct.unpack_from("<III", raw, 4) == (1, 5, STATUS_SUCCESS)
        assert raw[16:] == b"\xAA"

    def test_parse(self) -> None:
        data = struct.pack("<III", 2, 10, STATUS_ACCESS_DENIED) + b"\xBB"
        pdu = DeviceIoResponsePdu.parse(data)
        assert pdu.device_id == 2
        assert pdu.completion_id == 10
        assert pdu.io_status == STATUS_ACCESS_DENIED
        assert pdu.payload == b"\xBB"


class TestDriveChannelServerAnnounce:
    """Tests for DriveChannel handling Server Announce."""

    @pytest.mark.asyncio
    async def test_server_announce_sends_reply_and_name_and_device_list(self) -> None:
        """Server Announce triggers Client Announce Reply + Name Request + Device List."""
        send_fn = AsyncMock()
        drives = [DrivePath(name="C", path="/tmp", read_only=False)]
        channel = DriveChannel(send_fn=send_fn, drives=drives)

        announce_data = _make_server_announce(client_id=42)
        await channel.handle_message(announce_data)

        assert channel.ready is True
        assert send_fn.call_count == 3

        # First call: Client Announce Reply
        reply_data = send_fn.call_args_list[0][0][0]
        assert struct.unpack_from("<HH", reply_data, 0) == (RDPDR_CTYP_CORE, PAKID_CORE_CLIENT_ANNOUNCE_REPLY)

        # Second call: Client Name Request
        name_data = send_fn.call_args_list[1][0][0]
        assert struct.unpack_from("<HH", name_data, 0) == (RDPDR_CTYP_CORE, PAKID_CORE_CLIENT_NAME_REQUEST)

        # Third call: Device List Announce
        list_data = send_fn.call_args_list[2][0][0]
        assert struct.unpack_from("<HH", list_data, 0) == (RDPDR_CTYP_CORE, PAKID_CORE_DEVICE_LIST_ANNOUNCE)
        count = struct.unpack_from("<I", list_data, 4)[0]
        assert count == 1


class TestDriveChannelDeviceList:
    """Tests for device list announce with configured drives."""

    @pytest.mark.asyncio
    async def test_multiple_drives_announced(self) -> None:
        """Multiple drives are included in the device list."""
        send_fn = AsyncMock()
        drives = [
            DrivePath(name="C", path="/tmp/c", read_only=False),
            DrivePath(name="D", path="/tmp/d", read_only=True),
        ]
        channel = DriveChannel(send_fn=send_fn, drives=drives)

        await channel.handle_message(_make_server_announce())

        list_data = send_fn.call_args_list[2][0][0]
        count = struct.unpack_from("<I", list_data, 4)[0]
        assert count == 2

    @pytest.mark.asyncio
    async def test_no_drives_announced(self) -> None:
        """Empty drive list results in count=0."""
        send_fn = AsyncMock()
        channel = DriveChannel(send_fn=send_fn, drives=[])

        await channel.handle_message(_make_server_announce())

        list_data = send_fn.call_args_list[2][0][0]
        count = struct.unpack_from("<I", list_data, 4)[0]
        assert count == 0


class TestDriveChannelReadOnly:
    """Tests for read-only enforcement."""

    @pytest.mark.asyncio
    async def test_write_denied_on_read_only_drive(self) -> None:
        """Write access is denied on a read-only drive."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file to open
            test_file = os.path.join(tmpdir, "test.txt")
            with open(test_file, "w") as f:
                f.write("hello")

            send_fn = AsyncMock()
            drives = [DrivePath(name="C", path=tmpdir, read_only=True)]
            channel = DriveChannel(send_fn=send_fn, drives=drives)
            await channel.handle_message(_make_server_announce())
            send_fn.reset_mock()

            # Try to create with write access
            create_payload = _make_create_payload(
                "test.txt",
                desired_access=FILE_WRITE_DATA,
                create_disposition=FILE_OPEN,
            )
            io_request = _make_io_request(0, 0, 1, IRP_MJ_CREATE, payload=create_payload)
            await channel.handle_message(io_request)

            response_data = send_fn.call_args[0][0]
            io_status = struct.unpack_from("<I", response_data, 12)[0]
            assert io_status == STATUS_ACCESS_DENIED

    @pytest.mark.asyncio
    async def test_write_io_denied_on_read_only_drive(self) -> None:
        """IRP_MJ_WRITE is denied on a read-only drive."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.txt")
            with open(test_file, "w") as f:
                f.write("hello")

            send_fn = AsyncMock()
            drives = [DrivePath(name="C", path=tmpdir, read_only=True)]
            channel = DriveChannel(send_fn=send_fn, drives=drives)
            await channel.handle_message(_make_server_announce())
            send_fn.reset_mock()

            # Open file for read (should succeed)
            create_payload = _make_create_payload(
                "test.txt",
                desired_access=FILE_READ_DATA,
                create_disposition=FILE_OPEN,
            )
            io_request = _make_io_request(0, 0, 1, IRP_MJ_CREATE, payload=create_payload)
            await channel.handle_message(io_request)

            response_data = send_fn.call_args[0][0]
            io_status = struct.unpack_from("<I", response_data, 12)[0]
            assert io_status == STATUS_SUCCESS

            # Extract file_id from response
            file_id = struct.unpack_from("<I", response_data, 16)[0]

            send_fn.reset_mock()

            # Try to write
            write_payload = _make_write_payload(b"new data")
            io_request = _make_io_request(0, file_id, 2, IRP_MJ_WRITE, payload=write_payload)
            await channel.handle_message(io_request)

            response_data = send_fn.call_args[0][0]
            io_status = struct.unpack_from("<I", response_data, 12)[0]
            assert io_status == STATUS_ACCESS_DENIED

    @pytest.mark.asyncio
    async def test_read_allowed_on_read_only_drive(self) -> None:
        """Read access is allowed on a read-only drive."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.txt")
            with open(test_file, "wb") as f:
                f.write(b"hello world")

            send_fn = AsyncMock()
            drives = [DrivePath(name="C", path=tmpdir, read_only=True)]
            channel = DriveChannel(send_fn=send_fn, drives=drives)
            await channel.handle_message(_make_server_announce())
            send_fn.reset_mock()

            # Open file for read
            create_payload = _make_create_payload(
                "test.txt",
                desired_access=FILE_READ_DATA,
                create_disposition=FILE_OPEN,
            )
            io_request = _make_io_request(0, 0, 1, IRP_MJ_CREATE, payload=create_payload)
            await channel.handle_message(io_request)

            response_data = send_fn.call_args[0][0]
            io_status = struct.unpack_from("<I", response_data, 12)[0]
            assert io_status == STATUS_SUCCESS


class TestDriveChannelIoRequests:
    """Tests for I/O request handling."""

    @pytest.mark.asyncio
    async def test_create_read_close_lifecycle(self) -> None:
        """Full lifecycle: create, read, close."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "data.bin")
            with open(test_file, "wb") as f:
                f.write(b"ABCDEFGH")

            send_fn = AsyncMock()
            drives = [DrivePath(name="C", path=tmpdir, read_only=False)]
            channel = DriveChannel(send_fn=send_fn, drives=drives)
            await channel.handle_message(_make_server_announce())
            send_fn.reset_mock()

            # Create (open)
            create_payload = _make_create_payload(
                "data.bin",
                desired_access=FILE_READ_DATA,
                create_disposition=FILE_OPEN,
            )
            io_request = _make_io_request(0, 0, 1, IRP_MJ_CREATE, payload=create_payload)
            await channel.handle_message(io_request)

            response_data = send_fn.call_args[0][0]
            io_status = struct.unpack_from("<I", response_data, 12)[0]
            assert io_status == STATUS_SUCCESS
            file_id = struct.unpack_from("<I", response_data, 16)[0]

            send_fn.reset_mock()

            # Read
            read_payload = _make_read_payload(4, offset=2)
            io_request = _make_io_request(0, file_id, 2, IRP_MJ_READ, payload=read_payload)
            await channel.handle_message(io_request)

            response_data = send_fn.call_args[0][0]
            io_status = struct.unpack_from("<I", response_data, 12)[0]
            assert io_status == STATUS_SUCCESS
            data_len = struct.unpack_from("<I", response_data, 16)[0]
            assert data_len == 4
            read_data = response_data[20:20 + data_len]
            assert read_data == b"CDEF"

            send_fn.reset_mock()

            # Close
            io_request = _make_io_request(0, file_id, 3, IRP_MJ_CLOSE)
            await channel.handle_message(io_request)

            response_data = send_fn.call_args[0][0]
            io_status = struct.unpack_from("<I", response_data, 12)[0]
            assert io_status == STATUS_SUCCESS
            assert file_id not in channel.open_handles

    @pytest.mark.asyncio
    async def test_write_file(self) -> None:
        """Write data to a file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "output.bin")
            with open(test_file, "wb") as f:
                f.write(b"\x00" * 16)

            send_fn = AsyncMock()
            drives = [DrivePath(name="C", path=tmpdir, read_only=False)]
            channel = DriveChannel(send_fn=send_fn, drives=drives)
            await channel.handle_message(_make_server_announce())
            send_fn.reset_mock()

            # Open for write
            create_payload = _make_create_payload(
                "output.bin",
                desired_access=FILE_WRITE_DATA,
                create_disposition=FILE_OPEN,
            )
            io_request = _make_io_request(0, 0, 1, IRP_MJ_CREATE, payload=create_payload)
            await channel.handle_message(io_request)

            response_data = send_fn.call_args[0][0]
            file_id = struct.unpack_from("<I", response_data, 16)[0]
            send_fn.reset_mock()

            # Write
            write_payload = _make_write_payload(b"HELLO", offset=0)
            io_request = _make_io_request(0, file_id, 2, IRP_MJ_WRITE, payload=write_payload)
            await channel.handle_message(io_request)

            response_data = send_fn.call_args[0][0]
            io_status = struct.unpack_from("<I", response_data, 12)[0]
            assert io_status == STATUS_SUCCESS
            written = struct.unpack_from("<I", response_data, 16)[0]
            assert written == 5

            # Verify file content
            with open(test_file, "rb") as f:
                content = f.read()
            assert content[:5] == b"HELLO"

    @pytest.mark.asyncio
    async def test_query_information(self) -> None:
        """Query file information returns success."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "info.txt")
            with open(test_file, "wb") as f:
                f.write(b"test content")

            send_fn = AsyncMock()
            drives = [DrivePath(name="C", path=tmpdir, read_only=False)]
            channel = DriveChannel(send_fn=send_fn, drives=drives)
            await channel.handle_message(_make_server_announce())
            send_fn.reset_mock()

            # Open file
            create_payload = _make_create_payload("info.txt", create_disposition=FILE_OPEN)
            io_request = _make_io_request(0, 0, 1, IRP_MJ_CREATE, payload=create_payload)
            await channel.handle_message(io_request)

            response_data = send_fn.call_args[0][0]
            file_id = struct.unpack_from("<I", response_data, 16)[0]
            send_fn.reset_mock()

            # Query information (FileStandardInformation = 5)
            query_payload = struct.pack("<I", 5) + b"\x00" * 20
            io_request = _make_io_request(0, file_id, 2, IRP_MJ_QUERY_INFORMATION, payload=query_payload)
            await channel.handle_message(io_request)

            response_data = send_fn.call_args[0][0]
            io_status = struct.unpack_from("<I", response_data, 12)[0]
            assert io_status == STATUS_SUCCESS

    @pytest.mark.asyncio
    async def test_directory_control(self) -> None:
        """Directory listing returns entries."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create some files
            open(os.path.join(tmpdir, "file1.txt"), "w").close()
            open(os.path.join(tmpdir, "file2.txt"), "w").close()

            send_fn = AsyncMock()
            drives = [DrivePath(name="C", path=tmpdir, read_only=False)]
            channel = DriveChannel(send_fn=send_fn, drives=drives)
            await channel.handle_message(_make_server_announce())
            send_fn.reset_mock()

            # Open directory
            from arrdipi.channels.drive import FILE_DIRECTORY_FILE
            create_payload = _make_create_payload(
                "",
                desired_access=FILE_READ_DATA,
                create_disposition=FILE_OPEN,
                create_options=FILE_DIRECTORY_FILE,
            )
            io_request = _make_io_request(0, 0, 1, IRP_MJ_CREATE, payload=create_payload)
            await channel.handle_message(io_request)

            response_data = send_fn.call_args[0][0]
            io_status = struct.unpack_from("<I", response_data, 12)[0]
            assert io_status == STATUS_SUCCESS
            file_id = struct.unpack_from("<I", response_data, 16)[0]
            send_fn.reset_mock()

            # Query directory
            io_request = _make_io_request(0, file_id, 2, IRP_MJ_DIRECTORY_CONTROL)
            await channel.handle_message(io_request)

            response_data = send_fn.call_args[0][0]
            io_status = struct.unpack_from("<I", response_data, 12)[0]
            assert io_status == STATUS_SUCCESS


class TestDriveChannelErrorCodes:
    """Tests for NTSTATUS error code mapping."""

    @pytest.mark.asyncio
    async def test_file_not_found(self) -> None:
        """Opening a non-existent file returns STATUS_OBJECT_NAME_NOT_FOUND."""
        with tempfile.TemporaryDirectory() as tmpdir:
            send_fn = AsyncMock()
            drives = [DrivePath(name="C", path=tmpdir, read_only=False)]
            channel = DriveChannel(send_fn=send_fn, drives=drives)
            await channel.handle_message(_make_server_announce())
            send_fn.reset_mock()

            create_payload = _make_create_payload(
                "nonexistent.txt",
                desired_access=FILE_READ_DATA,
                create_disposition=FILE_OPEN,
            )
            io_request = _make_io_request(0, 0, 1, IRP_MJ_CREATE, payload=create_payload)
            await channel.handle_message(io_request)

            response_data = send_fn.call_args[0][0]
            io_status = struct.unpack_from("<I", response_data, 12)[0]
            assert io_status == STATUS_OBJECT_NAME_NOT_FOUND

    @pytest.mark.asyncio
    async def test_unsupported_major_function(self) -> None:
        """Unsupported major function returns STATUS_NOT_IMPLEMENTED."""
        send_fn = AsyncMock()
        drives = [DrivePath(name="C", path="/tmp", read_only=False)]
        channel = DriveChannel(send_fn=send_fn, drives=drives)
        await channel.handle_message(_make_server_announce())
        send_fn.reset_mock()

        # Use an unsupported major function (99)
        io_request = _make_io_request(0, 0, 1, 99)
        await channel.handle_message(io_request)

        response_data = send_fn.call_args[0][0]
        io_status = struct.unpack_from("<I", response_data, 12)[0]
        assert io_status == STATUS_NOT_IMPLEMENTED

    @pytest.mark.asyncio
    async def test_read_invalid_handle(self) -> None:
        """Reading from an invalid file handle returns STATUS_NO_SUCH_FILE."""
        send_fn = AsyncMock()
        drives = [DrivePath(name="C", path="/tmp", read_only=False)]
        channel = DriveChannel(send_fn=send_fn, drives=drives)
        await channel.handle_message(_make_server_announce())
        send_fn.reset_mock()

        read_payload = _make_read_payload(10)
        io_request = _make_io_request(0, 999, 1, IRP_MJ_READ, payload=read_payload)
        await channel.handle_message(io_request)

        response_data = send_fn.call_args[0][0]
        io_status = struct.unpack_from("<I", response_data, 12)[0]
        assert io_status == STATUS_NO_SUCH_FILE

    @pytest.mark.asyncio
    async def test_set_information_read_only(self) -> None:
        """Set information on read-only drive returns STATUS_ACCESS_DENIED."""
        send_fn = AsyncMock()
        drives = [DrivePath(name="C", path="/tmp", read_only=True)]
        channel = DriveChannel(send_fn=send_fn, drives=drives)
        await channel.handle_message(_make_server_announce())
        send_fn.reset_mock()

        io_request = _make_io_request(0, 0, 1, IRP_MJ_SET_INFORMATION)
        await channel.handle_message(io_request)

        response_data = send_fn.call_args[0][0]
        io_status = struct.unpack_from("<I", response_data, 12)[0]
        assert io_status == STATUS_ACCESS_DENIED
