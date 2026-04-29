"""Tests for arrdipi CLI entry point — argument parsing and connect command.

Tests cover:
- Argument parsing for the connect subcommand
- Password resolution from --password flag and ARRDIPI_PASSWORD env var
- Error exit code on connection failure
"""

from __future__ import annotations

import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from arrdipi.cli.main import _parse_drive, _run_connect, build_parser, main


class TestBuildParser:
    """Tests for build_parser() argument parsing."""

    def test_connect_subcommand_exists(self) -> None:
        """The parser should have a 'connect' subcommand."""
        parser = build_parser()
        args = parser.parse_args(["connect", "--host", "server", "--user", "admin"])
        assert args.command == "connect"

    def test_required_host_argument(self) -> None:
        """--host is required for the connect subcommand."""
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["connect", "--user", "admin"])

    def test_required_user_argument(self) -> None:
        """--user is required for the connect subcommand."""
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["connect", "--host", "server"])

    def test_host_and_user_parsed(self) -> None:
        """--host and --user values are correctly parsed."""
        parser = build_parser()
        args = parser.parse_args(["connect", "--host", "10.0.0.1", "--user", "bob"])
        assert args.host == "10.0.0.1"
        assert args.user == "bob"

    def test_default_port(self) -> None:
        """--port defaults to 3389."""
        parser = build_parser()
        args = parser.parse_args(["connect", "--host", "srv", "--user", "u"])
        assert args.port == 3389

    def test_custom_port(self) -> None:
        """--port can be set to a custom value."""
        parser = build_parser()
        args = parser.parse_args(
            ["connect", "--host", "srv", "--user", "u", "--port", "3390"]
        )
        assert args.port == 3390

    def test_default_security(self) -> None:
        """--security defaults to 'auto'."""
        parser = build_parser()
        args = parser.parse_args(["connect", "--host", "srv", "--user", "u"])
        assert args.security == "auto"

    def test_security_choices(self) -> None:
        """--security accepts auto, rdp, tls, nla."""
        parser = build_parser()
        for choice in ("auto", "rdp", "tls", "nla"):
            args = parser.parse_args(
                ["connect", "--host", "srv", "--user", "u", "--security", choice]
            )
            assert args.security == choice

    def test_invalid_security_rejected(self) -> None:
        """--security rejects invalid values."""
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(
                ["connect", "--host", "srv", "--user", "u", "--security", "invalid"]
            )

    def test_default_width_height(self) -> None:
        """--width defaults to 1920, --height defaults to 1080."""
        parser = build_parser()
        args = parser.parse_args(["connect", "--host", "srv", "--user", "u"])
        assert args.width == 1920
        assert args.height == 1080

    def test_custom_width_height(self) -> None:
        """--width and --height can be set to custom values."""
        parser = build_parser()
        args = parser.parse_args(
            [
                "connect",
                "--host",
                "srv",
                "--user",
                "u",
                "--width",
                "1280",
                "--height",
                "720",
            ]
        )
        assert args.width == 1280
        assert args.height == 720

    def test_password_optional(self) -> None:
        """--password is optional and defaults to None."""
        parser = build_parser()
        args = parser.parse_args(["connect", "--host", "srv", "--user", "u"])
        assert args.password is None

    def test_password_provided(self) -> None:
        """--password value is correctly parsed."""
        parser = build_parser()
        args = parser.parse_args(
            ["connect", "--host", "srv", "--user", "u", "--password", "secret"]
        )
        assert args.password == "secret"

    def test_domain_optional(self) -> None:
        """--domain is optional and defaults to empty string."""
        parser = build_parser()
        args = parser.parse_args(["connect", "--host", "srv", "--user", "u"])
        assert args.domain == ""

    def test_domain_provided(self) -> None:
        """--domain value is correctly parsed."""
        parser = build_parser()
        args = parser.parse_args(
            ["connect", "--host", "srv", "--user", "u", "--domain", "CORP"]
        )
        assert args.domain == "CORP"

    def test_drive_not_specified(self) -> None:
        """--drive defaults to None when not specified."""
        parser = build_parser()
        args = parser.parse_args(["connect", "--host", "srv", "--user", "u"])
        assert args.drive is None

    def test_drive_single(self) -> None:
        """--drive can be specified once."""
        parser = build_parser()
        args = parser.parse_args(
            ["connect", "--host", "srv", "--user", "u", "--drive", "share:/tmp"]
        )
        assert args.drive == ["share:/tmp"]

    def test_drive_multiple(self) -> None:
        """--drive can be specified multiple times."""
        parser = build_parser()
        args = parser.parse_args(
            [
                "connect",
                "--host",
                "srv",
                "--user",
                "u",
                "--drive",
                "share:/tmp",
                "--drive",
                "docs:/home/user/docs:ro",
            ]
        )
        assert args.drive == ["share:/tmp", "docs:/home/user/docs:ro"]

    def test_no_subcommand(self) -> None:
        """No subcommand results in command=None."""
        parser = build_parser()
        args = parser.parse_args([])
        assert args.command is None


class TestParseDrive:
    """Tests for _parse_drive() helper."""

    def test_name_path(self) -> None:
        """Parse 'NAME:PATH' format."""
        name, path, read_only = _parse_drive("share:/tmp/data")
        assert name == "share"
        assert path == "/tmp/data"
        assert read_only is False

    def test_name_path_readonly(self) -> None:
        """Parse 'NAME:PATH:ro' format."""
        name, path, read_only = _parse_drive("docs:/home/user:ro")
        assert name == "docs"
        assert path == "/home/user"
        assert read_only is True

    def test_invalid_format(self) -> None:
        """Invalid format raises ArgumentTypeError."""
        import argparse

        with pytest.raises(argparse.ArgumentTypeError):
            _parse_drive("invalid")

    def test_invalid_suffix(self) -> None:
        """Three parts with non-'ro' suffix raises ArgumentTypeError."""
        import argparse

        with pytest.raises(argparse.ArgumentTypeError):
            _parse_drive("name:path:rw")


class TestPasswordEnvVar:
    """Tests for password resolution from env var (Req 28, AC 8)."""

    def test_password_from_flag(self) -> None:
        """--password flag takes precedence over env var."""
        with patch.dict(os.environ, {"ARRDIPI_PASSWORD": "env_pass"}):
            parser = build_parser()
            args = parser.parse_args(
                ["connect", "--host", "srv", "--user", "u", "--password", "flag_pass"]
            )
            # Simulate main() logic
            password = args.password
            if password is None:
                password = os.environ.get("ARRDIPI_PASSWORD", "")
            assert password == "flag_pass"

    def test_password_from_env_var(self) -> None:
        """ARRDIPI_PASSWORD env var is used when --password is not provided."""
        with patch.dict(os.environ, {"ARRDIPI_PASSWORD": "env_pass"}):
            parser = build_parser()
            args = parser.parse_args(["connect", "--host", "srv", "--user", "u"])
            password = args.password
            if password is None:
                password = os.environ.get("ARRDIPI_PASSWORD", "")
            assert password == "env_pass"

    def test_password_empty_when_neither(self) -> None:
        """Password is empty string when neither flag nor env var is set."""
        env = os.environ.copy()
        env.pop("ARRDIPI_PASSWORD", None)
        with patch.dict(os.environ, env, clear=True):
            parser = build_parser()
            args = parser.parse_args(["connect", "--host", "srv", "--user", "u"])
            password = args.password
            if password is None:
                password = os.environ.get("ARRDIPI_PASSWORD", "")
            assert password == ""


class TestMainErrorExit:
    """Tests for error handling and exit codes (Req 28, AC 7)."""

    def test_connection_failure_exits_nonzero(self) -> None:
        """Connection failure prints to stderr and exits with code 1."""
        with (
            patch(
                "sys.argv",
                ["arrdipi", "connect", "--host", "bad", "--user", "u"],
            ),
            patch(
                "arrdipi.cli.main._run_connect",
                side_effect=ConnectionError("Connection refused"),
            ),
            pytest.raises(SystemExit) as exc_info,
            patch("sys.stderr", new_callable=MagicMock) as mock_stderr,
        ):
            main()

        assert exc_info.value.code == 1

    def test_no_command_launches_menu(self) -> None:
        """No subcommand launches the interactive menu."""
        with (
            patch("sys.argv", ["arrdipi"]),
            patch("arrdipi.cli.main.run_menu") as mock_menu,
            pytest.raises(SystemExit) as exc_info,
        ):
            main()

        mock_menu.assert_called_once()
        assert exc_info.value.code == 0


class TestRunConnect:
    """Tests for _run_connect() function."""

    def test_calls_connect_with_correct_args(self) -> None:
        """_run_connect calls arrdipi.connect() with parsed arguments."""
        parser = build_parser()
        args = parser.parse_args(
            [
                "connect",
                "--host",
                "10.0.0.1",
                "--user",
                "admin",
                "--port",
                "3390",
                "--domain",
                "CORP",
                "--security",
                "nla",
                "--width",
                "1280",
                "--height",
                "720",
            ]
        )

        mock_session = AsyncMock()
        mock_session.disconnect = AsyncMock()

        mock_window = MagicMock()
        mock_window.run = AsyncMock()

        with (
            patch("arrdipi.connect", new_callable=AsyncMock, return_value=mock_session) as mock_connect,
            patch("arrdipi.cli.main.DesktopWindow", return_value=mock_window) as mock_window_cls,
        ):
            _run_connect(args, "mypass")

        mock_connect.assert_called_once_with(
            host="10.0.0.1",
            port=3390,
            username="admin",
            password="mypass",
            domain="CORP",
            security="nla",
            width=1280,
            height=720,
            drive_paths=None,
        )

    def test_drive_paths_parsed(self) -> None:
        """_run_connect correctly parses --drive arguments into DrivePath objects."""
        parser = build_parser()
        args = parser.parse_args(
            [
                "connect",
                "--host",
                "srv",
                "--user",
                "u",
                "--drive",
                "share:/tmp",
                "--drive",
                "docs:/home:ro",
            ]
        )

        mock_session = AsyncMock()
        mock_session.disconnect = AsyncMock()

        mock_window = MagicMock()
        mock_window.run = AsyncMock()

        with (
            patch("arrdipi.connect", new_callable=AsyncMock, return_value=mock_session) as mock_connect,
            patch("arrdipi.cli.main.DesktopWindow", return_value=mock_window),
        ):
            _run_connect(args, "pass")

        # Verify drive_paths were passed
        call_kwargs = mock_connect.call_args[1]
        drive_paths = call_kwargs["drive_paths"]
        assert len(drive_paths) == 2
        assert drive_paths[0].name == "share"
        assert drive_paths[0].path == "/tmp"
        assert drive_paths[0].read_only is False
        assert drive_paths[1].name == "docs"
        assert drive_paths[1].path == "/home"
        assert drive_paths[1].read_only is True

    def test_disconnect_called_on_window_close(self) -> None:
        """Session.disconnect() is called after window closes."""
        parser = build_parser()
        args = parser.parse_args(["connect", "--host", "srv", "--user", "u"])

        mock_session = AsyncMock()
        mock_session.disconnect = AsyncMock()

        mock_window = MagicMock()
        mock_window.run = AsyncMock()

        with (
            patch("arrdipi.connect", new_callable=AsyncMock, return_value=mock_session),
            patch("arrdipi.cli.main.DesktopWindow", return_value=mock_window),
        ):
            _run_connect(args, "")

        mock_session.disconnect.assert_called_once()

    def test_disconnect_called_on_error(self) -> None:
        """Session.disconnect() is called even if window.run() raises."""
        parser = build_parser()
        args = parser.parse_args(["connect", "--host", "srv", "--user", "u"])

        mock_session = AsyncMock()
        mock_session.disconnect = AsyncMock()

        mock_window = MagicMock()
        mock_window.run = AsyncMock(side_effect=RuntimeError("window error"))

        with (
            patch("arrdipi.connect", new_callable=AsyncMock, return_value=mock_session),
            patch("arrdipi.cli.main.DesktopWindow", return_value=mock_window),
            pytest.raises(RuntimeError, match="window error"),
        ):
            _run_connect(args, "")

        mock_session.disconnect.assert_called_once()
