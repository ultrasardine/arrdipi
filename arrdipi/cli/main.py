"""CLI entry point for arrdipi.

Provides the `connect` subcommand for establishing RDP sessions
and displaying the remote desktop in a graphical window.

(Req 28, AC 1–2, 6–8)
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

from arrdipi.cli.menu import run_menu


# DesktopWindow will be implemented in Task 37.
# We use a lazy import so the module can be loaded without pygame at import time.
try:
    from arrdipi.cli.window import DesktopWindow
except ImportError:
    DesktopWindow = None  # type: ignore[assignment, misc]


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the arrdipi CLI.

    Returns an ArgumentParser with the `connect` subcommand and all
    required/optional arguments per Req 28, AC 1–2.
    """
    parser = argparse.ArgumentParser(
        prog="arrdipi",
        description="arrdipi — A pure Python RDP client",
    )
    subparsers = parser.add_subparsers(dest="command")

    # menu subcommand
    subparsers.add_parser(
        "menu",
        help="Open the interactive terminal menu",
    )

    # connect subcommand
    connect_parser = subparsers.add_parser(
        "connect",
        help="Connect to an RDP server",
    )

    # Required arguments
    connect_parser.add_argument(
        "--host",
        required=True,
        help="RDP server hostname or IP address",
    )
    connect_parser.add_argument(
        "--user",
        required=True,
        help="Username for authentication",
    )

    # Optional arguments
    connect_parser.add_argument(
        "--password",
        default=None,
        help="Password for authentication (or set ARRDIPI_PASSWORD env var)",
    )
    connect_parser.add_argument(
        "--port",
        type=int,
        default=3389,
        help="RDP server port (default: 3389)",
    )
    connect_parser.add_argument(
        "--domain",
        default="",
        help="Windows domain for authentication",
    )
    connect_parser.add_argument(
        "--security",
        choices=["auto", "rdp", "tls", "nla"],
        default="auto",
        help="Security mode (default: auto)",
    )
    connect_parser.add_argument(
        "--width",
        type=int,
        default=1920,
        help="Desktop width in pixels (default: 1920)",
    )
    connect_parser.add_argument(
        "--height",
        type=int,
        default=1080,
        help="Desktop height in pixels (default: 1080)",
    )
    connect_parser.add_argument(
        "--drive",
        action="append",
        default=None,
        help='Drive redirection in format "NAME:PATH" or "NAME:PATH:ro" (can be specified multiple times)',
    )

    return parser


def _parse_drive(drive_spec: str) -> tuple[str, str, bool]:
    """Parse a drive specification string into (name, path, read_only).

    Format: "NAME:PATH" or "NAME:PATH:ro"

    Raises:
        argparse.ArgumentTypeError: If the format is invalid.
    """
    parts = drive_spec.split(":")
    if len(parts) == 2:
        return parts[0], parts[1], False
    elif len(parts) == 3 and parts[2] == "ro":
        return parts[0], parts[1], True
    else:
        raise argparse.ArgumentTypeError(
            f"Invalid drive format: '{drive_spec}'. Use 'NAME:PATH' or 'NAME:PATH:ro'"
        )


def _run_connect(args: argparse.Namespace, password: str) -> None:
    """Run the connect command: establish session, open window, disconnect on close.

    (Req 28, AC 3, 6)
    """
    import arrdipi
    from arrdipi.connection import DrivePath

    # Parse drive paths
    drive_paths: list[DrivePath] = []
    if args.drive:
        for drive_spec in args.drive:
            name, path, read_only = _parse_drive(drive_spec)
            drive_paths.append(DrivePath(name=name, path=path, read_only=read_only))

    async def _connect_and_run() -> None:
        session = await arrdipi.connect(
            host=args.host,
            port=args.port,
            username=args.user,
            password=password,
            domain=args.domain,
            security=args.security,
            width=args.width,
            height=args.height,
            drive_paths=drive_paths or None,
        )

        try:
            if DesktopWindow is None:
                raise ImportError(
                    "DesktopWindow not available. Install pygame and ensure arrdipi.cli.window exists."
                )
            window = DesktopWindow(session, width=args.width, height=args.height)
            await window.run()
        finally:
            await session.disconnect()

    asyncio.run(_connect_and_run())


def main() -> None:
    """Main entry point for the arrdipi CLI.

    Parses arguments, resolves password from --password or ARRDIPI_PASSWORD
    env var, and dispatches to the appropriate subcommand.

    (Req 28, AC 7–8)
    """
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        run_menu()
        sys.exit(0)

    if args.command == "menu":
        run_menu()
        sys.exit(0)

    if args.command == "connect":
        # Resolve password: --password flag takes precedence over env var (Req 28, AC 8)
        password = args.password
        if password is None:
            password = os.environ.get("ARRDIPI_PASSWORD", "")

        try:
            _run_connect(args, password)
        except Exception as exc:
            # Print human-readable error to stderr and exit non-zero (Req 28, AC 7)
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
