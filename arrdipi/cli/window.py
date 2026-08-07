"""Desktop window — pygame display and input forwarding.

Provides a graphical window for displaying the remote desktop and
forwarding keyboard/mouse input events to the RDP session.

(Req 28, AC 3–6; Req 29, AC 3)
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import logging
import subprocess
import sys
import tempfile
from collections.abc import Awaitable
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import pygame

from arrdipi.graphics.surface import Rect
from arrdipi.channels.clipboard import (
    CF_UNICODETEXT,
    FILE_CONTENTS,
    FILE_GROUP_DESCRIPTOR,
    FILE_GROUP_DESCRIPTOR_W,
)

if TYPE_CHECKING:
    from arrdipi.session import Session

from arrdipi.pdu.input_pdu import PointerFlags

logger = logging.getLogger(__name__)

# SDL scancode (USB HID page 0x07) → (PS/2 Set 1 make code, is_extended)
# SDL scancodes come from event.scancode; RDP expects PS/2 Set 1 scan codes.
_SDL_TO_PS2: dict[int, tuple[int, bool]] = {
    # Letters A–Z
    4: (0x1E, False), 5: (0x30, False), 6: (0x2E, False), 7: (0x20, False),
    8: (0x12, False), 9: (0x21, False), 10: (0x22, False), 11: (0x23, False),
    12: (0x17, False), 13: (0x24, False), 14: (0x25, False), 15: (0x26, False),
    16: (0x32, False), 17: (0x31, False), 18: (0x18, False), 19: (0x19, False),
    20: (0x10, False), 21: (0x13, False), 22: (0x1F, False), 23: (0x14, False),
    24: (0x16, False), 25: (0x2F, False), 26: (0x11, False), 27: (0x2D, False),
    28: (0x15, False), 29: (0x2C, False),
    # Digits 1–0
    30: (0x02, False), 31: (0x03, False), 32: (0x04, False), 33: (0x05, False),
    34: (0x06, False), 35: (0x07, False), 36: (0x08, False), 37: (0x09, False),
    38: (0x0A, False), 39: (0x0B, False),
    # Editing / whitespace
    40: (0x1C, False),  # Return
    41: (0x01, False),  # Escape
    42: (0x0E, False),  # Backspace
    43: (0x0F, False),  # Tab
    44: (0x39, False),  # Space
    # Punctuation
    45: (0x0C, False),  # Minus / Underscore
    46: (0x0D, False),  # Equals / Plus
    47: (0x1A, False),  # LeftBracket
    48: (0x1B, False),  # RightBracket
    49: (0x2B, False),  # Backslash
    51: (0x27, False),  # Semicolon
    52: (0x28, False),  # Apostrophe
    53: (0x29, False),  # Grave
    54: (0x33, False),  # Comma
    55: (0x34, False),  # Period
    56: (0x35, False),  # Slash
    # Lock keys
    57: (0x3A, False),  # CapsLock
    83: (0x45, False),  # NumLock
    71: (0x46, False),  # ScrollLock
    # Function keys
    58: (0x3B, False), 59: (0x3C, False), 60: (0x3D, False), 61: (0x3E, False),
    62: (0x3F, False), 63: (0x40, False), 64: (0x41, False), 65: (0x42, False),
    66: (0x43, False), 67: (0x44, False), 68: (0x57, False), 69: (0x58, False),
    # Navigation (extended)
    73: (0x52, True),   # Insert
    76: (0x53, True),   # Delete
    74: (0x47, True),   # Home
    77: (0x4F, True),   # End
    75: (0x49, True),   # PageUp
    78: (0x51, True),   # PageDown
    82: (0x48, True),   # Up
    81: (0x50, True),   # Down
    80: (0x4B, True),   # Left
    79: (0x4D, True),   # Right
    # Numpad
    84: (0x35, True),   # KP_Divide (extended)
    85: (0x37, False),  # KP_Multiply
    86: (0x4A, False),  # KP_Minus
    87: (0x4E, False),  # KP_Plus
    88: (0x1C, True),   # KP_Enter (extended)
    89: (0x4F, False),  # KP_1 / End
    90: (0x50, False),  # KP_2 / Down
    91: (0x51, False),  # KP_3 / PageDown
    92: (0x4B, False),  # KP_4 / Left
    93: (0x4C, False),  # KP_5
    94: (0x4D, False),  # KP_6 / Right
    95: (0x47, False),  # KP_7 / Home
    96: (0x48, False),  # KP_8 / Up
    97: (0x49, False),  # KP_9 / PageUp
    98: (0x52, False),  # KP_0 / Insert
    99: (0x53, False),  # KP_Period / Delete
    # Modifiers
    224: (0x1D, False), # LCtrl
    225: (0x2A, False), # LShift
    226: (0x38, False), # LAlt
    227: (0x5B, True),  # LGui / LWin (extended)
    228: (0x1D, True),  # RCtrl (extended)
    229: (0x36, False), # RShift
    230: (0x38, True),  # RAlt (extended)
    231: (0x5C, True),  # RGui / RWin (extended)
}


class DesktopWindow:
    """pygame-based graphical window for remote desktop display.

    Initializes a pygame display surface, registers for graphics update
    callbacks, and runs an async event loop that forwards keyboard and
    mouse events to the RDP session.

    (Req 28, AC 3–6; Req 29, AC 3)
    """

    def __init__(
        self,
        session: Session,
        width: int = 1920,
        height: int = 1080,
        *,
        render_backend: Literal["auto", "surface", "gpu"] = "auto",
        clipboard_sync: bool = False,
    ) -> None:
        """Initialize the desktop window.

        Args:
            session: The active RDP session to forward input to.
            width: Display width in pixels.
            height: Display height in pixels.
            render_backend: Presentation backend.
                - auto: try GPU texture path first, fallback to surface blits
                - surface: force software surface blitting path
                - gpu: require GPU texture path (falls back if unavailable)
            clipboard_sync: Enable bidirectional OS clipboard sync via pyperclip.
        """
        self._session = session
        self._width = width
        self._height = height
        self._render_backend = render_backend
        self._clipboard_sync_requested = clipboard_sync
        self._screen: pygame.Surface | None = None
        self._frame_surface: pygame.Surface | None = None
        self._frame_buffer: memoryview | None = None
        self._gpu_renderer: Any | None = None
        self._gpu_texture: Any | None = None
        self._use_gpu_present = False
        self._pyperclip: Any | None = None
        self._clipboard_task: asyncio.Task[None] | None = None
        self._remote_text_changed = asyncio.Event()
        self._remote_files_changed = asyncio.Event()
        self._last_local_clipboard_text = ""
        self._last_remote_clipboard_text = ""
        self._last_local_clipboard_files: list[Path] = []
        self._clipboard_file_cache_dir = Path(tempfile.gettempdir()) / "arrdipi-clipboard"
        self._initial_clipboard_announced = False
        self._input_tasks: set[asyncio.Task[None]] = set()
        self._pending_dirty_rects: list[Rect] = []
        self._full_present_rect_threshold = 96
        self._running = False

    async def run(self) -> None:
        """Main loop: initialize pygame, render graphics updates, forward input events.

        Initializes the pygame display, registers the graphics update callback,
        and enters the event loop with a 60 FPS cap via asyncio.sleep(1/60).
        """
        pygame.init()
        self._screen = self._create_display_surface()
        self._frame_buffer = self._session.surface.get_buffer()
        self._frame_surface = pygame.image.frombuffer(
            self._frame_buffer,
            (self._session.surface.width, self._session.surface.height),
            "RGBA",
        )
        self._use_gpu_present = self._initialize_gpu_presenter()
        self._running = True
        self._initialize_clipboard_sync()
        backend_label = "gpu" if self._use_gpu_present else "surface"
        clipboard_label = "+clipboard" if self._clipboard_task is not None else ""
        pygame.display.set_caption(f"arrdipi ({backend_label}{clipboard_label})")

        self._session.on_graphics_update(self._on_graphics_update)
        self._session.on_disconnect(self._on_disconnect)

        while self._running:
            await self._process_pygame_events()
            self._present_pending_updates()
            await asyncio.sleep(1 / 60)  # 60 FPS cap

        for task in self._input_tasks:
            task.cancel()
        self._input_tasks.clear()
        if self._clipboard_task is not None:
            self._clipboard_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._clipboard_task
            self._clipboard_task = None
        pygame.quit()

    async def _process_pygame_events(self) -> None:
        """Convert pygame events to RDP input events.

        Maps:
        - KEYDOWN/KEYUP → send_key(scancode, is_released)
        - MOUSEMOTION → send_mouse_move(x, y)
        - MOUSEBUTTONDOWN/UP → send_mouse_button(x, y, button, is_released)
        - MOUSEWHEEL → send_mouse_scroll(x, y, delta)
        - QUIT → set running=False to exit loop

        (Req 28, AC 4, 6)
        """
        for event in pygame.event.get():
            match event.type:
                case pygame.QUIT:
                    self._running = False
                case pygame.KEYDOWN:
                    ps2 = _SDL_TO_PS2.get(event.scancode)
                    if ps2 is not None:
                        scan_code, is_extended = ps2
                        self._spawn_input_task(
                            self._session.send_key(scan_code, is_released=False, is_extended=is_extended)
                        )
                case pygame.KEYUP:
                    ps2 = _SDL_TO_PS2.get(event.scancode)
                    if ps2 is not None:
                        scan_code, is_extended = ps2
                        self._spawn_input_task(
                            self._session.send_key(scan_code, is_released=True, is_extended=is_extended)
                        )
                case pygame.MOUSEMOTION:
                    self._spawn_input_task(self._session.send_mouse_move(*event.pos))
                case pygame.MOUSEBUTTONDOWN:
                    button_flag = self._map_mouse_button(event.button)
                    if button_flag is None:
                        continue
                    self._spawn_input_task(
                        self._session.send_mouse_button(
                            *event.pos, button_flag, is_released=False
                        )
                    )
                case pygame.MOUSEBUTTONUP:
                    button_flag = self._map_mouse_button(event.button)
                    if button_flag is None:
                        continue
                    self._spawn_input_task(
                        self._session.send_mouse_button(
                            *event.pos, button_flag, is_released=True
                        )
                    )
                case pygame.MOUSEWHEEL:
                    x, y = pygame.mouse.get_pos()
                    self._spawn_input_task(
                        self._session.send_mouse_scroll(x, y, event.y)
                    )

        # Let scheduled input tasks start so event-driven tests remain deterministic.
        await asyncio.sleep(0)

    def _spawn_input_task(self, coro: Awaitable[None]) -> None:
        """Send input in background so UI rendering never blocks on network I/O."""
        task = asyncio.create_task(coro)
        self._input_tasks.add(task)
        task.add_done_callback(self._input_tasks.discard)
        task.add_done_callback(self._log_input_task_error)

    @staticmethod
    def _log_input_task_error(task: asyncio.Task[None]) -> None:
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            logger.warning("Input send failed: %s", exc)

    @staticmethod
    def _map_mouse_button(button: int) -> int | None:
        """Map pygame button indices to RDP pointer button flags."""
        if button == 1:
            return int(PointerFlags.PTRFLAGS_BUTTON1)
        if button == 2:
            return int(PointerFlags.PTRFLAGS_BUTTON3)  # middle button
        if button == 3:
            return int(PointerFlags.PTRFLAGS_BUTTON2)  # right button
        return None

    def _create_display_surface(self) -> pygame.Surface:
        """Create a display surface, preferring accelerated vsynced modes."""
        scaled_flag = getattr(pygame, "SCALED", None)
        doublebuf_flag = getattr(pygame, "DOUBLEBUF", None)
        flags = 0
        if isinstance(scaled_flag, int):
            flags |= scaled_flag
        if isinstance(doublebuf_flag, int):
            flags |= doublebuf_flag

        if flags:
            try:
                return pygame.display.set_mode((self._width, self._height), flags, vsync=1)
            except (TypeError, ValueError, pygame.error):
                logger.debug("Accelerated display mode unavailable, using default mode")

        return pygame.display.set_mode((self._width, self._height))

    def _initialize_gpu_presenter(self) -> bool:
        """Initialize SDL2 renderer/texture for GPU-backed presentation."""
        if self._render_backend == "surface" or self._frame_surface is None:
            return False

        try:
            sdl2_video = importlib.import_module("pygame._sdl2.video")
            window = sdl2_video.Window.from_display_module()
            renderer = sdl2_video.Renderer.from_window(window)
            texture = sdl2_video.Texture.from_surface(renderer, self._frame_surface)
        except Exception as exc:
            if self._render_backend == "gpu":
                logger.warning("GPU rendering unavailable; falling back to surface mode: %s", exc)
            else:
                logger.debug("GPU presenter unavailable; using surface blits: %s", exc)
            return False

        self._gpu_renderer = renderer
        self._gpu_texture = texture
        return True

    def _initialize_clipboard_sync(self) -> None:
        """Initialize optional clipboard sync loop and callbacks."""
        if not self._clipboard_sync_requested:
            return
        clipboard = self._session.clipboard
        if clipboard is None:
            logger.warning("Clipboard sync requested, but cliprdr channel is unavailable")
            return

        try:
            self._pyperclip = importlib.import_module("pyperclip")
        except ImportError:
            logger.warning("Clipboard sync requested, but pyperclip is not installed")
            return

        try:
            local_text = self._pyperclip.paste()
            if isinstance(local_text, str):
                self._last_local_clipboard_text = local_text
        except Exception as exc:
            logger.warning("Unable to read local clipboard: %s", exc)

        self._session.on_clipboard_changed(self._on_clipboard_changed)
        if clipboard.server_formats:
            self._on_server_formats(clipboard.server_formats)
        self._clipboard_task = asyncio.create_task(self._clipboard_sync_loop())

    async def _clipboard_sync_loop(self) -> None:
        """Synchronize local and remote text clipboard using CLIPRDR."""
        assert self._pyperclip is not None
        clipboard = self._session.clipboard
        if clipboard is None:
            return

        while self._running:
            if not self._initial_clipboard_announced and clipboard.ready:
                self._initial_clipboard_announced = True
                if self._last_local_clipboard_text:
                    try:
                        await clipboard.set_clipboard_text(self._last_local_clipboard_text)
                    except Exception as exc:
                        logger.warning("Failed to send initial local clipboard: %s", exc)
                file_paths = self._read_local_clipboard_file_paths()
                if file_paths:
                    self._last_local_clipboard_files = file_paths
                    try:
                        await clipboard.set_clipboard_files(file_paths)
                    except Exception as exc:
                        logger.warning("Failed to send initial local files: %s", exc)

            if self._remote_text_changed.is_set():
                self._remote_text_changed.clear()
                try:
                    remote_text = await clipboard.get_server_clipboard_text(timeout=1.0)
                except Exception as exc:
                    logger.warning("Failed to read remote clipboard: %s", exc)
                else:
                    if remote_text and remote_text != self._last_local_clipboard_text:
                        try:
                            self._pyperclip.copy(remote_text)
                            self._last_local_clipboard_text = remote_text
                            self._last_remote_clipboard_text = remote_text
                        except Exception as exc:
                            logger.warning("Failed to write local clipboard: %s", exc)

            if self._remote_files_changed.is_set():
                self._remote_files_changed.clear()
                try:
                    files = await clipboard.get_server_clipboard_files(
                        destination_dir=self._clipboard_file_cache_dir,
                        timeout=30.0,
                    )
                except Exception as exc:
                    logger.warning("Failed to fetch remote clipboard files: %s", exc)
                else:
                    if files:
                        self._set_local_clipboard_file_paths(files)
                        self._last_local_clipboard_files = files

            try:
                local_text = self._pyperclip.paste()
            except Exception as exc:
                logger.warning("Failed to read local clipboard: %s", exc)
            else:
                if (
                    isinstance(local_text, str)
                    and clipboard.ready
                    and local_text != self._last_local_clipboard_text
                    and local_text != self._last_remote_clipboard_text
                ):
                    self._last_local_clipboard_text = local_text
                    try:
                        await clipboard.set_clipboard_text(local_text)
                    except Exception as exc:
                        logger.warning("Failed to send local clipboard: %s", exc)

            local_files = self._read_local_clipboard_file_paths()
            if (
                clipboard.ready
                and local_files
                and local_files != self._last_local_clipboard_files
            ):
                self._last_local_clipboard_files = local_files
                try:
                    await clipboard.set_clipboard_files(local_files)
                except Exception as exc:
                    logger.warning("Failed to send local file clipboard: %s", exc)

            await asyncio.sleep(0.25)

    def _on_server_formats(self, clipboard_data: Any) -> None:
        """Process remote format list and trigger pull events."""
        if not isinstance(clipboard_data, list):
            return
        has_text = any(getattr(fmt, "format_id", None) == CF_UNICODETEXT for fmt in clipboard_data)
        has_file_group = any(
            getattr(fmt, "format_name", "").casefold()
            in {FILE_GROUP_DESCRIPTOR_W.casefold(), FILE_GROUP_DESCRIPTOR.casefold()}
            for fmt in clipboard_data
        )
        has_file_contents = any(
            getattr(fmt, "format_name", "").casefold() == FILE_CONTENTS.casefold()
            for fmt in clipboard_data
        )
        if has_text:
            self._remote_text_changed.set()
        if has_file_group and has_file_contents:
            self._remote_files_changed.set()

    async def _on_clipboard_changed(self, clipboard_data: Any) -> None:
        """Mark that remote clipboard formats changed."""
        self._on_server_formats(clipboard_data)

    def _read_local_clipboard_file_paths(self) -> list[Path]:
        """Read local file clipboard entries (macOS supported)."""
        if sys.platform != "darwin":
            return []
        script = (
            'try\n'
            'set f to (the clipboard as «class furl»)\n'
            'set p to POSIX path of (f as alias)\n'
            'return p\n'
            'on error\n'
            'return ""\n'
            'end try\n'
        )
        try:
            result = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                text=True,
                check=False,
                timeout=1.0,
            )
        except (OSError, subprocess.SubprocessError):
            return []

        path_str = result.stdout.strip()
        if not path_str:
            return []
        path = Path(path_str)
        if not path.is_file():
            return []
        return [path.resolve()]

    def _set_local_clipboard_file_paths(self, paths: list[Path]) -> None:
        """Set local clipboard file entries (macOS supported)."""
        if sys.platform != "darwin" or not paths:
            return
        valid_paths = [str(p) for p in paths if p.exists()]
        if not valid_paths:
            return

        # Pass paths as argv to avoid any injection via string interpolation.
        # osascript receives them as items of the `argv` list.
        if len(valid_paths) == 1:
            script = (
                "on run argv\n"
                "set the clipboard to (POSIX file (item 1 of argv))\n"
                "end run\n"
            )
        else:
            set_lines = "\n".join(
                f"set end of fileList to (POSIX file (item {i + 1} of argv))"
                for i in range(len(valid_paths))
            )
            script = (
                "on run argv\n"
                "set fileList to {}\n"
                f"{set_lines}\n"
                "set the clipboard to fileList\n"
                "end run\n"
            )
        try:
            subprocess.run(
                ["osascript", "-e", script, "--", *valid_paths],
                capture_output=True,
                text=True,
                check=False,
                timeout=1.0,
            )
        except (OSError, subprocess.SubprocessError):
            logger.warning("Failed to set local file clipboard entries")

    def _present_pending_updates(self) -> None:
        """Present queued dirty rectangles in batches to avoid row-by-row redraws."""
        if self._screen is None or self._frame_surface is None or not self._pending_dirty_rects:
            return

        rects = self._pending_dirty_rects
        self._pending_dirty_rects = []

        if self._use_gpu_present:
            try:
                assert self._gpu_texture is not None
                assert self._gpu_renderer is not None
                self._gpu_texture.update(self._frame_surface)
                self._gpu_renderer.clear()
                self._gpu_renderer.blit(self._gpu_texture)
                self._gpu_renderer.present()
                return
            except Exception as exc:
                logger.warning("GPU present failed; reverting to surface mode: %s", exc)
                self._use_gpu_present = False
                self._gpu_texture = None
                self._gpu_renderer = None

        if len(rects) >= self._full_present_rect_threshold:
            min_x = min(rect.x for rect in rects)
            min_y = min(rect.y for rect in rects)
            max_x = max(rect.x + rect.w for rect in rects)
            max_y = max(rect.y + rect.h for rect in rects)
            present_rect = pygame.Rect(min_x, min_y, max_x - min_x, max_y - min_y)
            self._screen.blit(self._frame_surface, (present_rect.x, present_rect.y), present_rect)
            pygame.display.update(present_rect)
            return

        update_rects = [pygame.Rect(r.x, r.y, r.w, r.h) for r in rects]
        for rect, area in zip(rects, update_rects, strict=True):
            self._screen.blit(self._frame_surface, (rect.x, rect.y), area)
        pygame.display.update(update_rects)

    async def _on_graphics_update(self, dirty_rects: list[Rect]) -> None:
        """Blit updated regions from the framebuffer to the pygame surface.

        Reads the full RGBA framebuffer from the session surface and creates
        a pygame image from it, then updates only the dirty rectangles on
        the display.

        (Req 28, AC 5)
        """
        if self._screen is None:
            return
        if self._frame_surface is None:
            self._frame_buffer = self._session.surface.get_buffer()
            self._frame_surface = pygame.image.frombuffer(
                self._frame_buffer,
                (self._session.surface.width, self._session.surface.height),
                "RGBA",
            )
        self._pending_dirty_rects.extend(dirty_rects)
        if not self._running:
            self._present_pending_updates()

    async def _on_disconnect(self, reason: str | None) -> None:
        """Stop the window loop when the RDP session disconnects."""
        if reason:
            logger.warning("Session disconnected: %s", reason)
        self._running = False
