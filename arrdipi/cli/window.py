"""Desktop window — pygame display and input forwarding.

Provides a graphical window for displaying the remote desktop and
forwarding keyboard/mouse input events to the RDP session.

(Req 28, AC 3–6; Req 29, AC 3)
"""

from __future__ import annotations

import asyncio
import importlib
import logging
from collections.abc import Awaitable
from typing import TYPE_CHECKING, Any, Literal

import pygame

from arrdipi.graphics.surface import Rect

if TYPE_CHECKING:
    from arrdipi.session import Session

from arrdipi.pdu.input_pdu import PointerFlags

logger = logging.getLogger(__name__)


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
        """
        self._session = session
        self._width = width
        self._height = height
        self._render_backend = render_backend
        self._screen: pygame.Surface | None = None
        self._frame_surface: pygame.Surface | None = None
        self._frame_buffer: memoryview | None = None
        self._gpu_renderer: Any | None = None
        self._gpu_texture: Any | None = None
        self._use_gpu_present = False
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
        backend_label = "gpu" if self._use_gpu_present else "surface"
        pygame.display.set_caption(f"arrdipi ({backend_label})")
        self._running = True

        self._session.on_graphics_update(self._on_graphics_update)
        self._session.on_disconnect(self._on_disconnect)

        while self._running:
            await self._process_pygame_events()
            self._present_pending_updates()
            await asyncio.sleep(1 / 60)  # 60 FPS cap

        for task in self._input_tasks:
            task.cancel()
        self._input_tasks.clear()
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
                    self._spawn_input_task(
                        self._session.send_key(event.scancode, is_released=False)
                    )
                case pygame.KEYUP:
                    self._spawn_input_task(
                        self._session.send_key(event.scancode, is_released=True)
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
