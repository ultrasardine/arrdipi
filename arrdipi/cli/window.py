"""Desktop window — pygame display and input forwarding.

Provides a graphical window for displaying the remote desktop and
forwarding keyboard/mouse input events to the RDP session.

(Req 28, AC 3–6; Req 29, AC 3)
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pygame

if TYPE_CHECKING:
    from arrdipi.graphics.surface import Rect
    from arrdipi.session import Session


class DesktopWindow:
    """pygame-based graphical window for remote desktop display.

    Initializes a pygame display surface, registers for graphics update
    callbacks, and runs an async event loop that forwards keyboard and
    mouse events to the RDP session.

    (Req 28, AC 3–6; Req 29, AC 3)
    """

    def __init__(self, session: Session, width: int = 1920, height: int = 1080) -> None:
        """Initialize the desktop window.

        Args:
            session: The active RDP session to forward input to.
            width: Display width in pixels.
            height: Display height in pixels.
        """
        self._session = session
        self._width = width
        self._height = height
        self._screen: pygame.Surface | None = None
        self._running = False

    async def run(self) -> None:
        """Main loop: initialize pygame, render graphics updates, forward input events.

        Initializes the pygame display, registers the graphics update callback,
        and enters the event loop with a 60 FPS cap via asyncio.sleep(1/60).
        """
        pygame.init()
        self._screen = pygame.display.set_mode((self._width, self._height))
        pygame.display.set_caption("arrdipi")
        self._running = True

        self._session.on_graphics_update(self._on_graphics_update)

        while self._running:
            await self._process_pygame_events()
            await asyncio.sleep(1 / 60)  # 60 FPS cap

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
                    await self._session.send_key(event.scancode, is_released=False)
                case pygame.KEYUP:
                    await self._session.send_key(event.scancode, is_released=True)
                case pygame.MOUSEMOTION:
                    await self._session.send_mouse_move(*event.pos)
                case pygame.MOUSEBUTTONDOWN:
                    await self._session.send_mouse_button(
                        *event.pos, event.button, is_released=False
                    )
                case pygame.MOUSEBUTTONUP:
                    await self._session.send_mouse_button(
                        *event.pos, event.button, is_released=True
                    )
                case pygame.MOUSEWHEEL:
                    x, y = pygame.mouse.get_pos()
                    await self._session.send_mouse_scroll(x, y, event.y)

    async def _on_graphics_update(self, dirty_rects: list[Rect]) -> None:
        """Blit updated regions from the framebuffer to the pygame surface.

        Reads the full RGBA framebuffer from the session surface and creates
        a pygame image from it, then updates only the dirty rectangles on
        the display.

        (Req 28, AC 5)
        """
        if self._screen is None:
            return

        buffer = self._session.surface.get_buffer()
        width = self._session.surface.width
        height = self._session.surface.height

        # Create a pygame surface from the RGBA buffer
        frame_surface = pygame.image.frombuffer(
            bytes(buffer), (width, height), "RGBA"
        )

        # Blit only the dirty regions
        for rect in dirty_rects:
            area = pygame.Rect(rect.x, rect.y, rect.w, rect.h)
            self._screen.blit(frame_surface, (rect.x, rect.y), area)

        pygame.display.update(
            [pygame.Rect(r.x, r.y, r.w, r.h) for r in dirty_rects]
        )
