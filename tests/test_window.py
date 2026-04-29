"""Tests for DesktopWindow — event mapping correctness.

Tests verify that pygame events are correctly mapped to session method calls.
All pygame interactions are mocked — no actual display is required.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture
def mock_session():
    """Create a mock Session with all required input methods."""
    session = MagicMock()
    session.send_key = AsyncMock()
    session.send_unicode_key = AsyncMock()
    session.send_mouse_move = AsyncMock()
    session.send_mouse_button = AsyncMock()
    session.send_mouse_scroll = AsyncMock()
    session.on_graphics_update = MagicMock()

    # Surface mock
    surface = MagicMock()
    surface.width = 1920
    surface.height = 1080
    surface.get_buffer.return_value = memoryview(bytearray(1920 * 1080 * 4))
    session.surface = surface

    return session


@pytest.fixture
def make_window(mock_session):
    """Factory to create a DesktopWindow with mocked pygame."""
    with patch("arrdipi.cli.window.pygame") as mock_pygame:
        # Set up pygame constants
        mock_pygame.QUIT = 256
        mock_pygame.KEYDOWN = 768
        mock_pygame.KEYUP = 769
        mock_pygame.MOUSEMOTION = 1024
        mock_pygame.MOUSEBUTTONDOWN = 1025
        mock_pygame.MOUSEBUTTONUP = 1026
        mock_pygame.MOUSEWHEEL = 1027

        from arrdipi.cli.window import DesktopWindow

        window = DesktopWindow(mock_session, width=1920, height=1080)
        yield window, mock_pygame


class TestDesktopWindowInit:
    """Tests for DesktopWindow initialization."""

    def test_init_stores_session(self, mock_session) -> None:
        """DesktopWindow stores the session reference."""
        with patch("arrdipi.cli.window.pygame"):
            from arrdipi.cli.window import DesktopWindow

            window = DesktopWindow(mock_session, width=1280, height=720)
            assert window._session is mock_session
            assert window._width == 1280
            assert window._height == 720

    def test_init_not_running(self, mock_session) -> None:
        """DesktopWindow starts in non-running state."""
        with patch("arrdipi.cli.window.pygame"):
            from arrdipi.cli.window import DesktopWindow

            window = DesktopWindow(mock_session, width=1920, height=1080)
            assert window._running is False


class TestDesktopWindowRun:
    """Tests for DesktopWindow.run() lifecycle."""

    @pytest.mark.asyncio
    async def test_run_initializes_pygame(self, mock_session) -> None:
        """run() calls pygame.init() and creates display surface."""
        with patch("arrdipi.cli.window.pygame") as mock_pygame:
            mock_pygame.QUIT = 256
            mock_pygame.KEYDOWN = 768
            mock_pygame.KEYUP = 769
            mock_pygame.MOUSEMOTION = 1024
            mock_pygame.MOUSEBUTTONDOWN = 1025
            mock_pygame.MOUSEBUTTONUP = 1026
            mock_pygame.MOUSEWHEEL = 1027

            # Make event.get() return QUIT immediately to exit the loop
            quit_event = MagicMock()
            quit_event.type = mock_pygame.QUIT
            mock_pygame.event.get.return_value = [quit_event]

            from arrdipi.cli.window import DesktopWindow

            window = DesktopWindow(mock_session, width=1920, height=1080)
            await window.run()

            mock_pygame.init.assert_called_once()
            mock_pygame.display.set_mode.assert_called_once_with((1920, 1080))
            mock_pygame.display.set_caption.assert_called_once_with("arrdipi")
            mock_pygame.quit.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_registers_graphics_callback(self, mock_session) -> None:
        """run() registers _on_graphics_update with the session."""
        with patch("arrdipi.cli.window.pygame") as mock_pygame:
            mock_pygame.QUIT = 256
            mock_pygame.KEYDOWN = 768
            mock_pygame.KEYUP = 769
            mock_pygame.MOUSEMOTION = 1024
            mock_pygame.MOUSEBUTTONDOWN = 1025
            mock_pygame.MOUSEBUTTONUP = 1026
            mock_pygame.MOUSEWHEEL = 1027

            quit_event = MagicMock()
            quit_event.type = mock_pygame.QUIT
            mock_pygame.event.get.return_value = [quit_event]

            from arrdipi.cli.window import DesktopWindow

            window = DesktopWindow(mock_session, width=1920, height=1080)
            await window.run()

            mock_session.on_graphics_update.assert_called_once_with(
                window._on_graphics_update
            )


class TestProcessPygameEvents:
    """Tests for _process_pygame_events() — event mapping correctness."""

    @pytest.mark.asyncio
    async def test_keydown_sends_key_pressed(self, mock_session) -> None:
        """KEYDOWN event calls send_key with is_released=False."""
        with patch("arrdipi.cli.window.pygame") as mock_pygame:
            mock_pygame.QUIT = 256
            mock_pygame.KEYDOWN = 768
            mock_pygame.KEYUP = 769
            mock_pygame.MOUSEMOTION = 1024
            mock_pygame.MOUSEBUTTONDOWN = 1025
            mock_pygame.MOUSEBUTTONUP = 1026
            mock_pygame.MOUSEWHEEL = 1027

            event = MagicMock()
            event.type = mock_pygame.KEYDOWN
            event.scancode = 30  # 'A' key scancode
            mock_pygame.event.get.return_value = [event]

            from arrdipi.cli.window import DesktopWindow

            window = DesktopWindow(mock_session, width=1920, height=1080)
            window._running = True
            await window._process_pygame_events()

            mock_session.send_key.assert_called_once_with(30, is_released=False)

    @pytest.mark.asyncio
    async def test_keyup_sends_key_released(self, mock_session) -> None:
        """KEYUP event calls send_key with is_released=True."""
        with patch("arrdipi.cli.window.pygame") as mock_pygame:
            mock_pygame.QUIT = 256
            mock_pygame.KEYDOWN = 768
            mock_pygame.KEYUP = 769
            mock_pygame.MOUSEMOTION = 1024
            mock_pygame.MOUSEBUTTONDOWN = 1025
            mock_pygame.MOUSEBUTTONUP = 1026
            mock_pygame.MOUSEWHEEL = 1027

            event = MagicMock()
            event.type = mock_pygame.KEYUP
            event.scancode = 30
            mock_pygame.event.get.return_value = [event]

            from arrdipi.cli.window import DesktopWindow

            window = DesktopWindow(mock_session, width=1920, height=1080)
            window._running = True
            await window._process_pygame_events()

            mock_session.send_key.assert_called_once_with(30, is_released=True)

    @pytest.mark.asyncio
    async def test_mousemotion_sends_mouse_move(self, mock_session) -> None:
        """MOUSEMOTION event calls send_mouse_move with position."""
        with patch("arrdipi.cli.window.pygame") as mock_pygame:
            mock_pygame.QUIT = 256
            mock_pygame.KEYDOWN = 768
            mock_pygame.KEYUP = 769
            mock_pygame.MOUSEMOTION = 1024
            mock_pygame.MOUSEBUTTONDOWN = 1025
            mock_pygame.MOUSEBUTTONUP = 1026
            mock_pygame.MOUSEWHEEL = 1027

            event = MagicMock()
            event.type = mock_pygame.MOUSEMOTION
            event.pos = (500, 300)
            mock_pygame.event.get.return_value = [event]

            from arrdipi.cli.window import DesktopWindow

            window = DesktopWindow(mock_session, width=1920, height=1080)
            window._running = True
            await window._process_pygame_events()

            mock_session.send_mouse_move.assert_called_once_with(500, 300)

    @pytest.mark.asyncio
    async def test_mousebuttondown_sends_button_pressed(self, mock_session) -> None:
        """MOUSEBUTTONDOWN event calls send_mouse_button with is_released=False."""
        with patch("arrdipi.cli.window.pygame") as mock_pygame:
            mock_pygame.QUIT = 256
            mock_pygame.KEYDOWN = 768
            mock_pygame.KEYUP = 769
            mock_pygame.MOUSEMOTION = 1024
            mock_pygame.MOUSEBUTTONDOWN = 1025
            mock_pygame.MOUSEBUTTONUP = 1026
            mock_pygame.MOUSEWHEEL = 1027

            event = MagicMock()
            event.type = mock_pygame.MOUSEBUTTONDOWN
            event.pos = (100, 200)
            event.button = 1  # Left button
            mock_pygame.event.get.return_value = [event]

            from arrdipi.cli.window import DesktopWindow

            window = DesktopWindow(mock_session, width=1920, height=1080)
            window._running = True
            await window._process_pygame_events()

            mock_session.send_mouse_button.assert_called_once_with(
                100, 200, 1, is_released=False
            )

    @pytest.mark.asyncio
    async def test_mousebuttonup_sends_button_released(self, mock_session) -> None:
        """MOUSEBUTTONUP event calls send_mouse_button with is_released=True."""
        with patch("arrdipi.cli.window.pygame") as mock_pygame:
            mock_pygame.QUIT = 256
            mock_pygame.KEYDOWN = 768
            mock_pygame.KEYUP = 769
            mock_pygame.MOUSEMOTION = 1024
            mock_pygame.MOUSEBUTTONDOWN = 1025
            mock_pygame.MOUSEBUTTONUP = 1026
            mock_pygame.MOUSEWHEEL = 1027

            event = MagicMock()
            event.type = mock_pygame.MOUSEBUTTONUP
            event.pos = (100, 200)
            event.button = 3  # Right button
            mock_pygame.event.get.return_value = [event]

            from arrdipi.cli.window import DesktopWindow

            window = DesktopWindow(mock_session, width=1920, height=1080)
            window._running = True
            await window._process_pygame_events()

            mock_session.send_mouse_button.assert_called_once_with(
                100, 200, 3, is_released=True
            )

    @pytest.mark.asyncio
    async def test_mousewheel_sends_scroll(self, mock_session) -> None:
        """MOUSEWHEEL event calls send_mouse_scroll with current mouse position and delta."""
        with patch("arrdipi.cli.window.pygame") as mock_pygame:
            mock_pygame.QUIT = 256
            mock_pygame.KEYDOWN = 768
            mock_pygame.KEYUP = 769
            mock_pygame.MOUSEMOTION = 1024
            mock_pygame.MOUSEBUTTONDOWN = 1025
            mock_pygame.MOUSEBUTTONUP = 1026
            mock_pygame.MOUSEWHEEL = 1027

            event = MagicMock()
            event.type = mock_pygame.MOUSEWHEEL
            event.y = 3  # Scroll up
            mock_pygame.mouse.get_pos.return_value = (400, 500)
            mock_pygame.event.get.return_value = [event]

            from arrdipi.cli.window import DesktopWindow

            window = DesktopWindow(mock_session, width=1920, height=1080)
            window._running = True
            await window._process_pygame_events()

            mock_session.send_mouse_scroll.assert_called_once_with(400, 500, 3)

    @pytest.mark.asyncio
    async def test_quit_event_stops_loop(self, mock_session) -> None:
        """QUIT event sets _running to False."""
        with patch("arrdipi.cli.window.pygame") as mock_pygame:
            mock_pygame.QUIT = 256
            mock_pygame.KEYDOWN = 768
            mock_pygame.KEYUP = 769
            mock_pygame.MOUSEMOTION = 1024
            mock_pygame.MOUSEBUTTONDOWN = 1025
            mock_pygame.MOUSEBUTTONUP = 1026
            mock_pygame.MOUSEWHEEL = 1027

            event = MagicMock()
            event.type = mock_pygame.QUIT
            mock_pygame.event.get.return_value = [event]

            from arrdipi.cli.window import DesktopWindow

            window = DesktopWindow(mock_session, width=1920, height=1080)
            window._running = True
            await window._process_pygame_events()

            assert window._running is False

    @pytest.mark.asyncio
    async def test_multiple_events_processed(self, mock_session) -> None:
        """Multiple events in a single frame are all processed."""
        with patch("arrdipi.cli.window.pygame") as mock_pygame:
            mock_pygame.QUIT = 256
            mock_pygame.KEYDOWN = 768
            mock_pygame.KEYUP = 769
            mock_pygame.MOUSEMOTION = 1024
            mock_pygame.MOUSEBUTTONDOWN = 1025
            mock_pygame.MOUSEBUTTONUP = 1026
            mock_pygame.MOUSEWHEEL = 1027

            key_event = MagicMock()
            key_event.type = mock_pygame.KEYDOWN
            key_event.scancode = 42

            move_event = MagicMock()
            move_event.type = mock_pygame.MOUSEMOTION
            move_event.pos = (10, 20)

            mock_pygame.event.get.return_value = [key_event, move_event]

            from arrdipi.cli.window import DesktopWindow

            window = DesktopWindow(mock_session, width=1920, height=1080)
            window._running = True
            await window._process_pygame_events()

            mock_session.send_key.assert_called_once_with(42, is_released=False)
            mock_session.send_mouse_move.assert_called_once_with(10, 20)


class TestOnGraphicsUpdate:
    """Tests for _on_graphics_update() — framebuffer blitting."""

    @pytest.mark.asyncio
    async def test_graphics_update_blits_dirty_rects(self, mock_session) -> None:
        """_on_graphics_update blits dirty regions and calls display.update."""
        with patch("arrdipi.cli.window.pygame") as mock_pygame:
            mock_pygame.QUIT = 256
            mock_pygame.KEYDOWN = 768
            mock_pygame.KEYUP = 769
            mock_pygame.MOUSEMOTION = 1024
            mock_pygame.MOUSEBUTTONDOWN = 1025
            mock_pygame.MOUSEBUTTONUP = 1026
            mock_pygame.MOUSEWHEEL = 1027

            # Set up mock screen surface
            mock_screen = MagicMock()
            mock_pygame.display.set_mode.return_value = mock_screen
            mock_pygame.image.frombuffer.return_value = MagicMock()
            mock_pygame.Rect = MagicMock(side_effect=lambda x, y, w, h: (x, y, w, h))

            from arrdipi.cli.window import DesktopWindow
            from arrdipi.graphics.surface import Rect

            window = DesktopWindow(mock_session, width=1920, height=1080)
            window._screen = mock_screen

            dirty = [Rect(x=10, y=20, w=100, h=50)]
            await window._on_graphics_update(dirty)

            # Verify frombuffer was called with the buffer
            mock_pygame.image.frombuffer.assert_called_once()
            # Verify blit was called
            mock_screen.blit.assert_called_once()
            # Verify display.update was called
            mock_pygame.display.update.assert_called_once()

    @pytest.mark.asyncio
    async def test_graphics_update_no_screen_noop(self, mock_session) -> None:
        """_on_graphics_update does nothing if screen is not initialized."""
        with patch("arrdipi.cli.window.pygame") as mock_pygame:
            mock_pygame.QUIT = 256
            mock_pygame.KEYDOWN = 768
            mock_pygame.KEYUP = 769
            mock_pygame.MOUSEMOTION = 1024
            mock_pygame.MOUSEBUTTONDOWN = 1025
            mock_pygame.MOUSEBUTTONUP = 1026
            mock_pygame.MOUSEWHEEL = 1027

            from arrdipi.cli.window import DesktopWindow
            from arrdipi.graphics.surface import Rect

            window = DesktopWindow(mock_session, width=1920, height=1080)
            # _screen is None by default

            dirty = [Rect(x=0, y=0, w=10, h=10)]
            await window._on_graphics_update(dirty)

            # Should not crash, and display.update should not be called
            mock_pygame.display.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_graphics_update_multiple_rects(self, mock_session) -> None:
        """_on_graphics_update handles multiple dirty rectangles."""
        with patch("arrdipi.cli.window.pygame") as mock_pygame:
            mock_pygame.QUIT = 256
            mock_pygame.KEYDOWN = 768
            mock_pygame.KEYUP = 769
            mock_pygame.MOUSEMOTION = 1024
            mock_pygame.MOUSEBUTTONDOWN = 1025
            mock_pygame.MOUSEBUTTONUP = 1026
            mock_pygame.MOUSEWHEEL = 1027

            mock_screen = MagicMock()
            mock_pygame.display.set_mode.return_value = mock_screen
            mock_pygame.image.frombuffer.return_value = MagicMock()
            mock_pygame.Rect = MagicMock(side_effect=lambda x, y, w, h: (x, y, w, h))

            from arrdipi.cli.window import DesktopWindow
            from arrdipi.graphics.surface import Rect

            window = DesktopWindow(mock_session, width=1920, height=1080)
            window._screen = mock_screen

            dirty = [
                Rect(x=0, y=0, w=100, h=100),
                Rect(x=200, y=200, w=50, h=50),
            ]
            await window._on_graphics_update(dirty)

            # blit should be called once per dirty rect
            assert mock_screen.blit.call_count == 2
            mock_pygame.display.update.assert_called_once()
