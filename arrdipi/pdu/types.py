"""Protocol enums and constants for RDP PDU types.

Definitions follow [MS-RDPBCGR] and related Microsoft Open Specifications.
"""

from enum import Enum, IntEnum, IntFlag


class NegotiationProtocol(IntFlag):
    """X.224 negotiation protocol flags [MS-RDPBCGR] 2.2.1.1.1."""

    PROTOCOL_RDP = 0x00000000
    PROTOCOL_SSL = 0x00000001
    PROTOCOL_HYBRID = 0x00000002


class ShareControlPduType(IntEnum):
    """Share Control PDU types [MS-RDPBCGR] 2.2.8.1.1.1.1."""

    DEMAND_ACTIVE = 0x0001
    CONFIRM_ACTIVE = 0x0003
    DEACTIVATE_ALL = 0x0006
    DATA = 0x0007
    SERVER_REDIR = 0x000A


class ShareDataPduType(IntEnum):
    """Share Data PDU types [MS-RDPBCGR] 2.2.8.1.1.1.2."""

    BITMAP_UPDATE = 0x0001
    PALETTE_UPDATE = 0x0002
    PLAY_SOUND = 0x0017
    SUPPRESS_OUTPUT = 0x0023
    SHUTDOWN_REQUEST = 0x0024
    SHUTDOWN_DENIED = 0x0025
    SAVE_SESSION_INFO = 0x0026
    FONT_LIST = 0x0027
    FONT_MAP = 0x0028
    SET_KEYBOARD_INDICATORS = 0x002A
    SET_KEYBOARD_IME_STATUS = 0x002D
    SET_ERROR_INFO = 0x002F
    DRAW_NINEGRID_ERROR = 0x0030
    DRAW_GDIPLUS_ERROR = 0x0031
    ARC_STATUS = 0x0032
    STATUS_INFO = 0x0036
    MONITOR_LAYOUT = 0x0037
    CONTROL = 0x0014
    POINTER = 0x001B
    INPUT = 0x001C
    SYNCHRONIZE = 0x001F
    REFRESH_RECT = 0x0021


class CapabilitySetType(IntEnum):
    """Capability set types [MS-RDPBCGR] 2.2.7.1."""

    GENERAL = 0x0001
    BITMAP = 0x0002
    ORDER = 0x0003
    BITMAP_CACHE = 0x0004
    CONTROL = 0x0005
    ACTIVATION = 0x0007
    POINTER = 0x0008
    SHARE = 0x0009
    COLOR_CACHE = 0x000A
    SOUND = 0x000C
    INPUT = 0x000D
    FONT = 0x000E
    BRUSH = 0x000F
    GLYPH_CACHE = 0x0010
    OFFSCREEN_BITMAP_CACHE = 0x0011
    BITMAP_CACHE_HOST_SUPPORT = 0x0012
    BITMAP_CACHE_V2 = 0x0013
    VIRTUAL_CHANNEL = 0x0014
    DRAW_NINEGRID_CACHE = 0x0015
    DRAW_GDIPLUS = 0x0016
    RAIL = 0x0017
    WINDOW = 0x0018
    COMP_DESK = 0x0019
    MULTIFRAGMENT_UPDATE = 0x001A
    LARGE_POINTER = 0x001B
    SURFACE_COMMANDS = 0x001C
    BITMAP_CODECS = 0x001D
    FRAME_ACKNOWLEDGE = 0x001E


class SecurityProtocol(Enum):
    """High-level security protocol selection for connection configuration."""

    AUTO = "auto"
    RDP = "rdp"
    TLS = "tls"
    NLA = "nla"


class PerformanceFlags(IntFlag):
    """Performance flags for Client Info PDU [MS-RDPBCGR] 2.2.1.11.1.1."""

    DISABLE_WALLPAPER = 0x00000001
    DISABLE_FULLWINDOWDRAG = 0x00000002
    DISABLE_MENUANIMATIONS = 0x00000004
    DISABLE_THEMING = 0x00000008
    DISABLE_CURSOR_SHADOW = 0x00000020
    DISABLE_CURSORSETTINGS = 0x00000040
    ENABLE_FONT_SMOOTHING = 0x00000080
    ENABLE_DESKTOP_COMPOSITION = 0x00000100


class CompressionType(IntEnum):
    """Bulk compression types [MS-RDPBCGR] 3.1.8."""

    TYPE_8K = 0
    TYPE_64K = 1
    TYPE_RDP6 = 2
    TYPE_RDP61 = 3


class ChannelChunkFlags(IntFlag):
    """Virtual channel chunk flags [MS-RDPBCGR] 2.2.6.1."""

    FLAG_FIRST = 0x00000001
    FLAG_LAST = 0x00000002
    FLAG_SHOW_PROTOCOL = 0x00000010


class EncryptionMethod(IntFlag):
    """Encryption method flags [MS-RDPBCGR] 2.2.1.4.3."""

    NONE = 0x00000000
    BIT_40 = 0x00000001
    BIT_128 = 0x00000002
    BIT_56 = 0x00000008
    FIPS = 0x00000010


class EncryptionLevel(IntEnum):
    """Encryption level values [MS-RDPBCGR] 2.2.1.4.3."""

    NONE = 0
    LOW = 1
    CLIENT_COMPATIBLE = 2
    HIGH = 3
    FIPS = 4
