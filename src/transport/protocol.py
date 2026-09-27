import enum
import struct
import uuid

PROTOCOL_VERSION = 1
HEADER_SIZE = 24
MAX_FRAME_PAYLOAD = 65536

HEADER_FORMAT = ">BBH16sI"  # version (1B), type (1B), flags (2B), request_id (16B), payload_length (4B)

class MessageType(enum.IntEnum):
    PING = 1
    PONG = 2
    FIND_NODE_REQUEST = 3
    FIND_NODE_RESPONSE = 4
    STORE_REQUEST = 5
    STORE_RESPONSE = 6
    FIND_VALUE_REQUEST = 7
    FIND_VALUE_RESPONSE = 8
    TUNNEL_BUILD = 9
    TUNNEL_BUILD_OK = 10
    TUNNEL_BUILD_FAIL = 11
    TUNNEL_DATA = 12
    TUNNEL_ACK = 13
    TUNNEL_CLOSE = 14
    APP_MESSAGE = 15
    APP_ACK = 16
    ERROR = 127

class FrameFlags(enum.IntFlag):
    NONE = 0
    RESPONSE = 0x0001
    ERROR = 0x0002
    FRAGMENT = 0x0004
    ENCRYPTED = 0x0008

class FramingError(Exception):
    """Base exception for framing errors."""
    pass

class PayloadLengthExceededError(FramingError):
    """Payload length exceeds MAX_FRAME_PAYLOAD."""
    pass

class InvalidProtocolVersionError(FramingError):
    """Protocol version mismatch."""
    pass