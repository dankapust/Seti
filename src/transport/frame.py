import struct
import uuid
import msgpack
from typing import Any, Tuple, Optional
from src.transport.protocol import (
    PROTOCOL_VERSION,
    HEADER_SIZE,
    MAX_FRAME_PAYLOAD,
    HEADER_FORMAT,
    MessageType,
    FrameFlags,
    FramingError,
    PayloadLengthExceededError,
    InvalidProtocolVersionError,
)

class Frame:
    def __init__(
        self,
        msg_type: MessageType,
        payload: bytes = b"",
        flags: FrameFlags = FrameFlags.NONE,
        request_id: Optional[bytes] = None,
        version: int = PROTOCOL_VERSION,
    ):
        self.version = version
        self.msg_type = MessageType(msg_type)
        self.flags = FrameFlags(flags)
        if request_id is None:
            self.request_id = uuid.uuid4().bytes
        else:
            if len(request_id) != 16:
                raise ValueError("request_id must be exactly 16 bytes")
            self.request_id = request_id

        if len(payload) > MAX_FRAME_PAYLOAD:
            raise PayloadLengthExceededError(
                f"Payload length {len(payload)} exceeds MAX_FRAME_PAYLOAD ({MAX_FRAME_PAYLOAD})"
            )
        self.payload = payload

    @property
    def payload_length(self) -> int:
        return len(self.payload)

    def encode(self) -> bytes:
        header = struct.pack(
            HEADER_FORMAT,
            self.version,
            int(self.msg_type),
            int(self.flags),
            self.request_id,
            self.payload_length,
        )
        return header + self.payload

    @classmethod
    def decode_header(cls, header_bytes: bytes) -> Tuple[int, MessageType, FrameFlags, bytes, int]:
        if len(header_bytes) < HEADER_SIZE:
            raise FramingError(f"Header size too small: {len(header_bytes)} < {HEADER_SIZE}")
        
        version, msg_type_raw, flags_raw, req_id, payload_len = struct.unpack(HEADER_FORMAT, header_bytes[:HEADER_SIZE])
        
        if version != PROTOCOL_VERSION:
            raise InvalidProtocolVersionError(f"Unsupported protocol version: {version}")
        
        if payload_len > MAX_FRAME_PAYLOAD:
            raise PayloadLengthExceededError(
                f"Payload length {payload_len} in header exceeds MAX_FRAME_PAYLOAD ({MAX_FRAME_PAYLOAD})"
            )
            
        try:
            msg_type = MessageType(msg_type_raw)
        except ValueError:
            raise FramingError(f"Unknown message type: {msg_type_raw}")

        flags = FrameFlags(flags_raw)
        return version, msg_type, flags, req_id, payload_len

    def unpack_data(self) -> Any:
        if not self.payload:
            return None
        try:
            return msgpack.unpackb(self.payload, raw=False)
        except Exception as e:
            raise FramingError(f"Failed to deserialize msgpack payload: {e}")

    @classmethod
    def pack_data(
        cls,
        msg_type: MessageType,
        data: Any,
        flags: FrameFlags = FrameFlags.NONE,
        request_id: Optional[bytes] = None,
    ) -> "Frame":
        payload = msgpack.packb(data, use_bin_type=True)
        return cls(msg_type=msg_type, payload=payload, flags=flags, request_id=request_id)
