import asyncio
import logging
from typing import Optional
from src.transport.protocol import (
    HEADER_SIZE,
    MAX_FRAME_PAYLOAD,
    FramingError,
    PayloadLengthExceededError,
)
from src.transport.frame import Frame

logger = logging.getLogger(__name__)

class Connection:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self._closed = False

    async def read_frame(self, timeout: Optional[float] = None) -> Optional[Frame]:
        """Reads exactly one complete Frame from the TCP stream."""
        try:
            if timeout:
                header_bytes = await asyncio.wait_for(self.reader.readexactly(HEADER_SIZE), timeout=timeout)
            else:
                header_bytes = await self.reader.readexactly(HEADER_SIZE)
        except asyncio.IncompleteReadError:
            return None  # Connection closed cleanly by remote
        except asyncio.TimeoutError:
            raise FramingError("Read timeout waiting for frame header")

        # Decode header and check payload length BEFORE allocating payload buffer
        version, msg_type, flags, req_id, payload_len = Frame.decode_header(header_bytes)

        payload_bytes = b""
        if payload_len > 0:
            try:
                if timeout:
                    payload_bytes = await asyncio.wait_for(self.reader.readexactly(payload_len), timeout=timeout)
                else:
                    payload_bytes = await self.reader.readexactly(payload_len)
            except asyncio.IncompleteReadError:
                raise FramingError(f"Incomplete payload read: expected {payload_len} bytes")
            except asyncio.TimeoutError:
                raise FramingError("Read timeout waiting for frame payload")

        return Frame(
            msg_type=msg_type,
            payload=payload_bytes,
            flags=flags,
            request_id=req_id,
            version=version,
        )

    async def send_frame(self, frame: Frame):
        """Encodes and sends a Frame over the stream."""
        data = frame.encode()
        self.writer.write(data)
        await self.writer.drain()

    async def close(self):
        if not self._closed:
            self._closed = True
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass
