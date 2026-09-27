import asyncio
import logging
from typing import Callable, Awaitable, Dict, Any
from src.transport.protocol import MessageType, FrameFlags
from src.transport.frame import Frame
from src.transport.connection import Connection

logger = logging.getLogger(__name__)

HandlerFunc = Callable[[Connection, Frame], Awaitable[None]]

class Dispatcher:
    def __init__(self):
        self._handlers: Dict[MessageType, HandlerFunc] = {}

    def register(self, msg_type: MessageType, handler: HandlerFunc):
        """Registers a handler coroutine for a specific MessageType."""
        self._handlers[msg_type] = handler

    async def dispatch(self, conn: Connection, frame: Frame):
        """Routes an incoming frame to its registered handler."""
        handler = self._handlers.get(frame.msg_type)
        if handler:
            try:
                await handler(conn, frame)
            except Exception as e:
                logger.error(f"Error handling msg_type {frame.msg_type.name}: {e}", exc_info=True)
                err_frame = Frame.pack_data(
                    msg_type=MessageType.ERROR,
                    data={"error": str(e)},
                    flags=FrameFlags.ERROR,
                    request_id=frame.request_id,
                )
                await conn.send_frame(err_frame)
        else:
            logger.warning(f"No handler registered for msg_type {frame.msg_type.name}")
            err_frame = Frame.pack_data(
                msg_type=MessageType.ERROR,
                data={"error": f"Unhandled message type: {frame.msg_type.name}"},
                flags=FrameFlags.ERROR,
                request_id=frame.request_id,
            )
            await conn.send_frame(err_frame)
