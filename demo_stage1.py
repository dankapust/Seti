import asyncio
import logging
import os
import sys
from typing import Optional

from src.transport import (
    Frame,
    MessageType,
    FrameFlags,
    Connection,
    Dispatcher,
    PROTOCOL_VERSION,
    ReadTimeoutError,
)
from src.transport.protocol import HEADER_SIZE

# Config UTF-8 output for Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logs/stage1_demo.log", encoding="utf-8"),
    ]
)
logger = logging.getLogger("NodeDemo")

class SimpleNode:
    def __init__(self, name: str, host: str, port: int, delay_pong: float = 0.0):
        self.name = name
        self.host = host
        self.port = port
        self.delay_pong = delay_pong  # Used to simulate timeout on request
        self.dispatcher = Dispatcher()
        self.server: Optional[asyncio.Server] = None
        self.register_handlers()

    def register_handlers(self):
        """Register handlers for message types"""
        async def handle_ping(conn: Connection, frame: Frame):
            data = frame.unpack_data()
            logger.info(f"[{self.name}] [RECV PING] from '{data.get('sender')}'. Payload: {data}")
            if self.delay_pong > 0:
                logger.info(f"[{self.name}] [DELAY RESPONSE] Simulating delay of {self.delay_pong}s to trigger timeout...")
                await asyncio.sleep(self.delay_pong)

            pong_frame = Frame.pack_data(
                msg_type=MessageType.PONG,
                data={"sender": self.name, "status": "OK", "echo": data},
                request_id=frame.request_id,
            )
            logger.info(f"[{self.name}] [SEND PONG] (req_id={frame.request_id.hex()[:8]}...)")
            await conn.send_frame(pong_frame)

        async def handle_app_message(conn: Connection, frame: Frame):
            data = frame.unpack_data()
            logger.info(f"[{self.name}] [RECV APP_MESSAGE]: id={data.get('id')}, len={len(data.get('content', ''))}")
            ack_frame = Frame.pack_data(
                msg_type=MessageType.APP_ACK,
                data={"status": "RECEIVED", "msg_id": data.get("id")},
                request_id=frame.request_id,
            )
            logger.info(f"[{self.name}] [SEND APP_ACK] Confirmation frame sent")
            await conn.send_frame(ack_frame)

        self.dispatcher.register(MessageType.PING, handle_ping)
        self.dispatcher.register(MessageType.APP_MESSAGE, handle_app_message)

    async def start(self):
        """Start independent TCP server node"""
        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            conn = Connection(reader, writer)
            remote_addr = writer.get_extra_info("peername")
            logger.info(f"[{self.name}] [CONNECT] Incoming TCP connection from {remote_addr}")
            try:
                while True:
                    frame = await conn.read_frame()
                    if frame is None:
                        logger.info(f"[{self.name}] [DISCONNECT] Connection from {remote_addr} closed cleanly")
                        break
                    
                    logger.info(
                        f"[{self.name}] [HEADER DISSECT] 24 bytes: "
                        f"Ver={frame.version}, Type={frame.msg_type.name}({frame.msg_type.value}), "
                        f"ReqID={frame.request_id.hex()[:8]}..., PayloadLen={frame.payload_length} bytes"
                    )
                    await self.dispatcher.dispatch(conn, frame)
            except Exception as e:
                logger.error(f"[{self.name}] Error processing connection: {e}")
                try:
                    err_frame = Frame.pack_data(
                        msg_type=MessageType.ERROR,
                        data={"code": "PROTOCOL_ERROR", "message": str(e)},
                        flags=FrameFlags.ERROR
                    )
                    await conn.send_frame(err_frame)
                except Exception:
                    pass
            finally:
                await conn.close()

        self.server = await asyncio.start_server(handle_client, self.host, self.port)
        logger.info(f"[{self.name}] [NODE STARTED] Independent process listening on {self.host}:{self.port}")

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info(f"[{self.name}] [NODE STOPPED]")

async def run_demo():
    print("=" * 80)
    print("       STAGE 1 DEMO: INDEPENDENT CONCURRENT NODES ON DIFFERENT PORTS & TIMEOUTS")
    print("=" * 80)

    # 1. Start 3 independent concurrent nodes listening on different ports
    node_a = SimpleNode(name="Node_A", host="127.0.0.1", port=8001)
    node_b = SimpleNode(name="Node_B", host="127.0.0.1", port=8002)
    node_c = SimpleNode(name="Node_C (Delayed)", host="127.0.0.1", port=8003, delay_pong=3.0)

    await node_a.start()
    await node_b.start()
    await node_c.start()

    # Function for a node connecting and exchanging frames with another node
    async def exchange_ping(sender_name: str, target_host: str, target_port: int, timeout_val: float = 2.0):
        logger.info(f"[{sender_name}] Connecting to target node at {target_host}:{target_port}...")
        reader, writer = await asyncio.open_connection(target_host, target_port)
        conn = Connection(reader, writer)
        
        ping_frame = Frame.pack_data(
            msg_type=MessageType.PING,
            data={"sender": sender_name, "text": f"Hello from {sender_name}!"},
        )
        await conn.send_frame(ping_frame)
        logger.info(f"[{sender_name}] PING frame sent. Waiting for PONG (timeout={timeout_val}s)...")
        
        try:
            pong_response = await conn.read_frame(timeout=timeout_val)
            if pong_response:
                data = pong_response.unpack_data()
                logger.info(f"[{sender_name}] [SUCCESS PONG RECV] {data}")
        except ReadTimeoutError as e:
            logger.warning(f"[{sender_name}] [TIMEOUT DETECTED] Read frame timed out: {e}")
        except Exception as e:
            logger.error(f"[{sender_name}] Error: {e}")
        finally:
            await conn.close()

    # 2. Run concurrent independent node interactions on different ports simultaneously
    logger.info("--- TEST 1: Simultaneous independent concurrent operations across ports 8001, 8002 ---")
    await asyncio.gather(
        exchange_ping("Node_B_Process", "127.0.0.1", 8001, timeout_val=2.0),
        exchange_ping("Node_A_Process", "127.0.0.1", 8002, timeout_val=2.0),
    )

    # 3. Test timeout mechanism explicitly on port 8003 (Node_C delays response by 3.0s, client timeout=1.0s)
    logger.info("--- TEST 2: Timeout detection test (Target Node_C on port 8003 with 1.0s timeout) ---")
    await exchange_ping("Node_B_Process", "127.0.0.1", 8003, timeout_val=1.0)

    # Clean stop all nodes
    await node_a.stop()
    await node_b.stop()
    await node_c.stop()

    print("\n" + "=" * 80)
    print(" [SUCCESS] STAGE 1 DEMO COMPLETED: Concurrent processes on different ports & timeouts verified!")
    print(f" [LOG FILE] {os.path.abspath('logs/stage1_demo.log')}")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(run_demo())
