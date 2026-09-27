import asyncio
import logging
import os
import uuid
import sys
from typing import Optional

from src.transport import (
    Frame,
    MessageType,
    FrameFlags,
    Connection,
    Dispatcher,
    PROTOCOL_VERSION,
)
from src.transport.protocol import HEADER_SIZE

# Устанавливаем UTF-8 для вывода в консоль Windows
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
    def __init__(self, name: str, host: str, port: int):
        self.name = name
        self.host = host
        self.port = port
        self.dispatcher = Dispatcher()
        self.server: Optional[asyncio.Server] = None
        self.register_handlers()

    def register_handlers(self):
        """Регистрация обработчиков входящих сообщений"""
        async def handle_ping(conn: Connection, frame: Frame):
            data = frame.unpack_data()
            logger.info(f"[{self.name}] [RECV PING] от '{data.get('sender')}'. Данные: {data}")
            pong_frame = Frame.pack_data(
                msg_type=MessageType.PONG,
                data={"sender": self.name, "status": "OK", "echo": data},
                request_id=frame.request_id,
            )
            logger.info(f"[{self.name}] [SEND PONG] ответ (req_id={frame.request_id.hex()[:8]}...)")
            await conn.send_frame(pong_frame)

        async def handle_app_message(conn: Connection, frame: Frame):
            data = frame.unpack_data()
            logger.info(f"[{self.name}] [RECV APP_MESSAGE]: id={data.get('id')}, len={len(data.get('content', ''))}")
            ack_frame = Frame.pack_data(
                msg_type=MessageType.APP_ACK,
                data={"status": "RECEIVED", "msg_id": data.get("id")},
                request_id=frame.request_id,
            )
            logger.info(f"[{self.name}] [SEND APP_ACK] подтверждение")
            await conn.send_frame(ack_frame)

        self.dispatcher.register(MessageType.PING, handle_ping)
        self.dispatcher.register(MessageType.APP_MESSAGE, handle_app_message)

    async def start(self):
        """Запуск TCP-сервера узла"""
        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            conn = Connection(reader, writer)
            remote_addr = writer.get_extra_info("peername")
            logger.info(f"[{self.name}] [CONNECT] Новое входящее TCP-соединение от {remote_addr}")
            try:
                while True:
                    frame = await conn.read_frame()
                    if frame is None:
                        logger.info(f"[{self.name}] [DISCONNECT] Соединение с {remote_addr} закрыто")
                        break
                    
                    logger.info(
                        f"[{self.name}] [HEADER DISSECT] 24 байта: "
                        f"Ver={frame.version}, Type={frame.msg_type.name}({frame.msg_type.value}), "
                        f"ReqID={frame.request_id.hex()[:8]}..., PayloadLen={frame.payload_length} байт"
                    )
                    await self.dispatcher.dispatch(conn, frame)
            except Exception as e:
                logger.error(f"[{self.name}] Ошибка обработки соединения: {e}")
                # Попытка отправить ERROR перед закрытием, как требует ТЗ
                try:
                    err_frame = Frame.pack_data(
                        msg_type=MessageType.ERROR,
                        data={"code": "PROTOCOL_ERROR", "message": str(e)},
                        flags=FrameFlags.ERROR
                    )
                    await conn.send_frame(err_frame)
                except Exception:
                    pass # Соединение уже может быть разорвано
            finally:
                await conn.close()

        self.server = await asyncio.start_server(handle_client, self.host, self.port)
        logger.info(f"[{self.name}] [NODE STARTED] Узел слушает порт {self.host}:{self.port}")

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info(f"[{self.name}] [NODE STOPPED] Узел остановлен")

async def run_demo():
    print("=" * 75)
    print("       ДЕМОНСТРАЦИЯ ЭТАПА 1: СЕТЕВОЙ ТРАНСПОРТ И КАДРИРОВАНИЕ P2P")
    print("=" * 75)

    # 1. Создаем два узла
    node_a = SimpleNode(name="Node_A (Server)", host="127.0.0.1", port=8001)
    node_b = SimpleNode(name="Node_B (Client)", host="127.0.0.1", port=8002)

    await node_a.start()

    # 2. Узел B подключается к Узлу A по TCP
    logger.info(f"[Node_B (Client)] [TCP CONNECTING] к Node_A (127.0.0.1:8001)...")
    reader, writer = await asyncio.open_connection("127.0.0.1", 8001)
    conn_b = Connection(reader, writer)
    logger.info(f"[Node_B (Client)] [CONNECTED] Узлы установили TCP-соединение!")

    # 3. Узел B отправляет PING канонический кадр
    ping_frame = Frame.pack_data(
        msg_type=MessageType.PING,
        data={"sender": "Node_B", "text": "Привет от узла B!", "seq": 1},
    )
    raw_bytes = ping_frame.encode()
    logger.info(f"[Node_B (Client)] [FRAME PACKED] PING. Размер: {len(raw_bytes)} Б (Header: 24Б + Payload: {ping_frame.payload_length}Б)")
    logger.info(f"[Node_B (Client)] [RAW HEADER HEX] (первые 24 байта): {raw_bytes[:24].hex()}")

    await conn_b.send_frame(ping_frame)
    logger.info(f"[Node_B (Client)] [SEND FRAME] PING отправлен в сеть")

    # 4. Узел B ожидает ответ PONG
    pong_response = await conn_b.read_frame(timeout=2.0)
    if pong_response:
        unpacked_pong = pong_response.unpack_data()
        logger.info(f"[Node_B (Client)] [RECV PONG] Узел B получил ответ PONG от Узла A!")
        logger.info(f"[Node_B (Client)] [UNPACKED PAYLOAD] {unpacked_pong}")

    # 5. Узел B отправляет объемное прикладное сообщение (APP_MESSAGE)
    big_payload = {"id": "msg-999", "content": "X" * 1000, "meta": {"encrypted": False}}
    app_frame = Frame.pack_data(msg_type=MessageType.APP_MESSAGE, data=big_payload)
    logger.info(f"[Node_B (Client)] [SEND APP_MESSAGE] (Payload len: {app_frame.payload_length} байт)...")
    await conn_b.send_frame(app_frame)

    ack_response = await conn_b.read_frame(timeout=2.0)
    if ack_response:
        logger.info(f"[Node_B (Client)] [RECV APP_ACK] Подтверждение: {ack_response.unpack_data()}")

    await conn_b.close()
    await node_a.stop()

    print("\n" + "=" * 75)
    print(" [SUCCESS] Демонстрация успешно завершена!")
    print(f" [LOG FILE] Подробный лог сохранен в: {os.path.abspath('logs/stage1_demo.log')}")
    print("=" * 75)

if __name__ == "__main__":
    asyncio.run(run_demo())