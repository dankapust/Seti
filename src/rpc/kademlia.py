import time
import logging
import hashlib
from typing import List, Optional
from src.transport import Frame, MessageType, Connection, Dispatcher
from src.routing.contact import Contact
from src.routing.table import RoutingTable
from src.identity.identity import NodeIdentity

logger = logging.getLogger(__name__)

class KademliaRPC:
    def __init__(self, dispatcher: Dispatcher, identity: NodeIdentity, routing_table: RoutingTable, host: str, port: int):
        self.dispatcher = dispatcher
        self.identity = identity
        self.routing_table = routing_table
        self.host = host
        self.port = port
        
        # Регистрируем обработчики для входящих запросов
        self.dispatcher.register(MessageType.PING, self.handle_ping)
        self.dispatcher.register(MessageType.FIND_NODE_REQUEST, self.handle_find_node)

    def get_local_contact(self) -> Contact:
        """Формирует свой Контакт для отправки другим узлам."""
        return Contact(
            node_id=self.identity.node_id,
            identity_algorithm="Ed25519",
            identity_public_key=self.identity.public_key_bytes,
            host=self.host,
            port=self.port
        )

    def process_incoming_contact(self, contact_dict: dict):
        """Проверяет и добавляет контакт удаленного узла в нашу таблицу маршрутизации."""
        try:
            contact = Contact.from_dict(contact_dict)
            
            # ТЗ Раздел 15.3: проверка криптографической идентичности
            expected_id = hashlib.sha256(contact.identity_public_key).digest()
            if expected_id != contact.node_id:
                logger.warning(f"Контакт {contact.host}:{contact.port} не прошел проверку NodeID!")
                return
            
            # Пытаемся добавить в K-Bucket
            added, oldest = self.routing_table.add_contact(contact)
            # Примечание: по ТЗ, если added=False (корзина полна), нужно пинговать oldest.
            # Эта логика обычно выносится в фоновый процесс (worker), чтобы не блокировать текущий запрос.
            
        except Exception as e:
            logger.warning(f"Ошибка разбора контакта: {e}")

    # ==========================================
    # ОБРАБОТЧИКИ ВХОДЯЩИХ ЗАПРОСОВ (СЕРВЕР)
    # ==========================================

    async def handle_ping(self, conn: Connection, frame: Frame):
        """Обработка входящего PING и отправка PONG."""
        data = frame.unpack_data()
        self.process_incoming_contact(data['sender'])
        
        pong_data = {
            "responder": self.get_local_contact().to_dict(),
            "ping_timestamp_ms": data.get('timestamp_ms', 0),
            "responder_timestamp_ms": int(time.time() * 1000)
        }
        pong_frame = Frame.pack_data(
            msg_type=MessageType.PONG,
            data=pong_data,
            request_id=frame.request_id
        )
        await conn.send_frame(pong_frame)

    async def handle_find_node(self, conn: Connection, frame: Frame):
        """Обработка FIND_NODE_REQUEST и возврат ближайших контактов."""
        data = frame.unpack_data()
        self.process_incoming_contact(data['sender'])
        
        target_node_id = data['target_node_id']
        # Ищем в своей таблице K_BUCKET_SIZE ближайших узлов к цели
        closest = self.routing_table.get_closest_contacts(target_node_id, self.routing_table.k_size)
        
        resp_data = {
            "responder": self.get_local_contact().to_dict(),
            "target_node_id": target_node_id,
            "contacts": [c.to_dict() for c in closest]
        }
        resp_frame = Frame.pack_data(
            msg_type=MessageType.FIND_NODE_RESPONSE,
            data=resp_data,
            request_id=frame.request_id
        )
        await conn.send_frame(resp_frame)

    # ==========================================
    # КЛИЕНТСКИЕ МЕТОДЫ (ОТПРАВКА ЗАПРОСОВ)
    # ==========================================

    async def send_ping(self, conn: Connection) -> bool:
        """Отправляет PING и ждет корректный PONG."""
        req_data = {
            "sender": self.get_local_contact().to_dict(),
            "timestamp_ms": int(time.time() * 1000)
        }
        frame = Frame.pack_data(msg_type=MessageType.PING, data=req_data)
        await conn.send_frame(frame)
        
        resp = await conn.read_frame(timeout=5.0) # PING_TIMEOUT_MS = 5000
        if resp and resp.msg_type == MessageType.PONG and resp.request_id == frame.request_id:
            data = resp.unpack_data()
            self.process_incoming_contact(data['responder'])
            return True
        return False

    async def send_find_node(self, conn: Connection, target_node_id: bytes) -> List[Contact]:
        """Отправляет FIND_NODE_REQUEST и возвращает полученные контакты."""
        req_data = {
            "sender": self.get_local_contact().to_dict(),
            "target_node_id": target_node_id
        }
        frame = Frame.pack_data(msg_type=MessageType.FIND_NODE_REQUEST, data=req_data)
        await conn.send_frame(frame)
        
        resp = await conn.read_frame(timeout=5.0)
        if resp and resp.msg_type == MessageType.FIND_NODE_RESPONSE and resp.request_id == frame.request_id:
            data = resp.unpack_data()
            self.process_incoming_contact(data['responder'])
            
            contacts = []
            for c_dict in data.get('contacts', []):
                try:
                    c = Contact.from_dict(c_dict)
                    # Базовая валидация полученных соседей
                    if hashlib.sha256(c.identity_public_key).digest() == c.node_id:
                        contacts.append(c)
                except Exception:
                    pass
            return contacts
        return []