import time
import logging
import hashlib
import asyncio
from typing import List, Optional, Set, Tuple
from src.transport import Frame, MessageType, Connection, Dispatcher
from src.routing.contact import Contact
from src.routing.table import RoutingTable
from src.identity.identity import NodeIdentity
from src.storage import DHTStorage, NodeRecord

logger = logging.getLogger(__name__)

class KademliaRPC:
    def __init__(
        self,
        dispatcher: Dispatcher,
        identity: NodeIdentity,
        routing_table: RoutingTable,
        host: str,
        port: int,
        ping_timeout: float = 2.0,
        storage: Optional[DHTStorage] = None
    ):
        self.dispatcher = dispatcher
        self.identity = identity
        self.routing_table = routing_table
        self.host = host
        self.port = port
        self.ping_timeout = ping_timeout
        self.storage = storage if storage is not None else DHTStorage()
        self._pinging_nodes: Set[bytes] = set()
        
        # Регистрируем обработчики для входящих запросов
        self.dispatcher.register(MessageType.PING, self.handle_ping)
        self.dispatcher.register(MessageType.FIND_NODE_REQUEST, self.handle_find_node)
        self.dispatcher.register(MessageType.STORE_REQUEST, self.handle_store)
        self.dispatcher.register(MessageType.FIND_VALUE_REQUEST, self.handle_find_value)

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
            
            # ТЗ Раздел 9: проверка криптографической идентичности
            if not contact.validate_identity():
                logger.warning(f"Контакт {contact.host}:{contact.port} не прошел проверку NodeID (подмена ключа или ID)!")
                return
            
            # Пытаемся добавить в K-Bucket
            added, oldest = self.routing_table.add_contact(contact)
            if not added and oldest is not None:
                # Корзина полна: по спецификации Kademlia проверяем доступность oldest
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(self.ping_and_evict(oldest, contact))
                except RuntimeError:
                    pass
            
        except Exception as e:
            logger.warning(f"Ошибка разбора контакта: {e}")

    async def ping_and_evict(self, oldest: Contact, candidate: Contact):
        """
        Проверяет доступность самого старого контакта (oldest) при переполнении K-Bucket.
        Если oldest ответил -> сохраняем его и перемещаем в хвост (promote_contact).
        Если oldest не ответил -> вытесняем его (remove_contact) и добавляем candidate.
        """
        if oldest.node_id in self._pinging_nodes:
            return
        self._pinging_nodes.add(oldest.node_id)
        
        logger.info(f"[{self.identity.node_id.hex()[:8]}] K-Bucket полон! Проверка доступности oldest ({oldest.host}:{oldest.port})...")
        is_alive = False
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(oldest.host, oldest.port),
                timeout=self.ping_timeout
            )
            conn = Connection(reader, writer)
            is_alive = await self.send_ping(conn)
            await conn.close()
        except Exception as e:
            logger.debug(f"[{self.identity.node_id.hex()[:8]}] Oldest {oldest.host}:{oldest.port} недоступен: {e}")
            is_alive = False
        finally:
            self._pinging_nodes.discard(oldest.node_id)

        if is_alive:
            logger.info(f"[{self.identity.node_id.hex()[:8]}] Oldest {oldest.host}:{oldest.port} ответил на PING. Сохраняем в K-Bucket.")
            self.routing_table.promote_contact(oldest.node_id)
        else:
            logger.info(f"[{self.identity.node_id.hex()[:8]}] Oldest {oldest.host}:{oldest.port} не ответил (таймаут). Вытесняем и добавляем {candidate.host}:{candidate.port}.")
            self.routing_table.remove_contact(oldest.node_id)
            self.routing_table.add_contact(candidate)

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

    async def handle_store(self, conn: Connection, frame: Frame):
        """Обработка STORE_REQUEST: валидация и сохранение NodeRecord (ТЗ Раздел 10.3)."""
        data = frame.unpack_data()
        self.process_incoming_contact(data['sender'])

        record_dict = data.get('record')
        if not record_dict:
            resp_frame = Frame.pack_data(
                msg_type=MessageType.STORE_RESPONSE,
                data={"responder": self.get_local_contact().to_dict(), "success": False, "reason": "Missing record"},
                request_id=frame.request_id
            )
            await conn.send_frame(resp_frame)
            return

        try:
            record = NodeRecord.from_dict(record_dict)
            success, reason = self.storage.put(record)
        except Exception as e:
            success = False
            reason = str(e)

        resp_data = {
            "responder": self.get_local_contact().to_dict(),
            "success": success,
            "reason": reason
        }
        resp_frame = Frame.pack_data(
            msg_type=MessageType.STORE_RESPONSE,
            data=resp_data,
            request_id=frame.request_id
        )
        await conn.send_frame(resp_frame)

    async def handle_find_value(self, conn: Connection, frame: Frame):
        """Обработка FIND_VALUE_REQUEST: возврат записи либо K ближайших контактов."""
        data = frame.unpack_data()
        self.process_incoming_contact(data['sender'])

        storage_key = data.get('storage_key')
        record = self.storage.get(storage_key) if storage_key else None

        if record is not None:
            # Запись найдена в локальном хранилище
            resp_data = {
                "responder": self.get_local_contact().to_dict(),
                "record": record.to_dict(),
                "contacts": []
            }
        else:
            # Запись отсутствует: возвращаем k ближайших контактов к storage_key
            closest = self.routing_table.get_closest_contacts(storage_key, self.routing_table.k_size)
            resp_data = {
                "responder": self.get_local_contact().to_dict(),
                "record": None,
                "contacts": [c.to_dict() for c in closest]
            }

        resp_frame = Frame.pack_data(
            msg_type=MessageType.FIND_VALUE_RESPONSE,
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
                    # Проверка криптографической идентичности по ТЗ
                    if c.validate_identity():
                        contacts.append(c)
                    else:
                        logger.warning(f"Отклонен контакт {c.host}:{c.port} с поддельным NodeID!")
                except Exception:
                    pass
            return contacts
        return []

    async def send_store(self, conn: Connection, record: NodeRecord, timeout: float = 5.0) -> Tuple[bool, str]:
        """Отправляет STORE_REQUEST и возвращает (успех, причина)."""
        req_data = {
            "sender": self.get_local_contact().to_dict(),
            "record": record.to_dict()
        }
        frame = Frame.pack_data(msg_type=MessageType.STORE_REQUEST, data=req_data)
        await conn.send_frame(frame)

        resp = await conn.read_frame(timeout=timeout)
        if resp and resp.msg_type == MessageType.STORE_RESPONSE and resp.request_id == frame.request_id:
            data = resp.unpack_data()
            self.process_incoming_contact(data['responder'])
            return bool(data.get('success', False)), data.get('reason', '')
        return False, "Timeout or invalid response"

    async def send_find_value(self, conn: Connection, storage_key: bytes, timeout: float = 5.0) -> Tuple[Optional[NodeRecord], List[Contact]]:
        """
        Отправляет FIND_VALUE_REQUEST.
        Если удаленный узел хранит запись -> возвращает (record, []).
        Если запись не найдена -> возвращает (None, closest_contacts).
        """
        req_data = {
            "sender": self.get_local_contact().to_dict(),
            "storage_key": storage_key
        }
        frame = Frame.pack_data(msg_type=MessageType.FIND_VALUE_REQUEST, data=req_data)
        await conn.send_frame(frame)

        resp = await conn.read_frame(timeout=timeout)
        if resp and resp.msg_type == MessageType.FIND_VALUE_RESPONSE and resp.request_id == frame.request_id:
            data = resp.unpack_data()
            self.process_incoming_contact(data['responder'])

            # 1. Проверяем, вернул ли узел запись
            record_dict = data.get('record')
            if record_dict:
                try:
                    record = NodeRecord.from_dict(record_dict)
                    # Валидируем запись
                    is_valid, reason = record.verify()
                    if is_valid:
                        return record, []
                    else:
                        logger.warning(f"Получена невалидная DHT-запись: {reason}")
                except Exception as e:
                    logger.warning(f"Ошибка парсинга DHT-записи: {e}")

            # 2. Если записи нет, извлекаем возвращенные контакты
            contacts = []
            for c_dict in data.get('contacts', []):
                try:
                    c = Contact.from_dict(c_dict)
                    if c.validate_identity():
                        contacts.append(c)
                except Exception:
                    pass
            return None, contacts

        return None, []