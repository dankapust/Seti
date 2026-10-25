import asyncio
import logging
import time
import uuid
from typing import List, Tuple, Optional
from src.transport.connection import Connection
from src.transport.dispatcher import Dispatcher
from src.identity.identity import NodeIdentity
from src.routing.table import RoutingTable
from src.routing.contact import Contact, xor_distance
from src.rpc.kademlia import KademliaRPC
from src.storage import DHTStorage, NodeRecord

logger = logging.getLogger(__name__)

class KademliaNode:
    def __init__(self, state_dir: str, host: str, port: int, k_size: int = 4, alpha: int = 3):
        self.host = host
        self.port = port
        self.k_size = k_size
        self.alpha = alpha
        
        # 1. Загружаем/создаем ключи (ТЗ: Идентичность)
        self.identity = NodeIdentity.load_or_generate(state_dir)
        self.node_id_hex = self.identity.node_id.hex()[:8]
        
        # 2. Инициализируем K-Buckets
        self.routing_table = RoutingTable(self.identity.node_id, k_size)
        
        # 3. Инициализируем локальное хранилище DHT и RPC
        self.storage = DHTStorage()
        self.dispatcher = Dispatcher()
        self.rpc = KademliaRPC(
            self.dispatcher, self.identity, self.routing_table, host, port, storage=self.storage
        )
        
        self.server = None
        self._current_sequence_number = 1
        self._bg_tasks: List[asyncio.Task] = []

    async def start(self):
        """Запускает TCP-сервер узла."""
        async def handle_client(reader, writer):
            conn = Connection(reader, writer)
            try:
                while True:
                    frame = await conn.read_frame()
                    if frame is None:
                        break
                    await self.dispatcher.dispatch(conn, frame)
            except Exception as e:
                pass
            finally:
                await conn.close()

        self.server = await asyncio.start_server(handle_client, self.host, self.port)
        logger.info(f"[{self.node_id_hex}] Узел запущен на {self.host}:{self.port}")

    async def stop(self):
        for task in self._bg_tasks:
            task.cancel()
        if self._bg_tasks:
            await asyncio.gather(*self._bg_tasks, return_exceptions=True)
            self._bg_tasks.clear()
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _query_contact(self, contact: Contact, target_node_id: bytes) -> List[Contact]:
        """Устанавливает временное соединение с контактом и отправляет FIND_NODE."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(contact.host, contact.port), timeout=3.0
            )
            conn = Connection(reader, writer)
            # Отправляем FIND_NODE
            results = await self.rpc.send_find_node(conn, target_node_id)
            await conn.close()
            return results
        except Exception as e:
            logger.debug(f"[{self.node_id_hex}] Не удалось опросить {contact.host}:{contact.port} - {e}")
            return []

    async def lookup_node(self, target_node_id: bytes) -> List[Contact]:
        """
        Итеративный поиск узла (Kademlia DHT Lookup, ТЗ Раздел 21).
        Использует ALPHA = 3 параллельных запросов.
        Условие остановки: все K ближайших кандидатов опрошены (или исчерпан пул).
        """
        lookup_id = uuid.uuid4().hex[:8]
        logger.info(f"[{self.node_id_hex}] [LOOKUP_START] ID={lookup_id}, Target={target_node_id.hex()[:8]}")
        start_time = time.time()
        queried = set()
        
        # Берем начальных кандидатов из своей таблицы
        candidates = self.routing_table.get_closest_contacts(target_node_id, self.k_size * 2)
        if not candidates:
            logger.info(f"[{self.node_id_hex}] [LOOKUP_EMPTY] ID={lookup_id}, локальная таблица пуста")
            return []

        seen_ids = {c.node_id for c in candidates}
        iterations = 0
        rpc_count = 0

        while True:
            iterations += 1
            # Сортируем всех известных кандидатов по XOR-расстоянию до цели
            candidates.sort(key=lambda c: xor_distance(c.node_id, target_node_id))
            
            # Проверяем K ближайших узлов
            k_closest = candidates[:self.k_size]
            unqueried_in_k = [c for c in k_closest if c.node_id not in queried]
            
            # Если все K ближайших кандидатов уже опрошены, поиск завершен
            if not unqueried_in_k:
                break
                
            # Выбираем до ALPHA ближайших неопрошенных кандидатов
            unqueried_all = [c for c in candidates if c.node_id not in queried]
            to_query = unqueried_all[:self.alpha]
            
            if not to_query:
                break
                
            tasks = []
            for c in to_query:
                queried.add(c.node_id)
                tasks.append(self._query_contact(c, target_node_id))
                rpc_count += 1
            
            # Опрашиваем параллельно (ALPHA запросов)
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for res in results:
                if isinstance(res, list):
                    for new_contact in res:
                        if new_contact.node_id != self.identity.node_id and new_contact.node_id not in seen_ids:
                            seen_ids.add(new_contact.node_id)
                            candidates.append(new_contact)
            
            # Если опрошены вообще все известные кандидаты
            if all(c.node_id in queried for c in candidates):
                break

        candidates.sort(key=lambda c: xor_distance(c.node_id, target_node_id))
        closest = candidates[:self.k_size]
        
        elapsed = time.time() - start_time
        logger.info(
            f"[{self.node_id_hex}] [LOOKUP_DONE] ID={lookup_id}, "
            f"Target={target_node_id.hex()[:8]}, RPC={rpc_count}, "
            f"Iterations={iterations}, Elapsed={elapsed:.3f}s, Closest={len(closest)}"
        )
        return closest

    async def bootstrap(self, bootstrap_host: str, bootstrap_port: int):
        """Присоединение к сети через известный узел (ТЗ Раздел 22.2)."""
        logger.info(f"[{self.node_id_hex}] Начинаем Bootstrap через {bootstrap_host}:{bootstrap_port}...")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(bootstrap_host, bootstrap_port), timeout=3.0
            )
            conn = Connection(reader, writer)
            
            # 1. PING bootstrap-узлу
            success = await self.rpc.send_ping(conn)
            await conn.close()
            
            if success:
                logger.info(f"[{self.node_id_hex}] Bootstrap PING успешен. Выполняем self-lookup...")
                # 2. Итеративный поиск собственного NodeID
                await self.lookup_node(self.identity.node_id)
                
                # Печатаем размер таблицы
                count = sum(len(b.contacts) for b in self.routing_table.buckets)
                logger.info(f"[{self.node_id_hex}] Bootstrap завершен! Контактов в таблице: {count}")
            else:
                logger.error(f"[{self.node_id_hex}] Bootstrap PING не удался.")
        except Exception as e:
            logger.error(f"[{self.node_id_hex}] Ошибка подключения к Bootstrap: {e}")

    # ==========================================
    # ОПЕРАЦИИ ХРАНЕНИЯ И РЕПЛИКАЦИИ (ЭТАП 3)
    # ==========================================

    async def publish_record(self, addresses: Optional[List[str]] = None, ttl_seconds: int = 180) -> Tuple[bool, int]:
        """
        Публикует собственную NodeRecord в сети Kademlia DHT с цифровой подписью Ed25519 (ТЗ Раздел 10.3).
        """
        if addresses is None:
            addresses = [f"{self.host}:{self.port}"]

        record = NodeRecord.create(
            identity=self.identity,
            addresses=addresses,
            sequence_number=self._current_sequence_number,
            ttl_seconds=ttl_seconds
        )
        self._current_sequence_number += 1
        return await self.store_record(record)

    async def store_record(self, record: NodeRecord, replicas: int = 3, min_success: int = 2) -> Tuple[bool, int]:
        """
        Реплицированное сохранение DHT-записи на R ближайших узлах (ТЗ Раздел 10.1, 10.3).
        STORE считается успешным после подтверждения не менее чем от 2 из 3 реплик.
        """
        storage_key = record.get_storage_key()
        logger.info(
            f"[{self.node_id_hex}] [STORE_START] Key={storage_key.hex()[:8]}, "
            f"Owner={record.node_id.hex()[:8]}, seq={record.sequence_number}"
        )

        # 1. Локальное сохранение
        local_stored, _ = self.storage.put(record)
        success_count = 1 if local_stored else 0

        # 2. Находим R ближайших узлов к storage_key через Lookup
        closest_candidates = await self.lookup_node(storage_key)
        
        target_nodes: List[Contact] = []
        for c in closest_candidates:
            if c.node_id != self.identity.node_id:
                target_nodes.append(c)

        selected_replicas = target_nodes[:replicas]

        # 3. Параллельная отправка STORE_REQUEST на выбранные реплики
        async def send_to_replica(contact: Contact) -> bool:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(contact.host, contact.port), timeout=3.0
                )
                conn = Connection(reader, writer)
                ok, reason = await self.rpc.send_store(conn, record)
                await conn.close()
                if ok:
                    logger.debug(f"[{self.node_id_hex}] Реплика {contact.host}:{contact.port} подтвердила STORE")
                return ok
            except Exception as e:
                logger.debug(f"[{self.node_id_hex}] Ошибка STORE на {contact.host}:{contact.port}: {e}")
                return False

        if selected_replicas:
            results = await asyncio.gather(*(send_to_replica(c) for c in selected_replicas), return_exceptions=True)
            for res in results:
                if res is True:
                    success_count += 1

        is_quorum = success_count >= min_success
        logger.info(
            f"[{self.node_id_hex}] [STORE_DONE] Key={storage_key.hex()[:8]}, "
            f"Success={success_count}/{len(selected_replicas) + 1}, Quorum={is_quorum}"
        )
        return is_quorum, success_count

    async def _query_value_contact(self, contact: Contact, storage_key: bytes) -> Tuple[Optional[NodeRecord], List[Contact]]:
        """Отправляет FIND_VALUE_REQUEST одному узлу."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(contact.host, contact.port), timeout=3.0
            )
            conn = Connection(reader, writer)
            record, contacts = await self.rpc.send_find_value(conn, storage_key)
            await conn.close()
            return record, contacts
        except Exception:
            return None, []

    async def _query_cache_store(self, contact: Contact, record: NodeRecord):
        """Фоновое кэширование найденной записи на ближайшем узле (Kademlia caching)."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(contact.host, contact.port), timeout=2.0
            )
            conn = Connection(reader, writer)
            await self.rpc.send_store(conn, record)
            await conn.close()
        except Exception:
            pass

    async def find_value(self, storage_key: bytes) -> Optional[NodeRecord]:
        """
        Итеративный поиск значения в Kademlia DHT (ТЗ Раздел 10.1, 10.3).
        Опрашивает узлы группами по ALPHA = 3.
        Если узел возвращает значение -> поиск завершается с успехом.
        """
        # 1. Проверяем локальное хранилище
        local_rec = self.storage.get(storage_key)
        if local_rec is not None:
            logger.info(f"[{self.node_id_hex}] [FIND_VALUE_LOCAL] Найдено локально: Key={storage_key.hex()[:8]}")
            return local_rec

        lookup_id = uuid.uuid4().hex[:8]
        logger.info(f"[{self.node_id_hex}] [FIND_VALUE_START] ID={lookup_id}, Key={storage_key.hex()[:8]}")
        start_time = time.time()
        queried = set()

        candidates = self.routing_table.get_closest_contacts(storage_key, self.k_size * 2)
        if not candidates:
            logger.info(f"[{self.node_id_hex}] [FIND_VALUE_EMPTY] Таблица маршрутизации пуста")
            return None

        seen_ids = {c.node_id for c in candidates}
        iterations = 0
        rpc_count = 0
        empty_nodes: List[Contact] = []

        while True:
            iterations += 1
            candidates.sort(key=lambda c: xor_distance(c.node_id, storage_key))

            k_closest = candidates[:self.k_size]
            unqueried_in_k = [c for c in k_closest if c.node_id not in queried]
            if not unqueried_in_k:
                break

            unqueried_all = [c for c in candidates if c.node_id not in queried]
            to_query = unqueried_all[:self.alpha]
            if not to_query:
                break

            tasks = []
            for c in to_query:
                queried.add(c.node_id)
                tasks.append(self._query_value_contact(c, storage_key))
                rpc_count += 1

            results = await asyncio.gather(*tasks, return_exceptions=True)

            found_record: Optional[NodeRecord] = None
            for idx, res in enumerate(results):
                if isinstance(res, tuple):
                    rec, closer_contacts = res
                    contact_queried = to_query[idx]
                    if rec is not None:
                        found_record = rec
                        break
                    else:
                        empty_nodes.append(contact_queried)
                        for new_c in closer_contacts:
                            if new_c.node_id != self.identity.node_id and new_c.node_id not in seen_ids:
                                seen_ids.add(new_c.node_id)
                                candidates.append(new_c)

            if found_record is not None:
                elapsed = time.time() - start_time
                logger.info(
                    f"[{self.node_id_hex}] [FIND_VALUE_SUCCESS] ID={lookup_id}, "
                    f"Key={storage_key.hex()[:8]}, RPC={rpc_count}, Elapsed={elapsed:.3f}s"
                )
                if empty_nodes:
                    closest_empty = min(empty_nodes, key=lambda c: xor_distance(c.node_id, storage_key))
                    try:
                        asyncio.create_task(self._query_cache_store(closest_empty, found_record))
                    except Exception:
                        pass
                return found_record

            if all(c.node_id in queried for c in candidates):
                break

        elapsed = time.time() - start_time
        logger.info(
            f"[{self.node_id_hex}] [FIND_VALUE_FAIL] ID={lookup_id}, "
            f"Key={storage_key.hex()[:8]}, RPC={rpc_count}, Elapsed={elapsed:.3f}s"
        )
        return None

    def start_cleanup_loop(self, interval: float = 30.0) -> asyncio.Task:
        """Запускает периодическую очистку устаревших по TTL записей в хранилище."""
        async def loop():
            while True:
                try:
                    await asyncio.sleep(interval)
                    removed = self.storage.cleanup_expired()
                    if removed > 0:
                        logger.info(f"[{self.node_id_hex}] Фоновая очистка: удалено {removed} истекших записей")
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.debug(f"[{self.node_id_hex}] Ошибка очистки хранилища: {e}")

        task = asyncio.create_task(loop())
        self._bg_tasks.append(task)
        return task

    def start_republish_loop(self, interval: float = 60.0, ttl_seconds: int = 180) -> asyncio.Task:
        """
        Запускает периодическое переопубликование собственной записи владельцем (ТЗ Раздел 10.3).
        Интервал переопубликования не должен превышать половины TTL.
        """
        async def loop():
            while True:
                try:
                    await asyncio.sleep(interval)
                    logger.info(f"[{self.node_id_hex}] Плановое переопубликование NodeRecord (TTL refresh)...")
                    await self.publish_record(ttl_seconds=ttl_seconds)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.debug(f"[{self.node_id_hex}] Ошибка переопубликования: {e}")

        task = asyncio.create_task(loop())
        self._bg_tasks.append(task)
        return task