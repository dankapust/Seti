import asyncio
import logging
import time
import uuid
from typing import List, Tuple
from src.transport.connection import Connection
from src.transport.dispatcher import Dispatcher
from src.identity.identity import NodeIdentity
from src.routing.table import RoutingTable
from src.routing.contact import Contact, xor_distance
from src.rpc.kademlia import KademliaRPC

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
        
        # 3. Настраиваем RPC и Диспетчер
        self.dispatcher = Dispatcher()
        self.rpc = KademliaRPC(self.dispatcher, self.identity, self.routing_table, host, port)
        
        self.server = None

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