import asyncio
import logging
import time
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
        Итеративный поиск узла (ТЗ Раздел 21).
        Использует ALPHA = 3 параллельных запросов.
        """
        start_time = time.time()
        queried = set()
        
        # Берем начальных кандидатов из своей таблицы
        candidates = self.routing_table.get_closest_contacts(target_node_id, self.k_size)
        if not candidates:
            return []

        iterations = 0
        rpc_count = 0

        while True:
            iterations += 1
            # Сортируем кандидатов по близости
            candidates.sort(key=lambda c: xor_distance(c.node_id, target_node_id))
            
            # Выбираем до ALPHA неопрошенных кандидатов
            unqueried = [c for c in candidates if c.node_id not in queried][:self.alpha]
            
            if not unqueried:
                break # Исчерпан пул кандидатов
                
            tasks = []
            for c in unqueried:
                queried.add(c.node_id)
                tasks.append(self._query_contact(c, target_node_id))
                rpc_count += 1
            
            # Опрашиваем параллельно (ALPHA запросов)
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            new_nodes_found = False
            for res in results:
                if isinstance(res, list):
                    for new_contact in res:
                        if new_contact.node_id != self.identity.node_id and new_contact not in candidates:
                            candidates.append(new_contact)
                            new_nodes_found = True
            
            # ТЗ: Поиск завершается, если новые узлы не улучшают ближайшую k-выборку
            if not new_nodes_found:
                break

        candidates.sort(key=lambda c: xor_distance(c.node_id, target_node_id))
        closest = candidates[:self.k_size]
        
        elapsed = time.time() - start_time
        logger.info(f"[{self.node_id_hex}] Lookup завершен: {rpc_count} RPC, {iterations} итераций, {elapsed:.2f} сек.")
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