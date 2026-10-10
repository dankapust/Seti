import asyncio
import os
import shutil
import tempfile
import hashlib
import pytest

from src.identity.identity import NodeIdentity
from src.routing.contact import Contact, xor_distance
from src.routing.table import KBucket, RoutingTable
from src.node.kademlia_node import KademliaNode
from src.rpc.kademlia import KademliaRPC
from src.transport import Dispatcher

def make_test_contact(port: int, node_id: bytes = None) -> Contact:
    """Вспомогательная функция для создания валидного контакта с правильным NodeID."""
    if node_id is None:
        priv_bytes = os.urandom(32)
        pub_bytes = hashlib.sha256(priv_bytes).digest()
        node_id = hashlib.sha256(pub_bytes).digest()
    else:
        pub_bytes = node_id  # для тестов
    return Contact(
        node_id=node_id,
        identity_algorithm="Ed25519",
        identity_public_key=pub_bytes,
        host="127.0.0.1",
        port=port
    )

def test_identity_generation_and_determinism():
    """Проверка генерации ключей и детерминированности NodeID = SHA256(PublicKey)."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        ident1 = NodeIdentity.load_or_generate(tmp_dir)
        assert len(ident1.node_id) == 32
        assert len(ident1.public_key_bytes) == 32
        assert hashlib.sha256(ident1.public_key_bytes).digest() == ident1.node_id
        
        # Повторная загрузка из той же папки должна возвращать тот же NodeID
        ident2 = NodeIdentity.load_or_generate(tmp_dir)
        assert ident1.node_id == ident2.node_id
        assert ident1.public_key_bytes == ident2.public_key_bytes

def test_xor_distance_properties():
    """Проверка математических свойств XOR-метрики."""
    id_a = os.urandom(32)
    id_b = os.urandom(32)
    id_c = os.urandom(32)

    # 1. d(x, x) = 0
    assert xor_distance(id_a, id_a) == 0

    # 2. Симметричность: d(x, y) == d(y, x)
    assert xor_distance(id_a, id_b) == xor_distance(id_b, id_a)

    # 3. Неотрицательность
    assert xor_distance(id_a, id_b) >= 0

def test_kbucket_lru_and_overflow():
    """Проверка емкости KBucket и возврата oldest при переполнении."""
    k_size = 3
    bucket = KBucket(k_size)
    
    contacts = [make_test_contact(8000 + i) for i in range(4)]
    
    # Добавляем 3 контакта (заполняем корзину)
    for c in contacts[:3]:
        added, oldest = bucket.add_or_update(c)
        assert added is True
        assert oldest is None
    
    assert len(bucket.contacts) == 3
    assert bucket.contacts[0] == contacts[0] # Самый старый (oldest)

    # Попытка добавить 4-й контакт при заполненной корзине
    added, oldest = bucket.add_or_update(contacts[3])
    assert added is False
    assert oldest == contacts[0] # Должен вернуть именно oldest

    # Обновление существующего контакта перемещает его в конец
    c0 = contacts[0]
    added, oldest = bucket.add_or_update(c0)
    assert added is True
    assert bucket.contacts[-1] == c0

@pytest.mark.asyncio
async def test_kbucket_oldest_eviction_when_unresponsive():
    """
    Проверка замечания E2-6 / E2-1:
    При переполнении корзины отправляется PING кандидату oldest.
    Если oldest недоступен (таймаут) -> он вытесняется из таблицы, а новый кандидат добавляется.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        node_ident = NodeIdentity.load_or_generate(tmp_dir)
        table = RoutingTable(node_ident.node_id, k_size=1) # корзина размера 1
        dispatcher = Dispatcher()
        rpc = KademliaRPC(dispatcher, node_ident, table, "127.0.0.1", 9999, ping_timeout=0.2)

        # Контакт 1: узел на несуществующем порту (заведомо недоступен)
        dead_contact = make_test_contact(59999)
        added, oldest = table.add_contact(dead_contact)
        assert added is True
        assert len(table.get_closest_contacts(os.urandom(32), 10)) == 1

        # Контакт 2: новый кандидат
        new_candidate = make_test_contact(59998)
        
        # Запускаем процедуру ping_and_evict
        await rpc.ping_and_evict(dead_contact, new_candidate)

        # Мертвый контакт должен быть удален, а новый кандидат добавлен!
        closest = table.get_closest_contacts(os.urandom(32), 10)
        assert len(closest) == 1
        assert closest[0].node_id == new_candidate.node_id
        assert closest[0].node_id != dead_contact.node_id

@pytest.mark.asyncio
async def test_kbucket_oldest_retained_when_responsive():
    """
    Проверка замечания E2-6 / E2-1:
    Если oldest ответил на PING -> он сохраняется в корзине (перемещается в конец),
    а новый кандидат отбрасывается.
    """
    with tempfile.TemporaryDirectory() as tmp_dir1, tempfile.TemporaryDirectory() as tmp_dir2:
        # Запускаем настоящий живой узел (oldest)
        live_node = KademliaNode(tmp_dir1, "127.0.0.1", 9555, k_size=1)
        await live_node.start()

        try:
            # Создаем локальный узел
            local_ident = NodeIdentity.load_or_generate(tmp_dir2)
            table = RoutingTable(local_ident.node_id, k_size=1)
            dispatcher = Dispatcher()
            rpc = KademliaRPC(dispatcher, local_ident, table, "127.0.0.1", 9556, ping_timeout=1.0)

            # Добавляем живой контакт в корзину
            live_contact = live_node.rpc.get_local_contact()
            table.add_contact(live_contact)

            # Пытаемся вытеснить его новым кандидатом
            candidate = make_test_contact(9557)
            await rpc.ping_and_evict(live_contact, candidate)

            # Живой узел должен ОСТАТЬСЯ в таблице, а кандидат не должен попасть
            closest = table.get_closest_contacts(os.urandom(32), 10)
            assert len(closest) == 1
            assert closest[0].node_id == live_contact.node_id
        finally:
            await live_node.stop()

@pytest.mark.asyncio
async def test_lookup_node_queries_all_candidates_not_premature():
    """
    Проверка замечания E2-4:
    Проверяем, что lookup_node не завершается преждевременно, если на первой итерации
    не возвращены новые узлы, но в пуле еще остались неопрошенные кандидаты.
    """
    with tempfile.TemporaryDirectory() as state_dir:
        # Создаем узел с alpha=2 и k_size=4
        node = KademliaNode(state_dir, "127.0.0.1", 9600, k_size=4, alpha=2)
        
        # Добавляем 4 контакта в локальную таблицу
        c1 = make_test_contact(9601)
        c2 = make_test_contact(9602)
        c3 = make_test_contact(9603)
        c4 = make_test_contact(9604)
        for c in [c1, c2, c3, c4]:
            node.routing_table.add_contact(c)

        queried_contacts = []
        # Мокаем _query_contact чтобы следить за опрошенными узлами
        async def mock_query(contact, target):
            queried_contacts.append(contact.node_id)
            # Возвращаем пустой список (нет новых узлов)
            return []

        node._query_contact = mock_query

        target_id = os.urandom(32)
        results = await node.lookup_node(target_id)

        # Все 4 кандидата должны быть опрошены (в 2 итерации по alpha=2),
        # а не только первые 2!
        assert len(queried_contacts) == 4
        assert set(queried_contacts) == {c1.node_id, c2.node_id, c3.node_id, c4.node_id}
        assert len(results) == 4

@pytest.mark.asyncio
async def test_multi_node_bootstrap_and_lookup():
    """
    Интеграционный тест: 4 узла соединяются через Star Bootstrap,
    после чего последний узел успешно находит первый узел через DHT Lookup.
    """
    temp_dirs = [tempfile.mkdtemp() for _ in range(4)]
    nodes = []
    base_port = 9700

    try:
        # 1. Запуск Seed узла
        seed = KademliaNode(temp_dirs[0], "127.0.0.1", base_port, k_size=4, alpha=3)
        await seed.start()
        nodes.append(seed)

        # 2. Запуск остальных 3 узлов
        for i in range(1, 4):
            node = KademliaNode(temp_dirs[i], "127.0.0.1", base_port + i, k_size=4, alpha=3)
            await node.start()
            await node.bootstrap("127.0.0.1", base_port)
            nodes.append(node)
            await asyncio.sleep(0.1)

        # 3. Lookup: узел 3 ищет узел 1
        target_id = nodes[1].identity.node_id
        initiator = nodes[3]
        closest = await initiator.lookup_node(target_id)

        # Проверяем, что целевой узел найден
        found_ids = {c.node_id for c in closest}
        assert target_id in found_ids

    finally:
        for n in nodes:
            await n.stop()
        for d in temp_dirs:
            shutil.rmtree(d, ignore_errors=True)
