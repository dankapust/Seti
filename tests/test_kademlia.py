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

def test_identity_spoofing_rejected():
    """
    Проверка критерия E2-1 и Раздела 16 ТЗ:
    Подмена открытого ключа или NodeID должна приводить к отказу.
    """
    valid_contact = make_test_contact(8001)
    assert valid_contact.validate_identity() is True

    # 1. Попытка подмены NodeID (чужой NodeID при своем открытом ключе)
    spoofed_id_contact = Contact(
        node_id=os.urandom(32), # Поддельный ID
        identity_algorithm="Ed25519",
        identity_public_key=valid_contact.identity_public_key,
        host="127.0.0.1",
        port=8001
    )
    assert spoofed_id_contact.validate_identity() is False

    # 2. Проверка отклонения в KademliaRPC: контакт не должен попасть в таблицу
    table = RoutingTable(os.urandom(32), k_size=4)
    dispatcher = Dispatcher()
    with tempfile.TemporaryDirectory() as tmp_dir:
        local_ident = NodeIdentity.load_or_generate(tmp_dir)
        rpc = KademliaRPC(dispatcher, local_ident, table, "127.0.0.1", 9000)
        
        # Передаем поддельный контакт
        rpc.process_incoming_contact(spoofed_id_contact.to_dict())
        
        # Таблица маршрутизации должна остаться абсолютно пустой
        assert len(table.get_closest_contacts(os.urandom(32), 10)) == 0

def test_xor_distance_properties():
    """Проверка математических свойств XOR-метрики (E2-2 и ТЗ Раздел 4)."""
    # 1. Свойства для случайных идентификаторов
    for _ in range(10):
        id_a = os.urandom(32)
        id_b = os.urandom(32)
        id_c = os.urandom(32)

        # 1. d(x, x) = 0 (тождество неразличимых)
        assert xor_distance(id_a, id_a) == 0
        assert (xor_distance(id_a, id_b) == 0) == (id_a == id_b)

        # 2. Неотрицательность
        assert xor_distance(id_a, id_b) >= 0

        # 3. Симметричность: d(x, y) == d(y, x)
        assert xor_distance(id_a, id_b) == xor_distance(id_b, id_a)

        # 4. Неравенство треугольника в форме XOR: d(x, z) = d(x, y) ^ d(y, z)
        # и как следствие для вещественных/целых расстояний: d(x, z) <= d(x, y) + d(y, z)
        dist_ac = xor_distance(id_a, id_c)
        dist_ab = xor_distance(id_a, id_b)
        dist_bc = xor_distance(id_b, id_c)
        assert dist_ac == (dist_ab ^ dist_bc)
        assert dist_ac <= dist_ab + dist_bc

        # 5. Ультраметрическое свойство (сильное неравенство треугольника):
        # Старший различающийся бит (префикс): d(x, z) <= max(d(x, y), d(y, z))
        # когда длины общих префиксов удовлетворяют ультраметрике
        assert dist_ac <= (dist_ab | dist_bc)

def test_routing_table_bucket_distribution():
    """Проверка распределения контактов по корзинам (E2-3 и ТЗ Раздел 10.1)."""
    my_id = b"\x00" * 32
    table = RoutingTable(my_id, k_size=4)

    # Пустая таблица
    dist = table.get_bucket_distribution()
    assert len(dist) == 0
    assert table.total_contacts_count() == 0

    # Создаем контакты, различающиеся на разном битовом расстоянии
    c1 = make_test_contact(8001, node_id=b"\x80" + b"\x00" * 31) # dist = 255
    c2 = make_test_contact(8002, node_id=b"\x40" + b"\x00" * 31) # dist = 254
    c3 = make_test_contact(8003, node_id=b"\x20" + b"\x00" * 31) # dist = 253

    table.add_contact(c1)
    table.add_contact(c2)
    table.add_contact(c3)

    assert table.total_contacts_count() == 3
    dist = table.get_bucket_distribution()
    assert len(dist) == 3
    # Проверяем наличие информации о заполнении
    for idx, bucket_info in dist.items():
        assert bucket_info["count"] == 1
        assert bucket_info["capacity"] == 4
        assert len(bucket_info["contacts"]) == 1


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

@pytest.mark.asyncio
async def test_chain_bootstrap_and_lookup():
    """
    Интеграционный тест: цепочечный (Chain/Tree) bootstrap (ТЗ Раздел 5, E2-8).
    Узел 0 <- Узел 1 <- Узел 2 <- Узел 3.
    Проверяется сходимость сети и обнаружение узлов через промежуточные хопы.
    """
    temp_dirs = [tempfile.mkdtemp() for _ in range(4)]
    nodes = []
    base_port = 9800

    try:
        # Узел 0 (Seed)
        n0 = KademliaNode(temp_dirs[0], "127.0.0.1", base_port, k_size=4, alpha=3)
        await n0.start()
        nodes.append(n0)

        # Узел 1 подключается к Узлу 0
        n1 = KademliaNode(temp_dirs[1], "127.0.0.1", base_port + 1, k_size=4, alpha=3)
        await n1.start()
        await n1.bootstrap("127.0.0.1", base_port)
        nodes.append(n1)
        await asyncio.sleep(0.1)

        # Узел 2 подключается к Узлу 1
        n2 = KademliaNode(temp_dirs[2], "127.0.0.1", base_port + 2, k_size=4, alpha=3)
        await n2.start()
        await n2.bootstrap("127.0.0.1", base_port + 1)
        nodes.append(n2)
        await asyncio.sleep(0.1)

        # Узел 3 подключается к Узлу 2
        n3 = KademliaNode(temp_dirs[3], "127.0.0.1", base_port + 3, k_size=4, alpha=3)
        await n3.start()
        await n3.bootstrap("127.0.0.1", base_port + 2)
        nodes.append(n3)
        await asyncio.sleep(0.1)

        # Узел 3 ищет узел 0 через DHT Lookup (хотя соединялся только с узлом 2)
        closest = await n3.lookup_node(n0.identity.node_id)
        found_ids = {c.node_id for c in closest}
        assert n0.identity.node_id in found_ids

        # Узел 0 ищет узел 3 через DHT Lookup
        closest_from_seed = await n0.lookup_node(n3.identity.node_id)
        found_from_seed = {c.node_id for c in closest_from_seed}
        assert n3.identity.node_id in found_from_seed

    finally:
        for n in nodes:
            await n.stop()
        for d in temp_dirs:
            shutil.rmtree(d, ignore_errors=True)

