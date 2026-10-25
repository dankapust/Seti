import asyncio
import os
import shutil
import tempfile
import time
import pytest

from src.identity.identity import NodeIdentity
from src.storage.record import NodeRecord
from src.storage.storage import DHTStorage
from src.node.kademlia_node import KademliaNode

def test_record_creation_and_signature_verification():
    """Проверка генерации NodeRecord и криптографической подписи Ed25519."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        ident = NodeIdentity.load_or_generate(tmp_dir)
        rec = NodeRecord.create(
            identity=ident,
            addresses=["127.0.0.1:8001"],
            sequence_number=1,
            ttl_seconds=180
        )
        
        # 1. Валидная запись
        valid, reason = rec.verify()
        assert valid is True
        assert reason == "OK"

        # 2. Искажение подписи приводит к отказу
        corrupted_sig_rec = NodeRecord.from_dict(rec.to_dict())
        corrupted_sig_rec.signature = os.urandom(64)
        valid, reason = corrupted_sig_rec.verify()
        assert valid is False
        assert "signature" in reason.lower()

        # 3. Модификация адреса без переподписи приводит к отказу
        tampered_rec = NodeRecord.from_dict(rec.to_dict())
        tampered_rec.addresses = ["127.0.0.1:9999"]
        valid, reason = tampered_rec.verify()
        assert valid is False
        assert "signature" in reason.lower()

def test_record_spoofing_rejected():
    """Проверка отклонения записи при подмене открытого ключа или NodeID (ТЗ Раздел 10.3)."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        ident = NodeIdentity.load_or_generate(tmp_dir)
        rec = NodeRecord.create(ident, ["127.0.0.1:8001"])
        
        # Подменяем node_id
        spoofed = NodeRecord.from_dict(rec.to_dict())
        spoofed.node_id = os.urandom(32)
        valid, reason = spoofed.verify()
        assert valid is False
        assert "spoofing" in reason.lower()

def test_record_ttl_expiration():
    """Проверка соблюдения TTL (ТЗ Раздел 10.3)."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        ident = NodeIdentity.load_or_generate(tmp_dir)
        now = int(time.time())
        rec = NodeRecord.create(ident, ["127.0.0.1:8001"], ttl_seconds=60)
        
        # В пределах срока
        valid, _ = rec.verify(current_time=now + 30)
        assert valid is True

        # После истечения срока (now + 65 сек)
        valid, reason = rec.verify(current_time=now + 65)
        assert valid is False
        assert "expired" in reason.lower()

def test_dht_storage_rollback_protection():
    """
    Проверка защиты от атак отката (Rollback protection, ТЗ Раздел 10.3):
    Запись принимается только при монотонном возрастании sequence_number.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        ident = NodeIdentity.load_or_generate(tmp_dir)
        storage = DHTStorage()

        # 1. Первая версия (seq=1) сохраняется
        rec1 = NodeRecord.create(ident, ["127.0.0.1:8001"], sequence_number=1)
        ok, _ = storage.put(rec1)
        assert ok is True

        # 2. Попытка записать устаревшую версию (seq=1 снова или seq=0) отклоняется
        rec_replay = NodeRecord.create(ident, ["127.0.0.1:8002"], sequence_number=1)
        ok, reason = storage.put(rec_replay)
        assert ok is False
        assert "rollback" in reason.lower()

        # 3. Новая версия с seq=2 успешно принимается
        rec2 = NodeRecord.create(ident, ["127.0.0.1:8002"], sequence_number=2)
        ok, _ = storage.put(rec2)
        assert ok is True
        stored = storage.get(rec2.get_storage_key())
        assert stored.sequence_number == 2
        assert stored.addresses == ["127.0.0.1:8002"]

def test_dht_storage_ttl_cleanup():
    """Проверка автоматической очистки просроченных записей в DHTStorage."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        ident = NodeIdentity.load_or_generate(tmp_dir)
        storage = DHTStorage()

        now = int(time.time())
        rec = NodeRecord.create(ident, ["127.0.0.1:8001"], ttl_seconds=50)
        storage.put(rec, current_time=now)
        assert storage.total_count() == 1

        # До истечения TTL
        assert storage.get(rec.get_storage_key(), current_time=now + 20) is not None

        # После истечения TTL
        assert storage.get(rec.get_storage_key(), current_time=now + 60) is None
        assert storage.total_count() == 0

@pytest.mark.asyncio
async def test_store_and_find_value_rpc():
    """Проверка RPC STORE и FIND_VALUE между двумя узлами."""
    temp_dirs = [tempfile.mkdtemp() for _ in range(2)]
    nodes = []
    base_port = 9300

    try:
        n1 = KademliaNode(temp_dirs[0], "127.0.0.1", base_port, k_size=4)
        n2 = KademliaNode(temp_dirs[1], "127.0.0.1", base_port + 1, k_size=4)
        await n1.start()
        await n2.start()
        nodes = [n1, n2]

        await n2.bootstrap("127.0.0.1", base_port)

        # n1 создает и публикует запись
        rec = NodeRecord.create(n1.identity, ["127.0.0.1:9300"], sequence_number=1)
        
        # Сохраняем запись на n2
        is_quorum, count = await n1.store_record(rec, replicas=1, min_success=1)
        assert is_quorum is True

        # n2 находит эту запись локально
        found_local = n2.storage.get(rec.get_storage_key())
        assert found_local is not None
        assert found_local.node_id == n1.identity.node_id

        # n2 ищет запись через DHT find_value
        found_dht = await n2.find_value(rec.get_storage_key())
        assert found_dht is not None
        assert found_dht.node_id == n1.identity.node_id

    finally:
        for n in nodes:
            await n.stop()
        for d in temp_dirs:
            shutil.rmtree(d, ignore_errors=True)

@pytest.mark.asyncio
async def test_find_value_after_replica_failure():
    """
    Контрольный результат Этапа 3 (ТЗ Недели 5-6, Раздел 18):
    «Поиск записи после отказа хранителя».
    
    Сценарий:
    1. Сеть из 5 узлов разворачивается и сходится.
    2. Узел-владелец реплицирует запись на R=3 узла (кворум подтверждения >= 2).
    3. Один из узлов-хранителей принудительно аварийно останавливается.
    4. Другой узел запрашивает запись через FIND_VALUE и гарантированно
       находит её у оставшихся доступных реплик.
    """
    temp_dirs = [tempfile.mkdtemp() for _ in range(5)]
    nodes = []
    base_port = 9400

    try:
        # 1. Развертывание 5 узлов
        seed = KademliaNode(temp_dirs[0], "127.0.0.1", base_port, k_size=4, alpha=3)
        await seed.start()
        nodes.append(seed)

        for i in range(1, 5):
            node = KademliaNode(temp_dirs[i], "127.0.0.1", base_port + i, k_size=4, alpha=3)
            await node.start()
            await node.bootstrap("127.0.0.1", base_port)
            nodes.append(node)
            await asyncio.sleep(0.1)

        owner = nodes[4] # Узел 9404 публикует запись
        rec = NodeRecord.create(
            owner.identity,
            addresses=["127.0.0.1:9404"],
            sequence_number=1,
            ttl_seconds=300
        )
        storage_key = rec.get_storage_key()

        # 2. Репликация записи на R=3 узла (требуется кворум >= 2)
        quorum_ok, success_count = await owner.store_record(rec, replicas=3, min_success=2)
        assert quorum_ok is True
        assert success_count >= 2

        # Определяем, на каких узлах физически сохранилась запись
        storage_nodes = [n for n in nodes if n.storage.get(storage_key) is not None and n != owner]
        assert len(storage_nodes) >= 1

        # 3. Имитация отказа хранителя: останавливаем один из узлов-реплик
        failed_replica = storage_nodes[0]
        await failed_replica.stop()

        # 4. Другой узел (Node 1) ищет запись через FIND_VALUE
        searcher = nodes[1]
        found_record = await searcher.find_value(storage_key)

        # 5. Проверка: запись успешно найдена, идентичность и подпись валидны
        assert found_record is not None
        assert found_record.node_id == owner.identity.node_id
        assert found_record.sequence_number == 1
        valid, reason = found_record.verify()
        assert valid is True

    finally:
        for n in nodes:
            try:
                await n.stop()
            except Exception:
                pass
        for d in temp_dirs:
            shutil.rmtree(d, ignore_errors=True)
