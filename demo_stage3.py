import asyncio
import logging
import sys
import os
import shutil
import time
from src.node.kademlia_node import KademliaNode
from src.storage.record import NodeRecord

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logs/stage3_demo.log", encoding="utf-8")
    ]
)
logger = logging.getLogger("Stage3Demo")

async def run_stage3():
    print("=" * 80)
    print("  STAGE 3 DEMO: STORE, FIND_VALUE, SIGNATURES, TTL & REPLICA FAILURE TOLERANCE")
    print("=" * 80)

    # Очищаем старое состояние для чистоты эксперимента
    if os.path.exists("./state"):
        shutil.rmtree("./state")

    # -------------------------------------------------------------------------
    # 1. КРИПТОГРАФИЧЕСКАЯ ПОДПИСЬ И ВАЛИДАЦИЯ NodeRecord (ТЗ Раздел 10.3)
    # -------------------------------------------------------------------------
    print("\n--- ТЕСТ 1: СОЗДАНИЕ И ВАЛИДАЦИЯ ПОДПИСАННОЙ NodeRecord (Ed25519) ---")
    owner_node = KademliaNode("./state/owner_node", "127.0.0.1", 9200, k_size=4)
    rec = NodeRecord.create(
        identity=owner_node.identity,
        addresses=["127.0.0.1:9200"],
        sequence_number=1,
        ttl_seconds=300
    )
    is_valid, reason = rec.verify()
    print(f"NodeRecord сгенерирована: NodeID={rec.node_id.hex()[:8]}, Seq={rec.sequence_number}")
    print(f"Ключ хранения в DHT: {rec.get_storage_key().hex()[:8]}")
    print(f"Подпись Ed25519: {rec.signature.hex()[:16]}... (длина {len(rec.signature)} байт)")
    if is_valid:
        print("[SUCCESS] Криптографическая валидация NodeRecord успешно пройдена!")
    else:
        print(f"[FAIL] Ошибка валидации: {reason}")

    # -------------------------------------------------------------------------
    # 2. ЗАЩИТА ОТ АТАК ПОДМЕНЫ И ОТКАТА ВЕРСИИ (ROLLBACK PROTECTION)
    # -------------------------------------------------------------------------
    print("\n--- ТЕСТ 2: ЗАЩИТА ОТ ПОДДЕЛКИ ПОДПИСИ И ОТКАТА sequence_number ---")
    # Попытка 1: испорченная подпись
    fake_rec = NodeRecord.from_dict(rec.to_dict())
    fake_rec.signature = os.urandom(64)
    fake_ok, fake_err = fake_rec.verify()
    print(f"Попытка валидации записи с фальшивой подписью: Valid={fake_ok}, Причина={fake_err}")
    assert fake_ok is False

    # Попытка 2: защита от отката версии в локальном хранилище
    stored_ok, _ = owner_node.storage.put(rec)
    print(f"Исходная запись (seq=1) сохранена в хранилище: {stored_ok}")
    
    # Пытаемся записать повторно seq=1 или seq=0
    rollback_rec = NodeRecord.create(owner_node.identity, ["127.0.0.1:9200"], sequence_number=1)
    rb_ok, rb_err = owner_node.storage.put(rollback_rec)
    print(f"Попытка записи с seq={rollback_rec.sequence_number} (откат): Accepted={rb_ok}, Причина={rb_err}")
    assert rb_ok is False
    print("[SUCCESS] Защита от подделки и отката версий (Rollback Protection) сработала корректно!")

    # -------------------------------------------------------------------------
    # 3. РАЗВЕРТЫВАНИЕ СЕТИ И РЕПЛИКАЦИЯ STORE НА R=3 ХРАНИТЕЛЕЙ
    # -------------------------------------------------------------------------
    print("\n--- ТЕСТ 3: РАЗВЕРТЫВАНИЕ СЕТИ И РЕПЛИКАЦИЯ STORE (R=3, QUORUM >= 2) ---")
    seed = KademliaNode("./state/net_seed", "127.0.0.1", 9500, k_size=4, alpha=3)
    await seed.start()

    net_nodes = [seed]
    for i in range(1, 5):
        port = 9500 + i
        n = KademliaNode(f"./state/net_node_{i}", "127.0.0.1", port, k_size=4, alpha=3)
        await n.start()
        await n.bootstrap("127.0.0.1", 9500)
        net_nodes.append(n)
        await asyncio.sleep(0.1)

    publisher = net_nodes[4] # Узел 9504 публикует данные
    pub_rec = NodeRecord.create(
        publisher.identity,
        addresses=["127.0.0.1:9504"],
        sequence_number=1,
        ttl_seconds=180
    )
    storage_key = pub_rec.get_storage_key()

    print(f"Узел {publisher.node_id_hex} (порт 9504) реплицирует запись на R=3 ближайших узла...")
    quorum_ok, confirmations = await publisher.store_record(pub_rec, replicas=3, min_success=2)
    print(f"Результат STORE: Quorum={quorum_ok}, Подтверждений={confirmations}")
    assert quorum_ok is True
    print("[SUCCESS] Кворум репликации (>= 2 подтверждений) успешно достигнут!")

    # Ищем, какие узлы сохранили запись
    holders = [n for n in net_nodes if n.storage.get(storage_key) is not None and n != publisher]
    print(f"Узлы-хранители реплик в сети: {[h.node_id_hex + ' (порт ' + str(h.port) + ')' for h in holders]}")

    # -------------------------------------------------------------------------
    # 4. КОНТРОЛЬНЫЙ СЦЕНАРИЙ: ПОИСК ЗАПИСИ ПОСЛЕ ОТКАЗА ХРАНИТЕЛЯ
    # -------------------------------------------------------------------------
    print("\n--- ТЕСТ 4: ПОИСК ЗАПИСИ (FIND_VALUE) ПОСЛЕ ОТКАЗА ХРАНИТЕЛЯ ---")
    failed_replica = holders[0]
    logger.info(f"Имитация аварии: принудительно останавливаем узел-хранитель {failed_replica.node_id_hex} (порт {failed_replica.port})...")
    await failed_replica.stop()
    print(f"Хранитель {failed_replica.node_id_hex} отключен (offline).")

    # Ищем независимый узел, который НЕ хранит запись локально
    non_holders = [n for n in net_nodes if n.storage.get(storage_key) is None and n != publisher and n != failed_replica]
    searcher = non_holders[0] if non_holders else net_nodes[1]
    logger.info(f"Узел {searcher.node_id_hex} (порт {searcher.port}, без локальной копии) начинает итеративный поиск FIND_VALUE для ключа {storage_key.hex()[:8]}...")
    found = await searcher.find_value(storage_key)

    if found is not None:
        print(f"[SUCCESS] Запись успешно обнаружена в сети после отказа хранителя!")
        print(f"  Владелец NodeID: {found.node_id.hex()[:8]}")
        print(f"  Адреса: {found.addresses}")
        print(f"  Sequence Number: {found.sequence_number}")
        print(f"  Срок действия (TTL): {found.expires_at - found.issued_at} сек")
    else:
        print("[FAIL] Запись не найдена после отказа хранителя!")
        assert False

    # -------------------------------------------------------------------------
    # 5. ДЕМОНСТРАЦИЯ ИСТЕЧЕНИЯ СРОКА ДЕЙСТВИЯ (TTL)
    # -------------------------------------------------------------------------
    print("\n--- ТЕСТ 5: КОНТРОЛЬ TTL И ОЧИСТКА ХРАНИЛИЩА ---")
    short_rec = NodeRecord.create(publisher.identity, ["127.0.0.1:9504"], sequence_number=2, ttl_seconds=2)
    searcher.storage.put(short_rec)
    print(f"Запись с коротким TTL (2 сек) сохранена у узла {searcher.node_id_hex}.")
    print("Ожидание 2.5 секунды для естественного истечения TTL...")
    await asyncio.sleep(2.5)

    expired_res = searcher.storage.get(short_rec.get_storage_key())
    if expired_res is None:
        print("[SUCCESS] Истекшая по TTL запись автоматически аннулирована и удалена!")
    else:
        print("[FAIL] Запись не была удалена после истечения срока TTL.")

    # 6. Завершение работы
    for n in net_nodes:
        try:
            await n.stop()
        except Exception:
            pass

    print("\n" + "=" * 80)
    print(" [STAGE 3 DEMO COMPLETED SUCCESSFULLY]")
    print(f" [LOG FILE] {os.path.abspath('logs/stage3_demo.log')}")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(run_stage3())
