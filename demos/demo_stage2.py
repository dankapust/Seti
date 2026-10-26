import asyncio
import logging
import sys
import os
import shutil
import hashlib
from src.node.kademlia_node import KademliaNode
from src.routing.contact import Contact
from src.routing.table import RoutingTable
from src.rpc.kademlia import KademliaRPC
from src.identity.identity import NodeIdentity
from src.transport import Dispatcher

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
    handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler("logs/stage2_demo.log", encoding="utf-8")]
)
logger = logging.getLogger("Stage2Demo")

async def run_stage2():
    print("=" * 80)
    print("  STAGE 2 DEMO: ED25519 IDENTITY, K-BUCKETS, OLDEST EVICTION & KADEMLIA LOOKUP")
    print("=" * 80)

    # Очищаем старые ключи для воспроизводимого эксперимента
    if os.path.exists("./state"):
        shutil.rmtree("./state")

    # -------------------------------------------------------------
    # 1. ТЕСТ ВЫТЕСНЕНИЯ OLDEST ПРИ ПЕРЕПОЛНЕНИИ КОРЗИНЫ (E2-6 / E2-1)
    # -------------------------------------------------------------
    print("\n--- ТЕСТ 1: ПРОВЕРКА ДОСТУПНОСТИ И ВЫТЕСНЕНИЯ OLDEST (E2-6) ---")
    ident_test = NodeIdentity.load_or_generate("./state/eviction_test_node")
    # Создаем таблицу с k_size = 1 для наглядного вытеснения
    test_table = RoutingTable(ident_test.node_id, k_size=1)
    dispatcher_test = Dispatcher()
    rpc_test = KademliaRPC(dispatcher_test, ident_test, test_table, "127.0.0.1", 8999, ping_timeout=0.5)

    # Добавляем заведомо недоступный узел (порт 59999 не слушается)
    dead_pub = os.urandom(32)
    dead_id = hashlib.sha256(dead_pub).digest()
    dead_contact = Contact(dead_id, "Ed25519", dead_pub, "127.0.0.1", 59999)
    test_table.add_contact(dead_contact)
    logger.info(f"Корзина заполнена (k=1) старым контактом oldest={dead_contact.host}:{dead_contact.port}")

    # Появляется новый кандидат (порт 59998)
    cand_pub = os.urandom(32)
    cand_id = hashlib.sha256(cand_pub).digest()
    cand_contact = Contact(cand_id, "Ed25519", cand_pub, "127.0.0.1", 59998)
    logger.info(f"Попытка добавления нового кандидата {cand_contact.host}:{cand_contact.port} в полную корзину...")

    # Запускаем ping_and_evict
    await rpc_test.ping_and_evict(dead_contact, cand_contact)

    closest_evict = test_table.get_closest_contacts(os.urandom(32), 10)
    if closest_evict and closest_evict[0].node_id == cand_contact.node_id:
        print("[SUCCESS] Тест вытеснения пройден: недоступный oldest удален, новый кандидат добавлен в таблицу!")
    else:
        print("[FAIL] Ошибка вытеснения oldest.")

    # -------------------------------------------------------------
    # 2. РАЗВЕРТЫВАНИЕ СЕТИ ИЗ 5 УЗЛОВ И STAR BOOTSTRAP (СХЕМА №1)
    # -------------------------------------------------------------
    print("\n--- ТЕСТ 2: STAR BOOTSTRAP СЕТИ ИЗ 5 УЗЛОВ (СХЕМА №1) ---")
    seed = KademliaNode("./state/node_seed", "127.0.0.1", 9000, k_size=4, alpha=3)
    await seed.start()
    
    nodes = []
    for i in range(1, 5):
        port = 9000 + i
        node = KademliaNode(f"./state/node_{i}", "127.0.0.1", port, k_size=4, alpha=3)
        await node.start()
        await node.bootstrap("127.0.0.1", 9000)
        nodes.append(node)
        await asyncio.sleep(0.2)

    # Вывод распределения по корзинам (ТЗ Раздел 10.1 / E2-3)
    print("\n[ИНФОРМАЦИЯ О ТАБЛИЦЕ МАРШРУТИЗАЦИИ SEED УЗЛА]")
    seed_dist = seed.routing_table.get_bucket_distribution()
    print(f"Всего известных контактов у Seed: {seed.routing_table.total_contacts_count()}")
    for idx, b in seed_dist.items():
        print(f"  Корзина index={idx}: {b['count']}/{b['capacity']} контактов")

    # -------------------------------------------------------------
    # 3. ИТЕРАТИВНЫЙ KADEMLIA LOOKUP С ОПРОСОМ ВСЕХ КАНДИДАТОВ (E2-4)
    # -------------------------------------------------------------
    print("\n--- ТЕСТ 3: ИТЕРАТИВНЫЙ KADEMLIA LOOKUP (E2-4) ---")
    node_initiator = nodes[3] # Узел 9004
    target_node = nodes[0]    # Узел 9001
    
    logger.info(f"Узел {node_initiator.node_id_hex} (порт 9004) начинает поиск узла {target_node.node_id_hex} (порт 9001)...")
    closest = await node_initiator.lookup_node(target_node.identity.node_id)
    
    found = any(c.node_id == target_node.identity.node_id for c in closest)
    if found:
        print(f"[SUCCESS] Узел {node_initiator.node_id_hex} успешно нашел {target_node.node_id_hex} через DHT!")
    else:
        print(f"[FAIL] Целевой узел не найден в результатах Lookup.")

    # Останавливаем узлы сети Star перед вторым тестом
    await seed.stop()
    for n in nodes:
        await n.stop()

    # -------------------------------------------------------------
    # 4. СХЕМА BOOTSTRAP №2: CHAIN / ДРЕВОВИДНЫЙ BOOTSTRAP (E2-8 / ТЗ Раздел 5)
    # -------------------------------------------------------------
    print("\n--- ТЕСТ 4: СХЕМА BOOTSTRAP №2 — CHAIN (КАСКАДНОЕ ПОДКЛЮЧЕНИЕ) ---")
    chain_seed = KademliaNode("./state/chain_node_0", "127.0.0.1", 9100, k_size=4, alpha=3)
    await chain_seed.start()

    chain_nodes = [chain_seed]
    # Каждый следующий узел подключается ТОЛЬКО к предыдущему: N(i) -> N(i-1)
    for i in range(1, 4):
        prev_port = 9100 + (i - 1)
        curr_port = 9100 + i
        c_node = KademliaNode(f"./state/chain_node_{i}", "127.0.0.1", curr_port, k_size=4, alpha=3)
        await c_node.start()
        logger.info(f"Узел цепочки {c_node.node_id_hex} (порт {curr_port}) подключается к узлу на порту {prev_port}...")
        await c_node.bootstrap("127.0.0.1", prev_port)
        chain_nodes.append(c_node)
        await asyncio.sleep(0.2)

    # Проверяем сквозное обнаружение через цепочку: крайний узел 3 ищет узел 0 (корневой seed)
    last_node = chain_nodes[3]
    first_node = chain_nodes[0]
    logger.info(f"Крайний узел цепочки {last_node.node_id_hex} (порт 9103) выполняет Lookup корневого узла {first_node.node_id_hex} (порт 9100)...")
    chain_lookup = await last_node.lookup_node(first_node.identity.node_id)

    chain_found = any(c.node_id == first_node.identity.node_id for c in chain_lookup)
    if chain_found:
        print(f"[SUCCESS] Chain Bootstrap успешен: сеть сошлась через многохоповый маршрут!")
    else:
        print(f"[FAIL] Не удалось обнаружить корневой узел через цепочку.")

    # Завершение работы цепочки
    for n in chain_nodes:
        await n.stop()

    print("\n" + "=" * 80)
    print(" [STAGE 2 DEMO COMPLETED SUCCESSFULLY]")
    print(f" [LOG FILE] {os.path.abspath('logs/stage2_demo.log')}")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(run_stage2())