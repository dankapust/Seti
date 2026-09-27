import asyncio
import logging
import sys
import os
import shutil
from src.node.kademlia_node import KademliaNode

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler("logs/stage2_demo.log", encoding="utf-8")]
)

async def run_stage2():
    print("=" * 75)
    print(" ДЕМОНСТРАЦИЯ ЭТАПА 2: ИДЕНТИЧНОСТЬ, K-BUCKETS И KADEMLIA LOOKUP")
    print("=" * 75)

    # Очищаем старые ключи для чистого эксперимента
    if os.path.exists("./state"):
        shutil.rmtree("./state")

    # 1. Запуск Seed-узла (Bootstrap)
    seed = KademliaNode("./state/node_seed", "127.0.0.1", 9000)
    await seed.start()
    
    # 2. Запуск еще 4 узлов и их bootstrap
    nodes = []
    for i in range(1, 5):
        port = 9000 + i
        node = KademliaNode(f"./state/node_{i}", "127.0.0.1", port)
        await node.start()
        # Все подключаются к Seed-узлу (Star bootstrap)
        await node.bootstrap("127.0.0.1", 9000)
        nodes.append(node)
        await asyncio.sleep(0.5) # Небольшая задержка

    # 3. Контрольный Lookup (ТЗ Раздел 25.2)
    node_initiator = nodes[3] # Последний узел (порт 9004)
    target_node = nodes[0]    # Ищем первый узел (порт 9001)
    
    print("\n--- ЗАПУСК КОНТРОЛЬНОГО LOOKUP ---")
    # Инициатор ищет target_node.id
    closest = await node_initiator.lookup_node(target_node.identity.node_id)
    
    found = any(c.node_id == target_node.identity.node_id for c in closest)
    if found:
        print(f"✅ УСПЕХ: Узел {node_initiator.node_id_hex} успешно нашел {target_node.node_id_hex} через DHT!")
    else:
        print(f"❌ ОШИБКА: Целевой узел не найден в результатах Lookup.")

    # 4. Завершение работы
    await seed.stop()
    for n in nodes:
        await n.stop()
    print("=" * 75)

if __name__ == "__main__":
    asyncio.run(run_stage2())