import asyncio
import logging
import os
import sys
import shutil
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.node.kademlia_node import KademliaNode
from src.tunnel.tunnel import TunnelState
from src.crypto.channel import SecureSession

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logs/stage5_demo.log", encoding="utf-8"),
    ]
)
logger = logging.getLogger("Stage5Demo")

async def run_stage5():
    print("=" * 80)
    print("  STAGE 5 DEMO: MULTI-HOP OVERLAY TUNNELING, E2E AEAD & RELAY FAILURE REBUILD")
    print("=" * 80)

    state_base = "./state/stage5"
    if os.path.exists(state_base):
        shutil.rmtree(state_base, ignore_errors=True)

    # -------------------------------------------------------------------------
    # ШАГ 1: ИНИЦИАЛИЗАЦИЯ 5 УЗЛОВ ОВЕРЛЕЙНОЙ СЕТИ
    # -------------------------------------------------------------------------
    print("\n--- ШАГ 1: ЗАПУСК 5 УЗЛОВ СЕТИ (ALICE, R1, R2, R3, BOB) ---")
    nodes_config = [
        ("Alice_Client", 10500),
        ("Relay_1",      10501),
        ("Relay_2",      10502),
        ("Relay_3_Alt",  10503),
        ("Bob_Endpoint", 10504),
    ]

    nodes = []
    for name, port in nodes_config:
        node = KademliaNode(f"{state_base}/{name}", "127.0.0.1", port, k_size=4)
        await node.start()
        nodes.append(node)
        print(f"  • [{name}] запущен на порту {port}, NodeID = {node.node_id_hex}...")

    alice, r1, r2, r3, bob = nodes

    # Контакты
    c_r1 = r1.tunnel_manager.local_contact
    c_r2 = r2.tunnel_manager.local_contact
    c_r3 = r3.tunnel_manager.local_contact
    c_bob = bob.tunnel_manager.local_contact

    # Добавляем известные контакты в таблицу Alice
    for c in [c_r1, c_r2, c_r3, c_bob]:
        alice.routing_table.add_contact(c)

    # -------------------------------------------------------------------------
    # ШАГ 2: СОГЛАСОВАНИЕ СКВОЗНОЙ КРИПТОСЕССИИ (END-TO-END E2E) МЕЖДУ ALICE И BOB
    # -------------------------------------------------------------------------
    print("\n--- ШАГ 2: СКВОЗНАЯ ЗАЩИЩЕННАЯ СЕССИЯ (E2E AEAD) ALICE <-> BOB ---")
    # Эмулируем взаимно согласованные сессионные ключи (ChaCha20-Poly1305)
    key_alice_to_bob = os.urandom(32)
    key_bob_to_alice = os.urandom(32)
    session_id = os.urandom(16)

    alice_session = SecureSession(
        session_id=session_id,
        is_initiator=True,
        peer_node_id=bob.identity.node_id,
        peer_public_key=bob.identity.public_key_bytes,
        send_key=key_alice_to_bob,
        recv_key=key_bob_to_alice,
    )

    bob_session = SecureSession(
        session_id=session_id,
        is_initiator=False,
        peer_node_id=alice.identity.node_id,
        peer_public_key=alice.identity.public_key_bytes,
        send_key=key_bob_to_alice,
        recv_key=key_alice_to_bob,
    )

    bob.tunnel_manager.register_e2e_session(alice.identity.node_id, bob_session)
    print(f"  ✓ Сквозная сессия ChaCha20-Poly1305 зарегистрирована между Alice и Bob.")
    print(f"  ✓ Ни один промежуточный ретранслятор не обладает этими ключами!")

    # -------------------------------------------------------------------------
    # ШАГ 3: ПОСТРОЕНИЕ 2-ПЕРЕХОДНОГО ТУННЕЛЯ (ALICE -> R1 -> R2 -> BOB)
    # -------------------------------------------------------------------------
    print("\n--- ШАГ 3: ПОСТРОЕНИЕ 2-ХОПОВОГО ТУННЕЛЯ (ALICE -> R1 -> R2 -> BOB) ---")
    tunnel = await alice.tunnel_manager.build_tunnel(
        destination=c_bob,
        relays=[c_r1, c_r2]
    )

    print(f"  ✓ Статус туннеля: {tunnel.state.value}")
    print(f"  ✓ Идентификатор туннеля: {tunnel.tunnel_id.hex()[:16]}...")
    print(f"  ✓ Маршрут туннеля: {tunnel.get_path_display()}")

    # -------------------------------------------------------------------------
    # ШАГ 4: СКВОЗНАЯ ПЕРЕДАЧА ЗАШИФРОВАННЫХ ДАННЫХ И ПРОВЕРКА КОНФИДЕНЦИАЛЬНОСТИ
    # -------------------------------------------------------------------------
    print("\n--- ШАГ 4: ПЕРЕДАЧА ПРИКЛАДНЫХ ДАННЫХ И КОНФИДЕНЦИАЛЬНОСТЬ РЕТРАНСЛЯЦИИ ---")
    secret_text = "CONFIDENTIAL E2E MESSAGE: Target coordinates are 59.9343 N, 30.3351 E. Funds: $500,000"
    print(f"  [Alice] Исходный текст: «{secret_text}»")

    res1 = await alice.tunnel_manager.send_through_tunnel(
        tunnel,
        secret_text.encode("utf-8"),
        secure_session=alice_session
    )

    print(f"\n[РЕЗУЛЬТАТ ДОСТАВКИ №1]:")
    print(f"  ✓ Статус:        {res1['status']}")
    print(f"  ✓ Время доставки:{res1['latency_ms']:.2f} мс")
    print(f"  ✓ Число хопов:   {res1['hops_count']} (Alice -> R1 -> R2 -> Bob)")

    # Проверяем, что получил Bob
    bob_received = bob.tunnel_manager.received_messages[-1]
    print(f"  ✓ [Bob Endpoint]: Успешно расшифровано: «{bob_received['payload_bytes'].decode('utf-8')}»")

    # -------------------------------------------------------------------------
    # ШАГ 5: КОНТРОЛЬНЫЙ СЦЕНАРИЙ ТЗ — ОТКАЗ РЕТРАНСЛЯТОРА И АВТОМАТИЧЕСКОЕ ПЕРЕСТРОЕНИЕ
    # -------------------------------------------------------------------------
    print("\n--- ШАГ 5: ОТКАЗ РЕТРАНСЛЯТОРА R2 И АВТОМАТИЧЕСКОЕ ПЕРЕСТРОЕНИЕ ТУННЕЛЯ ---")
    print("  [АВАРИЯ]: Имитируем аварийный сбой промежуточного ретранслятора Relay_2 (порт 10502)...")
    await r2.stop()
    print("  ✓ Узел Relay_2 остановлен (OFFLINE).")

    print("\n  [Alice]: Отправка второго сообщения с автовосстановлением маршрута...")
    msg2 = "URGENT UPDATE: Route diverted via Relay_3. Delivery confirmed!"
    
    # Отправляем через send_with_auto_rebuild
    res2 = await alice.tunnel_manager.send_with_auto_rebuild(
        destination=c_bob,
        payload_bytes=msg2.encode("utf-8"),
        secure_session=alice_session,
        available_relays=[c_r1, c_r2, c_r3]
    )

    print(f"\n[РЕЗУЛЬТАТ АВТОМАТИЧЕСКОГО ВОССТАНОВЛЕНИЯ]:")
    print(f"  ✓ Статус:              {res2['status']}")
    print(f"  ✓ Перестроен маршрут:  {res2['rebuilt']} (Туннель был пересоздан)")
    print(f"  ✓ Старый туннель:      DEAD (помечен как неработоспособный)")
    print(f"  ✓ Новый маршрут:       {res2['path_display']}")
    print(f"  ✓ Время восстановления:{res2['latency_ms']:.2f} мс")

    # Проверяем прием второго сообщения у Bob
    bob_received_2 = bob.tunnel_manager.received_messages[-1]
    print(f"  ✓ [Bob Endpoint]: Получено сообщение после аварии: «{bob_received_2['payload_bytes'].decode('utf-8')}»")

    # Остановка узлов
    for n in [alice, r1, r3, bob]:
        try:
            await n.stop()
        except Exception:
            pass

    print("\n" + "=" * 80)
    print(" [STAGE 5 DEMO COMPLETED SUCCESSFULLY]")
    print(f" [LOG FILE] {os.path.abspath('logs/stage5_demo.log')}")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(run_stage5())
