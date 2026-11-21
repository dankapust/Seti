import asyncio
import os
import shutil
import tempfile
import time
import uuid
import pytest

from src.identity.identity import NodeIdentity
from src.routing.contact import Contact
from src.routing.table import RoutingTable
from src.transport.dispatcher import Dispatcher
from src.transport.protocol import MessageType
from src.crypto.channel import SecureSession
from src.tunnel.tunnel import (
    Tunnel,
    TunnelState,
    TunnelManager,
    TunnelError,
    TunnelBuildError,
    TunnelDeliveryError,
)

def make_test_contact(port: int, node_id: bytes = None) -> Contact:
    import hashlib
    if node_id is None:
        priv = os.urandom(32)
        pub = hashlib.sha256(priv).digest()
        node_id = hashlib.sha256(pub).digest()
    else:
        pub = node_id
    return Contact(
        node_id=node_id,
        identity_algorithm="Ed25519",
        identity_public_key=pub,
        host="127.0.0.1",
        port=port
    )

def test_tunnel_path_validation_min_relays():
    """Тест ТЗ Раздел 12: Туннель требует минимум 2 ретранслятора."""
    init = make_test_contact(8001)
    r1 = make_test_contact(8002)
    dest = make_test_contact(8003)

    # 1 ретранслятор вместо 2 -> отказ
    with pytest.raises(TunnelBuildError, match="минимум 2 ретранслятора"):
        Tunnel(
            tunnel_id=uuid.uuid4().bytes,
            initiator=init,
            relays=[r1],
            destination=dest
        )

def test_tunnel_path_validation_no_loops():
    """Тест ТЗ Раздел 12: Запрет петель и дублирования узлов в маршруте."""
    init = make_test_contact(8001)
    r1 = make_test_contact(8002)
    r2 = make_test_contact(8002, node_id=r1.node_id) # дубликат R1
    dest = make_test_contact(8003)

    with pytest.raises(TunnelBuildError, match="петли или повторяющиеся узлы"):
        Tunnel(
            tunnel_id=uuid.uuid4().bytes,
            initiator=init,
            relays=[r1, r2],
            destination=dest
        )

def test_tunnel_max_hops_enforced():
    """Тест ТЗ Раздел 12: Ограничение max_hops."""
    init = make_test_contact(8000)
    relays = [make_test_contact(8001 + i) for i in range(5)]
    dest = make_test_contact(8010)

    with pytest.raises(TunnelBuildError, match="превышает max_hops"):
        Tunnel(
            tunnel_id=uuid.uuid4().bytes,
            initiator=init,
            relays=relays,
            destination=dest,
            max_hops=3
        )

@pytest.mark.asyncio
async def test_multi_hop_tunnel_build_and_delivery():
    """
    Интеграционный тест: Построение 2-хопового туннеля (A -> R1 -> R2 -> B)
    и передача прикладного сообщения со сквозным подтверждением TUNNEL_ACK.
    """
    temp_dirs = [tempfile.mkdtemp() for _ in range(4)]
    from src.node.kademlia_node import KademliaNode

    ports = [10100, 10101, 10102, 10103]
    nodes = []

    try:
        # Запуск узлов: A (клиент), R1 (ретранслятор 1), R2 (ретранслятор 2), B (получатель)
        for i, port in enumerate(ports):
            node = KademliaNode(temp_dirs[i], "127.0.0.1", port, k_size=4)
            await node.start()
            nodes.append(node)

        node_a, node_r1, node_r2, node_b = nodes

        # Наполняем таблицу A контактами ретрансляторов и получателя
        contact_r1 = node_r1.tunnel_manager.local_contact
        contact_r2 = node_r2.tunnel_manager.local_contact
        contact_b = node_b.tunnel_manager.local_contact

        for c in [contact_r1, contact_r2, contact_b]:
            node_a.routing_table.add_contact(c)

        # 1. Построение туннеля через R1 и R2
        tunnel = await node_a.tunnel_manager.build_tunnel(
            destination=contact_b,
            relays=[contact_r1, contact_r2]
        )

        assert tunnel.state == TunnelState.ACTIVE
        assert tunnel.is_active is True
        assert len(tunnel.relays) == 2

        # Проверяем, что в транзитных таблицах R1 и R2 появились маршруты
        assert tunnel.tunnel_id in node_r1.tunnel_manager.forward_table
        assert node_r1.tunnel_manager.forward_table[tunnel.tunnel_id] == ("127.0.0.1", 10102)

        assert tunnel.tunnel_id in node_r2.tunnel_manager.forward_table
        assert node_r2.tunnel_manager.forward_table[tunnel.tunnel_id] == ("127.0.0.1", 10103)

        # 2. Передача данных через туннель
        test_payload = b"SECRET APPLICATION PAYLOAD VIA 2 RELAYS"
        delivery_res = await node_a.tunnel_manager.send_through_tunnel(tunnel, test_payload)

        assert delivery_res["status"] == "DELIVERED"
        assert delivery_res["hops_count"] == 3 # A->R1, R1->R2, R2->B
        assert delivery_res["latency_ms"] >= 0

        # Проверяем, что узел B получил сообщение
        assert len(node_b.tunnel_manager.received_messages) == 1
        recv_item = node_b.tunnel_manager.received_messages[0]
        assert recv_item["tunnel_id"] == tunnel.tunnel_id
        assert recv_item["payload_bytes"] == test_payload
        assert recv_item["is_duplicate"] is False

    finally:
        for n in nodes:
            await n.stop()
        for d in temp_dirs:
            shutil.rmtree(d, ignore_errors=True)

@pytest.mark.asyncio
async def test_tunnel_end_to_end_encryption():
    """
    Тест сквозного шифрования (End-to-End AEAD):
    Ретрансляторы не имеют ключей и видят только зашифрованный блоб.
    Конечный получатель успешно расшифровывает сообщение.
    """
    temp_dirs = [tempfile.mkdtemp() for _ in range(4)]
    from src.node.kademlia_node import KademliaNode

    ports = [10200, 10201, 10202, 10203]
    nodes = []

    try:
        for i, port in enumerate(ports):
            node = KademliaNode(temp_dirs[i], "127.0.0.1", port, k_size=4)
            await node.start()
            nodes.append(node)

        node_a, node_r1, node_r2, node_b = nodes

        # Создаем общие симметричные ключи между A и B (эмуляция согласованной сессии)
        key_a_to_b = os.urandom(32)
        key_b_to_a = os.urandom(32)
        session_id = os.urandom(16)

        session_a = SecureSession(
            session_id=session_id,
            is_initiator=True,
            peer_node_id=node_b.identity.node_id,
            peer_public_key=node_b.identity.public_key_bytes,
            send_key=key_a_to_b,
            recv_key=key_b_to_a,
        )

        session_b = SecureSession(
            session_id=session_id,
            is_initiator=False,
            peer_node_id=node_a.identity.node_id,
            peer_public_key=node_a.identity.public_key_bytes,
            send_key=key_b_to_a,
            recv_key=key_a_to_b,
        )

        # Регистрируем сессию на узле B
        node_b.tunnel_manager.register_e2e_session(node_a.identity.node_id, session_b)

        # Строим туннель
        tunnel = await node_a.tunnel_manager.build_tunnel(
            destination=node_b.tunnel_manager.local_contact,
            relays=[node_r1.tunnel_manager.local_contact, node_r2.tunnel_manager.local_contact]
        )

        plain_message = b"TOP SECRET: Transfer $1,000,000 to account #777-ALPHA"
        res = await node_a.tunnel_manager.send_through_tunnel(
            tunnel, plain_message, secure_session=session_a
        )
        assert res["status"] == "DELIVERED"

        # Проверяем расшифрование у получателя B
        recv_record = node_b.tunnel_manager.received_messages[0]
        assert recv_record["is_decrypted"] is True
        assert recv_record["payload_bytes"] == plain_message

    finally:
        for n in nodes:
            await n.stop()
        for d in temp_dirs:
            shutil.rmtree(d, ignore_errors=True)

@pytest.mark.asyncio
async def test_tunnel_relay_failure_and_auto_rebuild():
    """
    Контрольный эксперимент ТЗ Раздел 12 и 15:
    Отказ одного из промежуточных ретрансляторов во время работы.
    Менеджер туннелей фиксирует отказ, переводит туннель в DEGRADED/DEAD
    и автоматически строит новый маршрут через альтернативный ретранслятор.
    """
    temp_dirs = [tempfile.mkdtemp() for _ in range(5)]
    from src.node.kademlia_node import KademliaNode

    ports = [10300, 10301, 10302, 10303, 10304]
    nodes = []

    try:
        # Узлы: A (клиент), R1 (хоп 1), R2 (хоп 2), R3 (запасной ретранслятор), B (получатель)
        for i, port in enumerate(ports):
            node = KademliaNode(temp_dirs[i], "127.0.0.1", port, k_size=4)
            await node.start()
            nodes.append(node)

        node_a, node_r1, node_r2, node_r3, node_b = nodes

        contact_r1 = node_r1.tunnel_manager.local_contact
        contact_r2 = node_r2.tunnel_manager.local_contact
        contact_r3 = node_r3.tunnel_manager.local_contact
        contact_b = node_b.tunnel_manager.local_contact

        available_relays = [contact_r1, contact_r2, contact_r3]

        # 1. Первая успешная доставка по туннелю A -> R1 -> R2 -> B
        res1 = await node_a.tunnel_manager.send_with_auto_rebuild(
            destination=contact_b,
            payload_bytes=b"Message 1 through initial tunnel",
            available_relays=available_relays
        )
        assert res1["status"] == "DELIVERED"
        assert res1["rebuilt"] is False

        # 2. Имитируем аварийный отказ ретранслятора R2 (kill / stop)
        await node_r2.stop()

        # 3. Отправляем второе сообщение: туннель падает, менеджер строит новый туннель через R3
        res2 = await node_a.tunnel_manager.send_with_auto_rebuild(
            destination=contact_b,
            payload_bytes=b"Message 2 after R2 crash",
            available_relays=available_relays
        )

        assert res2["status"] == "DELIVERED"
        assert res2["rebuilt"] is True
        assert res2["previous_tunnel_dead"] is True
        assert "10303" in res2["path_display"] # Узел R3 (порт 10303) теперь в цепочке!

        # Убеждаемся, что получатель B принял оба сообщения
        assert len(node_b.tunnel_manager.received_messages) == 2
        assert node_b.tunnel_manager.received_messages[1]["payload_bytes"] == b"Message 2 after R2 crash"

    finally:
        for n in nodes:
            try:
                await n.stop()
            except Exception:
                pass
        for d in temp_dirs:
            shutil.rmtree(d, ignore_errors=True)

@pytest.mark.asyncio
async def test_tunnel_deduplication():
    """Тест ТЗ Раздел 13.1: Защита от повторной обработки сообщений."""
    init = make_test_contact(8001)
    tm = TunnelManager(Dispatcher(), NodeIdentity.generate(), RoutingTable(init.node_id, 4), "127.0.0.1", 8001)

    msg_id = uuid.uuid4().bytes
    assert msg_id not in tm.delivered_message_ids

    # Эмулируем приход кадра
    class DummyWriter:
        def get_extra_info(self, key): return ("127.0.0.1", 9999)
    class DummyConn:
        writer = DummyWriter()
        async def send_frame(self, f): pass

    from src.transport.frame import Frame
    frame1 = Frame.pack_data(
        MessageType.TUNNEL_DATA,
        {"tunnel_id": b"1234567890123456", "message_id": msg_id, "data": b"test"}
    )
    await tm._handle_tunnel_data(DummyConn(), frame1)
    assert len(tm.received_messages) == 1
    assert tm.received_messages[0]["is_duplicate"] is False

    # Повторная посылка того же message_id
    await tm._handle_tunnel_data(DummyConn(), frame1)
    assert len(tm.received_messages) == 2
    assert tm.received_messages[1]["is_duplicate"] is True

def test_tunnel_ttl_expiration():
    """Тест ТЗ Раздел 12: Автоматическое истечение срока жизни туннеля по TTL."""
    init = make_test_contact(8001)
    r1 = make_test_contact(8002)
    r2 = make_test_contact(8003)
    dest = make_test_contact(8004)

    tunnel = Tunnel(
        tunnel_id=uuid.uuid4().bytes,
        initiator=init,
        relays=[r1, r2],
        destination=dest,
        ttl=0.1 # 100 мс
    )
    tunnel.state = TunnelState.ACTIVE
    assert tunnel.is_active is True

    time.sleep(0.15)
    # После истечения TTL туннель переходит в DEAD
    assert tunnel.is_active is False
    assert tunnel.state == TunnelState.DEAD
