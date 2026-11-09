import os
import struct
import time
import uuid
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from src.identity.identity import NodeIdentity
from src.transport.frame import Frame
from src.transport.protocol import MessageType, FrameFlags
from src.crypto.channel import (
    SecureSession,
    HandshakeError,
    ReplayAttackError,
    AuthenticationError,
    DecryptionError,
    create_handshake_init,
    process_handshake_init,
    process_handshake_resp,
)

def test_handshake_success():
    """Тест успешного рукопожатия между двумя узлами и вывода сессионных ключей."""
    node_a = NodeIdentity.generate()
    node_b = NodeIdentity.generate()

    # 1. Node A создает HANDSHAKE_INIT
    init_frame, eph_priv_a = create_handshake_init(node_a, node_b.node_id)
    assert init_frame.msg_type == MessageType.HANDSHAKE_INIT

    # 2. Node B обрабатывает HANDSHAKE_INIT и создает HANDSHAKE_RESP
    resp_frame, session_b = process_handshake_init(init_frame, node_b)
    assert resp_frame.msg_type == MessageType.HANDSHAKE_RESP
    assert bool(resp_frame.flags & FrameFlags.RESPONSE)

    # 3. Node A обрабатывает HANDSHAKE_RESP
    session_a = process_handshake_resp(resp_frame, node_a, eph_priv_a, node_b.node_id)

    # Проверяем согласование параметров
    assert session_a.session_id == session_b.session_id
    assert len(session_a.session_id) == 16
    assert session_a.send_key == session_b.recv_key
    assert session_a.recv_key == session_b.send_key
    assert session_a.peer_node_id == node_b.node_id
    assert session_b.peer_node_id == node_a.node_id


def test_handshake_identity_spoofing():
    """Тест защиты от подмены NodeID при рукопожатии."""
    node_a = NodeIdentity.generate()
    node_b = NodeIdentity.generate()

    init_frame, _ = create_handshake_init(node_a, node_b.node_id)
    data = init_frame.unpack_data()

    # Злоумышленник подменяет sender_node_id на чужой
    fake_node_id = b"\xff" * 32
    data["sender_node_id"] = fake_node_id

    tampered_frame = Frame.pack_data(MessageType.HANDSHAKE_INIT, data)

    with pytest.raises(HandshakeError, match="Sender NodeID does not match"):
        process_handshake_init(tampered_frame, node_b)


def test_handshake_tampered_signature():
    """Тест защиты от MITM: поврежденная подпись Ed25519 отклоняется."""
    node_a = NodeIdentity.generate()
    node_b = NodeIdentity.generate()

    init_frame, _ = create_handshake_init(node_a, node_b.node_id)
    data = init_frame.unpack_data()

    # Портим 1 байт подписи
    sig = bytearray(data["signature"])
    sig[0] ^= 0x01
    data["signature"] = bytes(sig)

    tampered_frame = Frame.pack_data(MessageType.HANDSHAKE_INIT, data)

    with pytest.raises(HandshakeError, match="Invalid Ed25519 signature"):
        process_handshake_init(tampered_frame, node_b)


def test_handshake_wrong_target():
    """Тест отклонения рукопожатия, адресованного другому узлу."""
    node_a = NodeIdentity.generate()
    node_b = NodeIdentity.generate()
    node_c = NodeIdentity.generate()

    # Инициализация адресована Node C, а отправлена Node B
    init_frame, _ = create_handshake_init(node_a, node_c.node_id)

    with pytest.raises(HandshakeError, match="Target NodeID does not match local node"):
        process_handshake_init(init_frame, node_b)


def test_handshake_expired_timestamp():
    """Тест отклонения рукопожатия с просроченной временной меткой."""
    node_a = NodeIdentity.generate()
    node_b = NodeIdentity.generate()

    init_frame, _ = create_handshake_init(node_a, node_b.node_id)
    # Проверяем с жестким допуском 1 сек после паузы или меняем время
    data = init_frame.unpack_data()
    data["timestamp"] = int(time.time()) - 100  # 100 секунд назад
    # Переподписываем, чтобы ошибка была именно по тайм-ауту
    import msgpack
    data_to_sign = msgpack.packb(
        [b"HANDSHAKE_INIT", node_a.node_id, node_b.node_id, data["ephemeral_public_key"], data["timestamp"]],
        use_bin_type=True,
    )
    data["signature"] = node_a.sign(data_to_sign)
    old_frame = Frame.pack_data(MessageType.HANDSHAKE_INIT, data)

    with pytest.raises(HandshakeError, match="Handshake timestamp delta too large"):
        process_handshake_init(old_frame, node_b, timestamp_tolerance=30.0)


def test_encrypted_frame_privacy_and_decryption():
    """
    Тест шифрования кадра:
    1. Полезная нагрузка в шифртексте полностью зашифрована (отсутствие открытого текста).
    2. Успешное расшифрование на стороне получателя.
    """
    node_a = NodeIdentity.generate()
    node_b = NodeIdentity.generate()

    init_frame, eph_priv = create_handshake_init(node_a, node_b.node_id)
    resp_frame, session_b = process_handshake_init(init_frame, node_b)
    session_a = process_handshake_resp(resp_frame, node_a, eph_priv, node_b.node_id)

    secret_message = "TOP_SECRET_P2P_PAYLOAD_STRING_12345"
    original_frame = Frame.pack_data(
        MessageType.APP_MESSAGE,
        {"text": secret_message, "important": True},
    )

    # Шифруем кадр от A к B
    enc_frame = session_a.encrypt_frame(original_frame)

    assert bool(enc_frame.flags & FrameFlags.ENCRYPTED)
    # Проверяем конфиденциальность: сырая строка не встречается в зашифрованных байтах
    assert secret_message.encode("utf-8") not in enc_frame.payload

    # Расшифровываем на стороне B
    dec_frame = session_b.decrypt_frame(enc_frame)
    assert not bool(dec_frame.flags & FrameFlags.ENCRYPTED)
    assert dec_frame.msg_type == MessageType.APP_MESSAGE
    assert dec_frame.request_id == original_frame.request_id
    assert dec_frame.unpack_data() == {"text": secret_message, "important": True}


def test_aead_integrity_ciphertext_tampering():
    """Тест целостности AEAD: изменение 1 бита в шифртексте приводит к AuthenticationError."""
    node_a = NodeIdentity.generate()
    node_b = NodeIdentity.generate()

    init_frame, eph_priv = create_handshake_init(node_a, node_b.node_id)
    resp_frame, session_b = process_handshake_init(init_frame, node_b)
    session_a = process_handshake_resp(resp_frame, node_a, eph_priv, node_b.node_id)

    frame = Frame.pack_data(MessageType.APP_MESSAGE, {"data": "confidential"})
    enc_frame = session_a.encrypt_frame(frame)

    # Искажаем 1 байт в теле шифропакета
    corrupted_payload = bytearray(enc_frame.payload)
    corrupted_payload[15] ^= 0x01

    tampered_frame = Frame(
        msg_type=enc_frame.msg_type,
        payload=bytes(corrupted_payload),
        flags=enc_frame.flags,
        request_id=enc_frame.request_id,
        version=enc_frame.version,
    )

    with pytest.raises(AuthenticationError, match="AEAD tag validation failed"):
        session_b.decrypt_frame(tampered_frame)


def test_aead_integrity_header_aad_tampering():
    """Тест защиты от модификации полей заголовка кадра (через AAD)."""
    node_a = NodeIdentity.generate()
    node_b = NodeIdentity.generate()

    init_frame, eph_priv = create_handshake_init(node_a, node_b.node_id)
    resp_frame, session_b = process_handshake_init(init_frame, node_b)
    session_a = process_handshake_resp(resp_frame, node_a, eph_priv, node_b.node_id)

    frame = Frame.pack_data(MessageType.APP_MESSAGE, {"command": "send_funds"})
    enc_frame = session_a.encrypt_frame(frame)

    # Злоумышленник пытается изменить request_id или msg_type в открытом заголовке
    fake_request_id = uuid.uuid4().bytes
    tampered_frame = Frame(
        msg_type=enc_frame.msg_type,
        payload=enc_frame.payload,
        flags=enc_frame.flags,
        request_id=fake_request_id,
        version=enc_frame.version,
    )

    with pytest.raises(AuthenticationError, match="AEAD tag validation failed"):
        session_b.decrypt_frame(tampered_frame)


def test_replay_attack_detection():
    """
    Тест защиты от повторного воспроизведения (Replay Attack):
    1. Первое сообщение принимается успешно.
    2. Повторная отправка того же самого перехваченного кадра вызывает ReplayAttackError.
    3. Отправка кадра со старым номером sequence вызывает ReplayAttackError.
    """
    node_a = NodeIdentity.generate()
    node_b = NodeIdentity.generate()

    init_frame, eph_priv = create_handshake_init(node_a, node_b.node_id)
    resp_frame, session_b = process_handshake_init(init_frame, node_b)
    session_a = process_handshake_resp(resp_frame, node_a, eph_priv, node_b.node_id)

    frame1 = Frame.pack_data(MessageType.APP_MESSAGE, {"msg_id": 1})
    frame2 = Frame.pack_data(MessageType.APP_MESSAGE, {"msg_id": 2})

    enc1 = session_a.encrypt_frame(frame1)
    enc2 = session_a.encrypt_frame(frame2)

    # 1. Первый кадр принимается
    dec1 = session_b.decrypt_frame(enc1)
    assert dec1.unpack_data()["msg_id"] == 1

    # 2. Повторная отправка enc1 (Replay Attack)
    with pytest.raises(ReplayAttackError, match="Replay attack detected"):
        session_b.decrypt_frame(enc1)

    # 3. Второй кадр принимается (seq=2 > seq=1)
    dec2 = session_b.decrypt_frame(enc2)
    assert dec2.unpack_data()["msg_id"] == 2

    # 4. Повторная отправка enc2
    with pytest.raises(ReplayAttackError, match="Replay attack detected"):
        session_b.decrypt_frame(enc2)

    # 5. Попытка отправить enc1 снова (старый seq 1 < last seen 2)
    with pytest.raises(ReplayAttackError, match="Replay attack detected"):
        session_b.decrypt_frame(enc1)


def test_bidirectional_encrypted_session():
    """Тест двустороннего обмена сообщениями в рамках одной сессии."""
    node_a = NodeIdentity.generate()
    node_b = NodeIdentity.generate()

    init_frame, eph_priv = create_handshake_init(node_a, node_b.node_id)
    resp_frame, session_b = process_handshake_init(init_frame, node_b)
    session_a = process_handshake_resp(resp_frame, node_a, eph_priv, node_b.node_id)

    # A -> B
    f_a2b = session_a.encrypt_frame(Frame.pack_data(MessageType.APP_MESSAGE, {"from": "A"}))
    dec_b = session_b.decrypt_frame(f_a2b)
    assert dec_b.unpack_data()["from"] == "A"

    # B -> A
    f_b2a = session_b.encrypt_frame(Frame.pack_data(MessageType.APP_ACK, {"status": "received"}))
    dec_a = session_a.decrypt_frame(f_b2a)
    assert dec_a.unpack_data()["status"] == "received"

    # A -> B еще раз
    f_a2b_2 = session_a.encrypt_frame(Frame.pack_data(MessageType.APP_MESSAGE, {"from": "A_part2"}))
    dec_b_2 = session_b.decrypt_frame(f_a2b_2)
    assert dec_b_2.unpack_data()["from"] == "A_part2"

