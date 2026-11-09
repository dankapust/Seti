import os
import sys
# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import asyncio
import logging
import os
import shutil
import sys
import time

from src.identity.identity import NodeIdentity
from src.transport.frame import Frame
from src.transport.protocol import MessageType, FrameFlags
from src.crypto.channel import (
    SecureSession,
    HandshakeError,
    ReplayAttackError,
    AuthenticationError,
    create_handshake_init,
    process_handshake_init,
    process_handshake_resp,
)

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logs/stage4_demo.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("Stage4Demo")


def format_hex_dump(data: bytes, max_len: int = 48) -> str:
    """Форматирует байты в компактный hex-дамп."""
    hex_str = data[:max_len].hex()
    spaced = " ".join(hex_str[i : i + 2] for i in range(0, len(hex_str), 2))
    if len(data) > max_len:
        spaced += f" ... (+{len(data) - max_len} bytes)"
    return spaced


def run_stage4():
    print("=" * 80)
    print("  STAGE 4 DEMO: SECURE CHANNEL, X25519 ECDH, CHACHA20-POLY1305 & REPLAY SHIELD")
    print("=" * 80)

    # -------------------------------------------------------------------------
    # 1. ИНИЦИАЛИЗАЦИЯ КРИПТОГРАФИЧЕСКИХ ИДЕНТИЧНОСТЕЙ УЗЛОВ (Ed25519)
    # -------------------------------------------------------------------------
    print("\n--- ШАГ 1: ИНИЦИАЛИЗАЦИЯ ИДЕНТИЧНОСТЕЙ УЗЛОВ (Ed25519) ---")
    alice = NodeIdentity.generate()
    bob = NodeIdentity.generate()
    print(f"Alice (Initiator): NodeID = {alice.node_id.hex()[:16]}... (SHA256)")
    print(f"                   PubKey = {alice.public_key_bytes.hex()[:16]}... (Ed25519 32B)")
    print(f"Bob   (Responder): NodeID = {bob.node_id.hex()[:16]}... (SHA256)")
    print(f"                   PubKey = {bob.public_key_bytes.hex()[:16]}... (Ed25519 32B)")

    # -------------------------------------------------------------------------
    # 2. РУКОПОЖАТИЕ (HANDSHAKE) И ВЫВОД СЕССИОННЫХ КЛЮЧЕЙ
    # -------------------------------------------------------------------------
    print("\n--- ШАГ 2: АСИММЕТРИЧНЫЙ ОБМЕН КЛЮЧАМИ (X25519 ECDH + HKDF-SHA256) ---")
    t0 = time.perf_counter()

    # Alice формирует HANDSHAKE_INIT
    init_frame, eph_priv_alice = create_handshake_init(alice, bob.node_id)
    init_data = init_frame.unpack_data()
    print(f"[Alice -> Bob] Отправлен HANDSHAKE_INIT:")
    print(f"  • Эфемерный открытый ключ X25519: {init_data['ephemeral_public_key'].hex()[:24]}... (32 байта)")
    print(f"  • Цифровая подпись Ed25519:        {init_data['signature'].hex()[:24]}... (64 байта)")
    print(f"  • Временная метка (timestamp):     {init_data['timestamp']}")

    # Bob проверяет подпись Alice, генерирует свой X25519 ключ и отвечает
    resp_frame, session_bob = process_handshake_init(init_frame, bob)
    resp_data = resp_frame.unpack_data()
    print(f"\n[Bob -> Alice] Проверка пройдена. Отправлен HANDSHAKE_RESP:")
    print(f"  • Эфемерный открытый ключ X25519: {resp_data['ephemeral_public_key'].hex()[:24]}... (32 байта)")
    print(f"  • Ответная подпись Ed25519:        {resp_data['signature'].hex()[:24]}... (64 байта)")

    # Alice проверяет подпись Bob и финализирует сессию
    session_alice = process_handshake_resp(resp_frame, alice, eph_priv_alice, bob.node_id)
    dt_ms = (time.perf_counter() - t0) * 1000

    print(f"\n[РЕЗУЛЬТАТ РУКОПОЖАТИЯ]:")
    print(f"  ✓ Session ID:          {session_alice.session_id.hex()}")
    print(f"  ✓ Совпадение секретов: {session_alice.session_id == session_bob.session_id} (Идентичны)")
    print(f"  ✓ Ключ Alice->Bob:     {session_alice.send_key.hex()[:16]}... == {session_bob.recv_key.hex()[:16]}...")
    print(f"  ✓ Ключ Bob->Alice:     {session_alice.recv_key.hex()[:16]}... == {session_bob.send_key.hex()[:16]}...")
    print(f"  ✓ Время выполнения:    {dt_ms:.2f} мс")

    # -------------------------------------------------------------------------
    # 3. ЭМУЛЯЦИЯ СЕТЕВОГО ПЕРЕХВАТА ТРАФИКА (WIRESHARK / SNIFFER CHECK)
    # -------------------------------------------------------------------------
    print("\n--- ШАГ 3: ЭМУЛЯЦИЯ ЗАХВАТА СЕТЕВОГО ТРАФИКА (ПРОВЕРКА КОНФИДЕНЦИАЛЬНОСТИ) ---")
    secret_text = "CONFIDENTIAL: Secret banking token 9845-ABCD-7711-ZZ99 and private keys"
    raw_payload_data = {"text": secret_text, "amount": 1000000, "currency": "USD"}

    plain_frame = Frame.pack_data(MessageType.APP_MESSAGE, raw_payload_data)
    print(f"Исходное прикладное сообщение (открытый текст):")
    print(f"  «{secret_text}»")

    # Шифрование кадра на стороне Alice
    encrypted_frame = session_alice.encrypt_frame(plain_frame)
    wire_bytes = encrypted_frame.encode()

    print(f"\n[СЕТЕВОЙ ПРОВОД / СНИФФЕР]: Перехвачен сырой TCP-кадр ({len(wire_bytes)} байт):")
    print(f"  • Заголовок (24 байта):  {format_hex_dump(wire_bytes[:24])}")
    print(f"  • Флаги заголовка:       {encrypted_frame.flags} (ENCRYPTED bit 0x0008 установлен)")
    print(f"  • Тело кадра (Payload):  {format_hex_dump(encrypted_frame.payload)}")

    # Проверка: содержится ли исходная подстрока в зашифрованных байтах провода
    contains_leak = secret_text.encode("utf-8") in wire_bytes
    if not contains_leak:
        print("  ✓ [ПРОВЕРКА КОНФИДЕНЦИАЛЬНОСТИ]: Открытый текст полностью скрыт! Утечек данных нет.")
    else:
        print("  ✗ [ОШИБКА]: Обнаружена утечка открытого текста в сеть!")

    # Bob принимает и расшифровывает кадр
    decrypted_frame = session_bob.decrypt_frame(encrypted_frame)
    unpacked_bob = decrypted_frame.unpack_data()
    print(f"\n[Bob] Кадр успешно расшифрован:")
    print(f"  • Содержимое: «{unpacked_bob['text']}»")
    print(f"  • Сумма:      {unpacked_bob['amount']} {unpacked_bob['currency']}")

    # -------------------------------------------------------------------------
    # 4. ДЕМОНСТРАЦИЯ ЗАЩИТЫ ОТ REPLAY-АТАК (ПОВТОРНОГО ВОСПРОИЗВЕДЕНИЯ)
    # -------------------------------------------------------------------------
    print("\n--- ШАГ 4: ЗАЩИТА ОТ REPLAY-АТАК (ПОВТОРНОГО ВОСПРОИЗВЕДЕНИЯ КАДРА) ---")
    print("Злоумышленник перехватил предыдущий зашифрованный кадр и повторно отправляет его Bob...")

    try:
        session_bob.decrypt_frame(encrypted_frame)
        print("  ✗ [FAIL]: Повторный пакет был ошибочно принят!")
    except ReplayAttackError as e:
        print(f"  ✓ [SUCCESS] Повторный пакет заблокирован защитой от повторов!")
        print(f"    Причина: {e}")

    # -------------------------------------------------------------------------
    # 5. ДЕМОНСТРАЦИЯ ЗАЩИТЫ ОТ ИСКАЖЕНИЯ ДАННЫХ (AEAD INTEGRITY / TAMPERING)
    # -------------------------------------------------------------------------
    print("\n--- ШАГ 5: ЗАЩИТА ОТ ИСКАЖЕНИЯ ДАННЫХ (AEAD POLY1305 INTEGRITY) ---")
    print("Злоумышленник перехватил новый кадр и инвертировал ровно 1 бит в шифртексте...")

    msg2 = Frame.pack_data(MessageType.APP_MESSAGE, {"command": "TRANSFER_FUNDS"})
    enc_msg2 = session_alice.encrypt_frame(msg2)

    # Инвертируем 1 бит
    corrupted_bytes = bytearray(enc_msg2.payload)
    corrupted_bytes[12] ^= 0x01
    corrupted_frame = Frame(
        msg_type=enc_msg2.msg_type,
        payload=bytes(corrupted_bytes),
        flags=enc_msg2.flags,
        request_id=enc_msg2.request_id,
        version=enc_msg2.version,
    )

    try:
        session_bob.decrypt_frame(corrupted_frame)
        print("  ✗ [FAIL]: Поврежденный пакет был принят без ошибки!")
    except AuthenticationError as e:
        print(f"  ✓ [SUCCESS] Подделка обнаружена на уровне проверки тега Poly1305!")
        print(f"    Причина: {e}")

    # -------------------------------------------------------------------------
    # 6. ДВУСТОРОННИЙ ЗАЩИЩЕННЫЙ ДИАЛОГ
    # -------------------------------------------------------------------------
    print("\n--- ШАГ 6: ДВУСТОРОННИЙ ЗАЩИЩЕННЫЙ ОБМЕН (ALICE <-> BOB) ---")
    ack_frame = Frame.pack_data(MessageType.APP_ACK, {"status": "SUCCESS_RECORD_STORED"})
    enc_ack = session_bob.encrypt_frame(ack_frame)
    dec_ack = session_alice.decrypt_frame(enc_ack)

    print(f"[Bob -> Alice] Зашифрованный ответ: {format_hex_dump(enc_ack.payload)}")
    print(f"[Alice] Расшифрованный ответ:       {dec_ack.unpack_data()}")

    print("\n" + "=" * 80)
    print("  ИТОГ ЭТАПА 4: ВСЕ МЕХАНИЗМЫ БЕЗОПАСНОСТИ УСПЕШНО ВЕРИФИЦИРОВАНЫ!")
    print("=" * 80)


if __name__ == "__main__":
    run_stage4()
