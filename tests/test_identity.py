import os
import hashlib
import tempfile
import pytest

from src.identity.identity import NodeIdentity

def test_identity_generation_key_lengths():
    """Тест генерации пары ключей Ed25519 и длин всех криптографических артефактов."""
    ident = NodeIdentity.generate()
    assert len(ident.public_key_bytes) == 32
    assert len(ident.node_id) == 32
    # NodeID должен быть детерминированным SHA-256 хэшем сырых 32 байт публичного ключа
    expected_id = hashlib.sha256(ident.public_key_bytes).digest()
    assert ident.node_id == expected_id

def test_identity_uniqueness():
    """Тест энтропии: каждая генерация возвращает уникальную пару ключей."""
    identities = [NodeIdentity.generate() for _ in range(50)]
    node_ids = {i.node_id for i in identities}
    pub_keys = {i.public_key_bytes for i in identities}
    assert len(node_ids) == 50
    assert len(pub_keys) == 50

def test_ed25519_sign_and_verify_valid():
    """Тест создания и успешной верификации цифровой подписи Ed25519."""
    ident = NodeIdentity.generate()
    message = b"Test network frame payload 2026"
    signature = ident.sign(message)

    assert len(signature) == 64
    assert NodeIdentity.verify_signature(ident.public_key_bytes, signature, message) is True

def test_ed25519_verify_signature_tampered_payload():
    """Тест защиты от искажения данных: подпись не проходит при изменении полезной нагрузки."""
    ident = NodeIdentity.generate()
    message = b"Initial valid transaction message"
    signature = ident.sign(message)

    tampered_message = b"Modified malicious transaction message"
    assert NodeIdentity.verify_signature(ident.public_key_bytes, signature, tampered_message) is False

def test_ed25519_verify_signature_tampered_sig():
    """Тест детекции повреждения подписи: инверсия 1 бита в подписи приводит к отказу."""
    ident = NodeIdentity.generate()
    message = b"Integrity check string"
    signature = bytearray(ident.sign(message))

    # Инвертируем 1 бит
    signature[10] ^= 0x01
    assert NodeIdentity.verify_signature(ident.public_key_bytes, bytes(signature), message) is False

def test_ed25519_verify_signature_wrong_key():
    """Тест защиты от спуфинга: подпись одного узла не проходит проверку публичным ключом другого узла."""
    alice = NodeIdentity.generate()
    bob = NodeIdentity.generate()
    message = b"Message from Alice"
    alice_signature = alice.sign(message)

    # Проверяем подпись Алисы ключом Боба
    assert NodeIdentity.verify_signature(bob.public_key_bytes, alice_signature, message) is False

def test_ed25519_sign_empty_bytes():
    """Тест граничного условия: подпись пустого массива байт b''."""
    ident = NodeIdentity.generate()
    empty_msg = b""
    signature = ident.sign(empty_msg)
    assert len(signature) == 64
    assert NodeIdentity.verify_signature(ident.public_key_bytes, signature, empty_msg) is True

def test_ed25519_sign_large_bytes():
    """Тест подписи объемных данных (256 КБ)."""
    ident = NodeIdentity.generate()
    large_msg = os.urandom(256 * 1024)
    signature = ident.sign(large_msg)
    assert len(signature) == 64
    assert NodeIdentity.verify_signature(ident.public_key_bytes, signature, large_msg) is True

def test_load_or_generate_persistence():
    """Тест персистентности: сохранение ключа на диск и повторная загрузка идентичности."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        # 1. Первый вызов создает файл identity.key
        ident1 = NodeIdentity.load_or_generate(tmp_dir)
        key_file = os.path.join(tmp_dir, "identity.key")
        assert os.path.exists(key_file)
        assert os.path.getsize(key_file) == 32

        # 2. Второй вызов из той же папки загружает идентичные ключи
        ident2 = NodeIdentity.load_or_generate(tmp_dir)
        assert ident1.node_id == ident2.node_id
        assert ident1.public_key_bytes == ident2.public_key_bytes

        # Подпись, сделанная ident1, проверяется публичным ключом ident2
        msg = b"Cross check between loaded instances"
        sig = ident1.sign(msg)
        assert NodeIdentity.verify_signature(ident2.public_key_bytes, sig, msg) is True

def test_ed25519_verify_signature_invalid_key_length():
    """Тест обработки некорректных байтов публичного ключа (длина != 32)."""
    ident = NodeIdentity.generate()
    sig = ident.sign(b"data")
    assert NodeIdentity.verify_signature(b"too_short", sig, b"data") is False
    assert NodeIdentity.verify_signature(b"", sig, b"data") is False
    assert NodeIdentity.verify_signature(b"\x00" * 31, sig, b"data") is False

