import asyncio
import hashlib
import logging
import struct
import time
from typing import Optional, Tuple

import msgpack
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag

from src.identity.identity import NodeIdentity
from src.transport.connection import Connection
from src.transport.frame import Frame
from src.transport.protocol import (
    FrameFlags,
    MessageType,
    ReadTimeoutError,
)

logger = logging.getLogger(__name__)

class CryptoChannelError(Exception):
    """Базовое исключение криптографического защищенного канала."""
    pass

class HandshakeError(CryptoChannelError):
    """Ошибка аутентификации или согласования ключей при рукопожатии."""
    pass

class ReplayAttackError(CryptoChannelError):
    """Обнаружена атака повторного воспроизведения пакета (Replay Attack)."""
    pass

class AuthenticationError(CryptoChannelError):
    """Ошибка аутентичности AEAD (сообщение повреждено или подделано)."""
    pass

class DecryptionError(CryptoChannelError):
    """Ошибка расшифрования кадра."""
    pass


class SecureSession:
    """
    Защищенная криптографическая сессия между двумя узлами P2P-сети.

    Обеспечивает:
    - Конфиденциальность и целостность: AEAD-шифр ChaCha20-Poly1305 (256-битный ключ, 128-битный тег Poly1305).
    - Защиту заголовка кадра: первые 20 байт заголовка (версия, тип, флаги, request_id) передаются как AAD.
    - Защиту от повторов (Replay Protection): строгий монотонный счетчик пакетов `sequence_number`.
    - Разделение направлений: независимые ключи `send_key` и `recv_key`.
    """

    def __init__(
        self,
        session_id: bytes,
        is_initiator: bool,
        peer_node_id: bytes,
        peer_public_key: bytes,
        send_key: bytes,
        recv_key: bytes,
    ):
        self.session_id = session_id
        self.is_initiator = is_initiator
        self.peer_node_id = peer_node_id
        self.peer_public_key = peer_public_key
        self.send_key = send_key
        self.recv_key = recv_key

        self.send_seq = 1
        self.last_recv_seq = 0

        self._send_cipher = ChaCha20Poly1305(self.send_key)
        self._recv_cipher = ChaCha20Poly1305(self.recv_key)

    def _compute_nonce(self, seq_num: int) -> bytes:
        """Формирует детерминированный 12-байтовый (96-битный) nonce: 8 байт seq + 4 байта соли сессии."""
        return struct.pack(">Q", seq_num) + self.session_id[:4]

    def encrypt_payload(self, payload: bytes, aad: bytes = b"") -> bytes:
        """
        Шифрует полезную нагрузку алгоритмом ChaCha20-Poly1305 с инкрементом счетчика seq.
        Формат шифропакета:
            [8 байт sequence_number] + [ciphertext] + [16 байт Poly1305 tag]
        """
        seq = self.send_seq
        self.send_seq += 1
        nonce = self._compute_nonce(seq)
        ciphertext = self._send_cipher.encrypt(nonce, payload, aad)
        return struct.pack(">Q", seq) + ciphertext

    def decrypt_payload(self, encrypted_blob: bytes, aad: bytes = b"") -> bytes:
        """
        Расшифровывает полезную нагрузку и проверяет отсутствие Replay-атаки.
        """
        if len(encrypted_blob) < 8 + 16:
            raise DecryptionError("Encrypted payload is too short to contain sequence and tag")

        seq = struct.unpack(">Q", encrypted_blob[:8])[0]

        # Защита от Replay-атаки: строгая монотонность порядковых номеров
        if seq <= self.last_recv_seq:
            raise ReplayAttackError(
                f"Replay attack detected: received packet sequence {seq} <= last seen {self.last_recv_seq}"
            )

        nonce = self._compute_nonce(seq)
        ciphertext = encrypted_blob[8:]

        try:
            plaintext = self._recv_cipher.decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            raise AuthenticationError("AEAD tag validation failed: ciphertext corrupted or header modified")

        self.last_recv_seq = seq
        return plaintext

    @staticmethod
    def compute_frame_aad(frame_version: int, msg_type: MessageType, flags: FrameFlags, request_id: bytes) -> bytes:
        """Вычисляет 20 байт канонического AAD из заголовка кадра (без 4 байт длины)."""
        return struct.pack(">BBH16s", frame_version, int(msg_type), int(flags), request_id)

    def encrypt_frame(self, frame: Frame) -> Frame:
        """
        Шифрует кадр: выставляет флаг ENCRYPTED, упаковывает payload в шифропакет
        и привязывает поля заголовка через AAD.
        """
        target_flags = frame.flags | FrameFlags.ENCRYPTED
        aad = self.compute_frame_aad(frame.version, frame.msg_type, target_flags, frame.request_id)
        enc_payload = self.encrypt_payload(frame.payload, aad=aad)

        return Frame(
            msg_type=frame.msg_type,
            payload=enc_payload,
            flags=target_flags,
            request_id=frame.request_id,
            version=frame.version,
        )

    def decrypt_frame(self, frame: Frame) -> Frame:
        """
        Расшифровывает зашифрованный кадр и снимает флаг ENCRYPTED.
        """
        if not (frame.flags & FrameFlags.ENCRYPTED):
            raise DecryptionError("Frame is not flagged as ENCRYPTED")

        aad = self.compute_frame_aad(frame.version, frame.msg_type, frame.flags, frame.request_id)
        dec_payload = self.decrypt_payload(frame.payload, aad=aad)

        return Frame(
            msg_type=frame.msg_type,
            payload=dec_payload,
            flags=frame.flags & ~FrameFlags.ENCRYPTED,
            request_id=frame.request_id,
            version=frame.version,
        )


def _derive_session_keys(shared_secret: bytes, salt: bytes) -> Tuple[bytes, bytes, bytes]:
    """Выводит пару 32-байтовых ключей и 16-байтовый session_id с помощью HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=b"seti-p2p-v1-session-keys",
    )
    keys = hkdf.derive(shared_secret)
    key_init_to_resp = keys[:32]
    key_resp_to_init = keys[32:64]
    session_id = hashlib.sha256(b"session-id:" + salt).digest()[:16]
    return key_init_to_resp, key_resp_to_init, session_id


def create_handshake_init(
    local_identity: NodeIdentity,
    target_node_id: bytes,
) -> Tuple[Frame, x25519.X25519PrivateKey]:
    """
    Формирует инициирующий кадр HANDSHAKE_INIT.
    Генерирует эфемерный ключ X25519 и подписывает его долговременным ключом Ed25519.
    """
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    now = int(time.time())

    data_to_sign = msgpack.packb(
        [b"HANDSHAKE_INIT", local_identity.node_id, target_node_id, eph_pub, now],
        use_bin_type=True,
    )
    signature = local_identity.sign(data_to_sign)

    payload_data = {
        "sender_node_id": local_identity.node_id,
        "sender_public_key": local_identity.public_key_bytes,
        "ephemeral_public_key": eph_pub,
        "target_node_id": target_node_id,
        "timestamp": now,
        "signature": signature,
    }

    frame = Frame.pack_data(MessageType.HANDSHAKE_INIT, payload_data)
    return frame, eph_priv


def process_handshake_init(
    frame: Frame,
    local_identity: NodeIdentity,
    timestamp_tolerance: float = 30.0,
) -> Tuple[Frame, SecureSession]:
    """
    Обрабатывает входящий HANDSHAKE_INIT, верифицирует инициатора,
    создает ответный HANDSHAKE_RESP и возвращает готовую сессию responder-а.
    """
    if frame.msg_type != MessageType.HANDSHAKE_INIT:
        raise HandshakeError(f"Expected HANDSHAKE_INIT frame, got {frame.msg_type}")

    data = frame.unpack_data()
    sender_node_id = data.get("sender_node_id")
    sender_pub_key = data.get("sender_public_key")
    eph_pub = data.get("ephemeral_public_key")
    target_node_id = data.get("target_node_id")
    ts = data.get("timestamp")
    signature = data.get("signature")

    if not all([sender_node_id, sender_pub_key, eph_pub, target_node_id, ts, signature]):
        raise HandshakeError("Malformed HANDSHAKE_INIT: missing required fields")

    # 1. Проверка адресата
    if target_node_id != local_identity.node_id:
        raise HandshakeError("Target NodeID does not match local node (misrouted handshake)")

    # 2. Проверка соответствия NodeID открытому ключу (защита от спуфинга)
    expected_id = hashlib.sha256(sender_pub_key).digest()
    if sender_node_id != expected_id:
        raise HandshakeError("Sender NodeID does not match SHA-256(sender_public_key)")

    # 3. Проверка временной метки (защита от replay рукопожатия)
    now = time.time()
    if abs(now - ts) > timestamp_tolerance:
        raise HandshakeError(f"Handshake timestamp delta too large: {abs(now - ts):.1f}s > {timestamp_tolerance}s")

    # 4. Проверка цифровой подписи Ed25519
    data_to_verify = msgpack.packb(
        [b"HANDSHAKE_INIT", sender_node_id, target_node_id, eph_pub, ts],
        use_bin_type=True,
    )
    if not NodeIdentity.verify_signature(sender_pub_key, signature, data_to_verify):
        raise HandshakeError("Invalid Ed25519 signature in HANDSHAKE_INIT")

    # 5. Генерация собственного эфемерного ключа и вычисление общего секрета
    resp_eph_priv = x25519.X25519PrivateKey.generate()
    resp_eph_pub = resp_eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    peer_eph_key = x25519.X25519PublicKey.from_public_bytes(eph_pub)
    shared_secret = resp_eph_priv.exchange(peer_eph_key)

    # 6. Вывод ключей HKDF
    salt = hashlib.sha256(eph_pub + resp_eph_pub).digest()
    key_init_to_resp, key_resp_to_init, session_id = _derive_session_keys(shared_secret, salt)

    # 7. Подпись ответа
    resp_data_to_sign = msgpack.packb(
        [b"HANDSHAKE_RESP", local_identity.node_id, sender_node_id, resp_eph_pub, eph_pub],
        use_bin_type=True,
    )
    resp_signature = local_identity.sign(resp_data_to_sign)

    resp_payload = {
        "responder_node_id": local_identity.node_id,
        "responder_public_key": local_identity.public_key_bytes,
        "ephemeral_public_key": resp_eph_pub,
        "target_node_id": sender_node_id,
        "signature": resp_signature,
    }
    resp_frame = Frame.pack_data(
        MessageType.HANDSHAKE_RESP,
        resp_payload,
        flags=FrameFlags.RESPONSE,
        request_id=frame.request_id,
    )

    session = SecureSession(
        session_id=session_id,
        is_initiator=False,
        peer_node_id=sender_node_id,
        peer_public_key=sender_pub_key,
        send_key=key_resp_to_init,
        recv_key=key_init_to_resp,
    )

    return resp_frame, session


def process_handshake_resp(
    frame: Frame,
    local_identity: NodeIdentity,
    eph_priv: x25519.X25519PrivateKey,
    expected_peer_node_id: bytes,
) -> SecureSession:
    """
    Обрабатывает входящий ответ HANDSHAKE_RESP на стороне инициатора
    и возвращает готовую сессию initiator-а.
    """
    if frame.msg_type != MessageType.HANDSHAKE_RESP:
        raise HandshakeError(f"Expected HANDSHAKE_RESP frame, got {frame.msg_type}")

    data = frame.unpack_data()
    resp_node_id = data.get("responder_node_id")
    resp_pub_key = data.get("responder_public_key")
    resp_eph_pub = data.get("ephemeral_public_key")
    target_node_id = data.get("target_node_id")
    signature = data.get("signature")

    if not all([resp_node_id, resp_pub_key, resp_eph_pub, target_node_id, signature]):
        raise HandshakeError("Malformed HANDSHAKE_RESP: missing required fields")

    if resp_node_id != expected_peer_node_id:
        raise HandshakeError(
            f"Responder NodeID mismatch: expected {expected_peer_node_id.hex()[:8]}, got {resp_node_id.hex()[:8]}"
        )

    if target_node_id != local_identity.node_id:
        raise HandshakeError("HANDSHAKE_RESP targeted to a different node")

    expected_id = hashlib.sha256(resp_pub_key).digest()
    if resp_node_id != expected_id:
        raise HandshakeError("Responder NodeID does not match SHA-256(responder_public_key)")

    # Проверка подписи Ed25519
    local_eph_pub = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    resp_data_to_verify = msgpack.packb(
        [b"HANDSHAKE_RESP", resp_node_id, local_identity.node_id, resp_eph_pub, local_eph_pub],
        use_bin_type=True,
    )
    if not NodeIdentity.verify_signature(resp_pub_key, signature, resp_data_to_verify):
        raise HandshakeError("Invalid Ed25519 signature in HANDSHAKE_RESP")

    # Вычисление общего секрета
    peer_eph_key = x25519.X25519PublicKey.from_public_bytes(resp_eph_pub)
    shared_secret = eph_priv.exchange(peer_eph_key)

    salt = hashlib.sha256(local_eph_pub + resp_eph_pub).digest()
    key_init_to_resp, key_resp_to_init, session_id = _derive_session_keys(shared_secret, salt)

    return SecureSession(
        session_id=session_id,
        is_initiator=True,
        peer_node_id=resp_node_id,
        peer_public_key=resp_pub_key,
        send_key=key_init_to_resp,
        recv_key=key_resp_to_init,
    )


class SecureConnection:
    """
    Асинхронная обёртка над TCP Connection с прозрачным AEAD-шифрованием
    и защитой от атак повтора.
    """

    def __init__(self, connection: Connection, session: SecureSession):
        self.connection = connection
        self.session = session

    @property
    def peer_node_id(self) -> bytes:
        return self.session.peer_node_id

    @property
    def session_id(self) -> bytes:
        return self.session.session_id

    async def send_frame(self, frame: Frame):
        """Шифрует и отправляет кадр по защищенному каналу."""
        enc_frame = self.session.encrypt_frame(frame)
        await self.connection.send_frame(enc_frame)

    async def read_frame(self, timeout: Optional[float] = None) -> Optional[Frame]:
        """Принимает зашифрованный кадр и прозрачно расшифровывает его с проверкой AEAD/Replay."""
        raw_frame = await self.connection.read_frame(timeout=timeout)
        if raw_frame is None:
            return None
        return self.session.decrypt_frame(raw_frame)

    async def close(self):
        await self.connection.close()

    @classmethod
    async def perform_handshake_as_initiator(
        cls,
        connection: Connection,
        local_identity: NodeIdentity,
        target_node_id: bytes,
        timeout: float = 5.0,
    ) -> 'SecureConnection':
        """Выполняет активное рукопожатие в качестве клиента/инициатора."""
        init_frame, eph_priv = create_handshake_init(local_identity, target_node_id)
        await connection.send_frame(init_frame)

        resp_frame = await connection.read_frame(timeout=timeout)
        if resp_frame is None:
            raise HandshakeError("Connection closed by peer during handshake")

        session = process_handshake_resp(resp_frame, local_identity, eph_priv, target_node_id)
        return cls(connection, session)

    @classmethod
    async def perform_handshake_as_responder(
        cls,
        connection: Connection,
        local_identity: NodeIdentity,
        timeout: float = 5.0,
    ) -> 'SecureConnection':
        """Ожидает и обрабатывает входящее рукопожатие в качестве сервера."""
        init_frame = await connection.read_frame(timeout=timeout)
        if init_frame is None:
            raise HandshakeError("Connection closed by peer before handshake init")

        resp_frame, session = process_handshake_init(init_frame, local_identity)
        await connection.send_frame(resp_frame)
        return cls(connection, session)

