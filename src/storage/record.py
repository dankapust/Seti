import time
import hashlib
from typing import List, Optional, Tuple
import msgpack
from src.identity.identity import NodeIdentity

class NodeRecord:
    """
    DHT-запись узла (ТЗ Раздел 10.3).
    Содержит сетевые адреса, криптографическую идентичность,
    срок действия (TTL), монотонный sequence_number и цифровую подпись Ed25519.

    Формат адресов (поле ``addresses``):
        Каждый адрес представлен строкой вида ``"<IPv4>:<port>"`` (например,
        ``"192.168.1.10:8001"``). Разделителем хоста и порта служит символ ``":"``.
        IPv6-адреса не поддерживаются, поскольку двоеточие в IPv6-нотации
        (``"::1"``, ``"fe80::1"``) конфликтует с разделителем ``host:port``,
        делая однозначный разбор невозможным без дополнительного экранирования
        (RFC 3986 bracket notation ``[::1]:8001``). Это намеренное ограничение
        для минимизации сложности парсера.
    """
    def __init__(
        self,
        node_id: bytes,
        identity_public_key: bytes,
        addresses: List[str],
        sequence_number: int,
        issued_at: int,
        expires_at: int,
        signature: bytes = b""
    ):
        self.node_id = node_id
        self.identity_public_key = identity_public_key
        self.addresses = list(addresses)
        self.sequence_number = sequence_number
        self.issued_at = int(issued_at)
        self.expires_at = int(expires_at)
        self.signature = signature

    @staticmethod
    def compute_storage_key(node_id: bytes) -> bytes:
        """
        Ключ записи в DHT по ТЗ Раздел 10.3:
        SHA-256("node:" || NodeID)
        """
        return hashlib.sha256(b"node:" + node_id).digest()

    def get_storage_key(self) -> bytes:
        return self.compute_storage_key(self.node_id)

    def canonical_bytes(self) -> bytes:
        """
        Детерминированное бинарное представление данных записи без подписи.
        Используется для создания и проверки подписи Ed25519.
        """
        data_to_pack = [
            self.node_id,
            self.identity_public_key,
            sorted(self.addresses),
            self.sequence_number,
            self.issued_at,
            self.expires_at
        ]
        return msgpack.packb(data_to_pack, use_bin_type=True)

    def sign(self, identity: NodeIdentity):
        """Подписывает запись закрытым ключом владельца."""
        if identity.node_id != self.node_id:
            raise ValueError("Identity does not match record node_id")
        self.signature = identity.sign(self.canonical_bytes())

    def verify(self, current_time: Optional[float] = None) -> Tuple[bool, str]:
        """
        Полная валидация записи (ТЗ Раздел 10.3):
        1. Соответствие node_id публичному ключу (защита от подмены);
        2. Проверка срока действия (TTL);
        3. Проверка цифровой подписи Ed25519.
        """
        if current_time is None:
            current_time = time.time()
        curr_int = int(current_time)

        # 1. Проверка идентичности
        expected_id = hashlib.sha256(self.identity_public_key).digest()
        if self.node_id != expected_id:
            return False, "NodeID mismatch (identity spoofing)"

        # 2. Проверка срока действия TTL
        if curr_int < self.issued_at - 10:  # допуск 10 сек на рассинхронизацию часов
            return False, "Record issued in the future"
        if curr_int >= self.expires_at:
            return False, f"Record expired (expired at {self.expires_at}, now {curr_int})"

        # 3. Проверка подписи Ed25519
        if not self.signature:
            return False, "Missing signature"

        canonical = self.canonical_bytes()
        if not NodeIdentity.verify_signature(self.identity_public_key, self.signature, canonical):
            return False, "Invalid cryptographic signature"

        return True, "OK"

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "identity_public_key": self.identity_public_key,
            "addresses": self.addresses,
            "sequence_number": self.sequence_number,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "signature": self.signature
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'NodeRecord':
        return cls(
            node_id=data["node_id"],
            identity_public_key=data["identity_public_key"],
            addresses=list(data.get("addresses", [])),
            sequence_number=data["sequence_number"],
            issued_at=data["issued_at"],
            expires_at=data["expires_at"],
            signature=data.get("signature", b"")
        )

    @classmethod
    def create(
        cls,
        identity: NodeIdentity,
        addresses: List[str],
        sequence_number: int = 1,
        ttl_seconds: int = 180
    ) -> 'NodeRecord':
        """Фабричный метод для создания и автоматической подписи валидной записи."""
        now = int(time.time())
        record = cls(
            node_id=identity.node_id,
            identity_public_key=identity.public_key_bytes,
            addresses=addresses,
            sequence_number=sequence_number,
            issued_at=now,
            expires_at=now + ttl_seconds
        )
        record.sign(identity)
        return record
