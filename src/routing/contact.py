import time
from typing import Dict, Any

def xor_distance(id1: bytes, id2: bytes) -> int:
    """Вычисляет XOR-расстояние между двумя NodeID (как 256-битные числа)."""
    if len(id1) != 32 or len(id2) != 32:
        raise ValueError("NodeID must be exactly 32 bytes (256 bits)")
    
    # integer_from_big_endian(a XOR b) по ТЗ
    int1 = int.from_bytes(id1, byteorder='big')
    int2 = int.from_bytes(id2, byteorder='big')
    return int1 ^ int2

class Contact:
    """
    Контактная информация узла Kademlia.

    Ограничение формата адреса (IPv4-only):
        Поле ``host`` принимает исключительно IPv4-адреса (например, ``"127.0.0.1"``)
        или DNS-имена хостов. Адреса IPv6 **не поддерживаются намеренно**, поскольку
        формат сетевого адреса в протоколе использует разделитель ``":"`` для пары
        ``host:port`` (например, ``"192.168.1.10:8001"``). Символ двоеточия является
        штатным компонентом IPv6-нотации (например, ``"::1"`` или ``"fe80::1"``),
        что делает однозначный разбор строки ``host:port`` невозможным без введения
        дополнительного экранирования (квадратные скобки ``[::1]:8001`` по RFC 3986).
        Для минимизации сложности парсера принято проектное решение ограничить адресацию
        стеком IPv4.
    """

    def __init__(
        self, 
        node_id: bytes, 
        identity_algorithm: str, 
        identity_public_key: bytes, 
        host: str, 
        port: int
    ):
        if len(node_id) != 32:
            raise ValueError("node_id must be 32 bytes")
            
        self.node_id = node_id
        self.identity_algorithm = identity_algorithm
        self.identity_public_key = identity_public_key
        self.host = host
        self.port = port
        
        # Локальные метаданные (не передаются по сети)
        self.last_seen_ms = int(time.time() * 1000)
        self.last_verified_ms = 0

    def touch(self):
        """Обновляет время последнего наблюдения."""
        self.last_seen_ms = int(time.time() * 1000)

    def mark_verified(self):
        """Отмечает, что контакт успешно ответил (например, на PING)."""
        self.touch()
        self.last_verified_ms = self.last_seen_ms

    def validate_identity(self) -> bool:
        """
        Проверяет криптографическое соответствие: NodeID == SHA256(identity_public_key).
        ТЗ Раздел 9: При получении открытого ключа узел обязан повторно вычислить NodeID
        и сравнить его с заявленным значением.
        """
        if not self.identity_public_key or len(self.identity_public_key) != 32:
            return False
        import hashlib
        expected_id = hashlib.sha256(self.identity_public_key).digest()
        return expected_id == self.node_id

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация для передачи по сети (без локальных last_seen)."""
        return {
            "node_id": self.node_id,
            "identity_algorithm": self.identity_algorithm,
            "identity_public_key": self.identity_public_key,
            "host": self.host,
            "port": self.port
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Contact':
        """Десериализация из сети."""
        return cls(
            node_id=data["node_id"],
            identity_algorithm=data["identity_algorithm"],
            identity_public_key=data["identity_public_key"],
            host=data["host"],
            port=data["port"]
        )

    def __eq__(self, other):
        if not isinstance(other, Contact):
            return False
        return self.node_id == other.node_id

    def __hash__(self):
        return hash(self.node_id)