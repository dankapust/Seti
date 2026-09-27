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