import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class NodeIdentity:
    def __init__(self, private_key: ed25519.Ed25519PrivateKey):
        self.private_key = private_key
        self.public_key = private_key.public_key()
        
        # canonical_encode по ТЗ: сырые байты публичного ключа
        self.public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        # NodeID = SHA-256(canonical_encode(identity_public_key))
        self.node_id = hashlib.sha256(self.public_key_bytes).digest()

    @classmethod
    def generate(cls) -> 'NodeIdentity':
        """Генерирует новую пару ключей."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        return cls(private_key)

    @classmethod
    def load_or_generate(cls, state_dir: str) -> 'NodeIdentity':
        """Загружает ключ из директории состояния, либо генерирует новый, если его нет."""
        os.makedirs(state_dir, exist_ok=True)
        key_path = os.path.join(state_dir, "identity.key")
        
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                key_bytes = f.read()
                private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)
                return cls(private_key)
        else:
            identity = cls.generate()
            with open(key_path, "wb") as f:
                # Сохраняем приватный ключ в сыром виде (для учебного проекта)
                f.write(identity.private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            return identity