from typing import List, Optional, Tuple
from src.routing.contact import Contact, xor_distance

class KBucket:
    def __init__(self, k_size: int):
        self.k_size = k_size
        # Контакты упорядочены от наименее недавно виденного (index 0) к самому свежему (index -1)
        self.contacts: List[Contact] = []

    def get_oldest(self) -> Optional[Contact]:
        """Возвращает наименее недавно подтвержденный контакт (кандидат на вытеснение)."""
        return self.contacts[0] if self.contacts else None

    def remove_contact(self, node_id: bytes):
        """Удаляет контакт по NodeID."""
        self.contacts = [c for c in self.contacts if c.node_id != node_id]

    def add_or_update(self, contact: Contact) -> Tuple[bool, Optional[Contact]]:
        """
        Добавляет или обновляет контакт.
        Возвращает:
            (True, None) - если контакт добавлен или успешно обновлен.
            (False, Contact) - если корзина полна, и нужно отправить PING самому старому контакту.
        """
        # 1. Если контакт уже есть - обновляем и переносим в конец (самый свежий)
        for idx, c in enumerate(self.contacts):
            if c.node_id == contact.node_id:
                c.host = contact.host
                c.port = contact.port
                c.touch()
                self.contacts.pop(idx)
                self.contacts.append(c)
                return True, None
        
        # 2. Если контакт новый и есть место - добавляем в конец
        if len(self.contacts) < self.k_size:
            contact.touch()
            self.contacts.append(contact)
            return True, None
            
        # 3. Контакт новый, но корзина полна
        return False, self.contacts[0]

    def promote_contact(self, node_id: bytes):
        """Перемещает контакт в конец корзины как недавно подтвержденный."""
        for idx, c in enumerate(self.contacts):
            if c.node_id == node_id:
                c.mark_verified()
                self.contacts.pop(idx)
                self.contacts.append(c)
                break

class RoutingTable:
    def __init__(self, local_node_id: bytes, k_size: int):
        self.local_node_id = local_node_id
        self.k_size = k_size
        # 256 корзин для 256-битного пространства (индекс равен старшему биту расстояния)
        self.buckets = [KBucket(k_size) for _ in range(256)]

    def _bucket_index(self, distance: int) -> int:
        """Определяет индекс корзины на основе XOR-расстояния."""
        if distance == 0:
            return 0
        # bit_length() дает позицию старшего установленного бита (1 для 1, 2 для 2-3, 3 для 4-7 и т.д.)
        return distance.bit_length() - 1

    def add_contact(self, contact: Contact) -> Tuple[bool, Optional[Contact]]:
        """
        Пытается добавить контакт в таблицу.
        """
        if contact.node_id == self.local_node_id:
            return False, None  # Себя не добавляем
        
        distance = xor_distance(self.local_node_id, contact.node_id)
        idx = self._bucket_index(distance)
        return self.buckets[idx].add_or_update(contact)

    def remove_contact(self, node_id: bytes):
        """Удаляет контакт (например, если он не ответил на PING)."""
        distance = xor_distance(self.local_node_id, node_id)
        idx = self._bucket_index(distance)
        self.buckets[idx].remove_contact(node_id)

    def promote_contact(self, node_id: bytes):
        """Перемещает контакт в конец корзины как активный."""
        distance = xor_distance(self.local_node_id, node_id)
        idx = self._bucket_index(distance)
        self.buckets[idx].promote_contact(node_id)

    def get_closest_contacts(self, target_node_id: bytes, limit: int) -> List[Contact]:
        """
        Находит до `limit` ближайших известных контактов к `target_node_id`.
        """
        all_contacts = []
        for bucket in self.buckets:
            all_contacts.extend(bucket.contacts)
        
        # Сортируем все известные контакты по XOR-расстоянию до цели
        all_contacts.sort(key=lambda c: xor_distance(c.node_id, target_node_id))
        
        return all_contacts[:limit]

    def get_bucket_distribution(self) -> dict:
        """
        Возвращает детальную статистику распределения контактов по отдельным k-bucket.
        Требование ТЗ Раздел 10.1: показывать содержимое отдельных корзин.
        """
        distribution = {}
        for idx, bucket in enumerate(self.buckets):
            if bucket.contacts:
                distribution[idx] = {
                    "count": len(bucket.contacts),
                    "capacity": bucket.k_size,
                    "contacts": [
                        {
                            "node_id": c.node_id.hex()[:8],
                            "host": c.host,
                            "port": c.port,
                            "distance_hex": hex(xor_distance(self.local_node_id, c.node_id))[:10]
                        }
                        for c in bucket.contacts
                    ]
                }
        return distribution

    def total_contacts_count(self) -> int:
        """Общее число уникальных контактов во всей таблице маршрутизации."""
        return sum(len(b.contacts) for b in self.buckets)

    def dump_contacts(self) -> List[dict]:
        """Сериализует все известные контакты таблицы маршрутизации для сохранения на диск (E2-7)."""
        contacts = []
        for bucket in self.buckets:
            for c in bucket.contacts:
                contacts.append({
                    "node_id": c.node_id,
                    "identity_algorithm": c.identity_algorithm,
                    "identity_public_key": c.identity_public_key,
                    "host": c.host,
                    "port": c.port,
                    "last_seen_ms": c.last_seen_ms,
                    "last_verified_ms": c.last_verified_ms
                })
        return contacts

    def load_contacts(self, contacts_data: List[dict]):
        """Загружает сохраненные контакты в таблицу маршрутизации с валидацией идентичности."""
        for item in contacts_data:
            try:
                c = Contact(
                    node_id=item["node_id"],
                    identity_algorithm=item["identity_algorithm"],
                    identity_public_key=item["identity_public_key"],
                    host=item["host"],
                    port=item["port"]
                )
                c.last_seen_ms = item.get("last_seen_ms", c.last_seen_ms)
                c.last_verified_ms = item.get("last_verified_ms", c.last_verified_ms)
                if c.validate_identity():
                    self.add_contact(c)
            except Exception:
                continue

    def save_to_file(self, file_path: str):
        """Сохраняет таблицу маршрутизации на диск (E2-7: Routing Table Persistence)."""
        import os
        import msgpack
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        data = {
            "version": 1,
            "local_node_id": self.local_node_id,
            "k_size": self.k_size,
            "contacts": self.dump_contacts()
        }
        with open(file_path, "wb") as f:
            f.write(msgpack.packb(data, use_bin_type=True))

    def load_from_file(self, file_path: str) -> bool:
        """Загружает сохраненную таблицу маршрутизации с диска (E2-7)."""
        import os
        import msgpack
        if not os.path.exists(file_path):
            return False
        try:
            with open(file_path, "rb") as f:
                data = msgpack.unpackb(f.read(), raw=False)
            if isinstance(data, dict) and "contacts" in data:
                self.load_contacts(data["contacts"])
                return True
        except Exception:
            return False
        return False
