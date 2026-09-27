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