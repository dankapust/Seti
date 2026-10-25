import time
import logging
from typing import Dict, Optional, Tuple, List
from src.storage.record import NodeRecord

logger = logging.getLogger(__name__)

class DHTStorage:
    """
    Локальное хранилище DHT-записей узла (ТЗ Раздел 10.3).
    Обеспечивает:
    - Валидацию криптографической подписи перед сохранением;
    - Защиту от атак отката (проверка строгой монотонности sequence_number);
    - Контроль времени жизни (TTL) и автоматическую очистку устаревших записей.
    """
    def __init__(self):
        self._records: Dict[bytes, NodeRecord] = {}

    def put(self, record: NodeRecord, current_time: Optional[float] = None) -> Tuple[bool, str]:
        """
        Сохраняет запись в DHT с полной проверкой валидности и монотонности версий.
        """
        if current_time is None:
            current_time = time.time()

        # 1. Проверяем валидность самой записи (подпись, идентичность, TTL)
        is_valid, reason = record.verify(current_time)
        if not is_valid:
            logger.warning(f"Отказ сохранения DHT-записи: {reason}")
            return False, reason

        storage_key = record.get_storage_key()
        existing = self._records.get(storage_key)

        # 2. Проверка монотонности sequence_number (ТЗ Раздел 10.3)
        # Из нескольких валидных записей одного владельца выбирается запись с наибольшим sequence_number;
        # запись с меньшим или равным номером считается попыткой отката.
        if existing is not None:
            if record.sequence_number <= existing.sequence_number:
                reject_msg = (
                    f"Rollback rejected: new sequence_number={record.sequence_number} "
                    f"<= existing={existing.sequence_number}"
                )
                logger.warning(f"Отказ обновления DHT-записи: {reject_msg}")
                return False, reject_msg

        self._records[storage_key] = record
        logger.debug(
            f"DHT-запись успешно сохранена для ключа {storage_key.hex()[:8]} "
            f"(NodeID={record.node_id.hex()[:8]}, seq={record.sequence_number})"
        )
        return True, "Stored successfully"

    def get(self, storage_key: bytes, current_time: Optional[float] = None) -> Optional[NodeRecord]:
        """
        Возвращает запись по ключу. Если запись просрочена (TTL), удаляет её и возвращает None.
        """
        if current_time is None:
            current_time = time.time()

        record = self._records.get(storage_key)
        if record is None:
            return None

        # Проверка TTL
        if int(current_time) >= record.expires_at:
            logger.info(f"DHT-запись для {storage_key.hex()[:8]} истекла по TTL и удалена")
            del self._records[storage_key]
            return None

        return record

    def cleanup_expired(self, current_time: Optional[float] = None) -> int:
        """Удаляет все просроченные записи из хранилища и возвращает число удаленных."""
        if current_time is None:
            current_time = time.time()
        curr_int = int(current_time)

        expired_keys = [
            k for k, r in self._records.items()
            if curr_int >= r.expires_at
        ]
        for k in expired_keys:
            del self._records[k]
        return len(expired_keys)

    def total_count(self) -> int:
        return len(self._records)

    def all_records(self) -> List[NodeRecord]:
        return list(self._records.values())
