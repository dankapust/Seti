# Защищённая оверлейная сеть передачи данных на основе пиринговых протоколов

Учебный прототип P2P-сети, реализующий TCP-транспорт, строгий бинарный фрейминг, криптографическую идентичность на основе Ed25519 и DHT-маршрутизацию Kademlia. Проект реализует этапы курсовой работы.

---

### Требования
* Python 3.11+
* Docker и Docker Compose (для изолированного тестирования)

---

### Конфигурация узла
Конфигурация по умолчанию хранится в файле `config/default.json`:
```json
{
  "NODE_STATE_DIR": "./state/node",
  "LISTEN_HOST": "0.0.0.0",
  "LISTEN_PORT": 9101,
  "BOOTSTRAP_PEERS": [],
  "NODE_ID_BITS": 256,
  "K_BUCKET_SIZE": 4,
  "ALPHA": 3,
  "CONNECT_TIMEOUT_MS": 3000,
  "READ_TIMEOUT_MS": 5000,
  "PING_TIMEOUT_MS": 5000,
  "MAX_FRAME_PAYLOAD": 65536,
  "PROTOCOL_VERSION": 1,
  "LOG_LEVEL": "INFO"
}
```

---

### Запуск тестов (Этапы 1 и 2)
В проекте реализован полный набор unit- и integration-тестов (15 тестов):
* **Транспортный уровень (`test_framing.py`, 8 тестов):** 24-байтовый заголовок, сериализация MessagePack, лимит `MAX_FRAME_PAYLOAD`, склейка и фрагментация TCP, независимые параллельные порты, таймауты `ReadTimeoutError`, обработка ошибок диспетчером.
* **Маршрутизация Kademlia (`test_kademlia.py`, 7 тестов):** генерация и детерминизм ключей Ed25519, свойства XOR-метрики, емкость K-Bucket, вытеснение недоступного кандидата `oldest` по таймауту, сохранение активного `oldest`, итеративный `lookup_node` с полным опросом кандидатов, многоузловой Bootstrap и поиск.

**Локальный запуск всех тестов:**
```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

**Запуск тестов через Docker:**
```bash
docker-compose up --build tests
```

---

### Запуск демонстрационных сценариев

#### Сценарий Этапа 1 (`demo_stage1.py`)
Демонстрирует работу 3 независимых одновременных узлов на портах 8001, 8002 и 8003:
1. Параллельный перекрестный обмен кадрами PING/PONG через `asyncio.gather`.
2. Контролируемую обработку таймаута при задержке ответа от узла Node_C с возбуждением `ReadTimeoutError`.

**Запуск:**
```bash
python demo_stage1.py
```
*(Логи сохраняются в `logs/stage1_demo.log`)*

#### Сценарий Этапа 2 (`demo_stage2.py`)
Разворачивает сеть из 5 узлов, подключает их через Star Bootstrap схему к Seed-узлу (порт 9000) и выполняет контрольный Kademlia Lookup, подтверждая многопереходный поиск в DHT.

**Запуск:**
```bash
python demo_stage2.py
```
*(Логи сохраняются в `logs/stage2_demo.log`)*

---

### Запуск демонстраций в Docker
```bash
# Демонстрация Этапа 1
docker-compose run --rm stage1_demo

# Демонстрация Этапа 2
docker-compose run --rm stage2_demo
```