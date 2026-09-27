# Защищённая оверлейная сеть передачи данных на основе пиринговых протоколов

Учебный прототип P2P-сети, реализующий TCP-транспорт, строгий бинарный фрейминг, криптографическую идентичность на основе Ed25519 и DHT-маршрутизацию Kademlia. Проект реализует этапы 1 и 2 в рамках курсовой работы.

### Требования
* Python 3.11+
* Docker и Docker Compose (для запуска изолированного стенда)

### Конфигурация узла
Конфигурация задается в файле `config/default.json`:
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
Запуск тестов
В проекте реализованы unit- и integration-тесты для транспортного слоя. Тесты проверяют склеивание TCP-фреймов, превышение размера payload, ошибки версионирования и валидность сериализации.

Локально:

pip install -r requirements.txt
python -m pytest tests/test_framing.py -v

Через Docker:

docker-compose up --build stage1_tests

Запуск приёмочной демонстрации (Этап 2)
Сценарий Этапа 2 (demo_stage2.py) разворачивает сеть из 5 узлов, подключает их через Star Bootstrap схему к единому Seed-узлу (порт 9000) и выполняет контрольный Kademlia Lookup, доказывая успешный многопереходный поиск в DHT.

python demo_stage2.py

Журналы демонстрации сохраняются в ./logs/stage2_demo.log. Полноценное хранение ключей узлов имитируется в локальной папке ./state/.