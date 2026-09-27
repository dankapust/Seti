# USERGUIDE — Руководство по Этапу 1

## 1. Состав файлов Этапа 1

* `src/transport/protocol.py` — константы, типы сообщений, флаги, 24-байтовый заголовок.
* `src/transport/frame.py` — класс `Frame`, упаковка данных через `msgpack`, проверка лимита 65KB.
* `src/transport/connection.py` — асинхронный чтец TCP-потока.
* `src/transport/dispatcher.py` — диспетчер сообщений по типам.
* `tests/test_framing.py` — автотесты бинарного кадрирования.
* `Dockerfile` & `docker-compose.yml` — конфигурация развёртывания в Docker.

---

## 2. Локальный запуск тестов без Docker

```powershell
.\venv\Scripts\python -m pytest tests/test_framing.py -v
```

---

## 3. Запуск тестов через Docker Compose

```powershell
docker-compose up --build
```
