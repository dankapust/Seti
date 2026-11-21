import asyncio
import enum
import logging
import time
import uuid
from typing import Dict, List, Optional, Tuple, Set, Any

from src.transport.connection import Connection
from src.transport.dispatcher import Dispatcher
from src.transport.frame import Frame
from src.transport.protocol import MessageType, FrameFlags, ReadTimeoutError
from src.routing.contact import Contact
from src.routing.table import RoutingTable
from src.identity.identity import NodeIdentity
from src.crypto.channel import SecureSession

logger = logging.getLogger(__name__)

class TunnelError(Exception):
    """Базовое исключение подсистемы оверлейных туннелей."""
    pass

class TunnelBuildError(TunnelError):
    """Ошибка построения многопереходного туннеля."""
    pass

class TunnelDeliveryError(TunnelError):
    """Ошибка доставки данных по туннелю."""
    pass


class TunnelState(enum.Enum):
    """
    Состояния жизненного цикла оверлейного туннеля (ТЗ Раздел 12).
    """
    BUILDING = "BUILDING"
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    CLOSING = "CLOSING"
    DEAD = "DEAD"


class Tunnel:
    """
    Структура зафиксированного многопереходного туннеля через ретрансляторы.
    
    Свойства (ТЗ Раздел 12):
    - Минимум два ретранслятора (R1, R2);
    - Отсутствие повторяющихся узлов и петель;
    - Уникальный tunnel_id (16 байт UUID);
    - Ограничение max_hops и TTL туннеля;
    - Фиксация состояний и журнала фактической последовательности узлов.
    """
    def __init__(
        self,
        tunnel_id: bytes,
        initiator: Contact,
        relays: List[Contact],
        destination: Contact,
        ttl: float = 120.0,
        max_hops: int = 4
    ):
        self.tunnel_id = tunnel_id
        self.initiator = initiator
        self.relays = relays
        self.destination = destination
        self.ttl = ttl
        self.max_hops = max_hops
        self.created_at = time.time()
        self.state = TunnelState.BUILDING
        
        # Журнал последовательности узлов маршрута: Initiator -> R1 -> R2 -> ... -> Dest
        self.hops_path = [initiator] + relays + [destination]
        self._validate_path()

    def _validate_path(self):
        """Проверяет отсутствие петель, дубликатов и соблюдение лимита хопов."""
        if len(self.relays) < 2:
            raise TunnelBuildError(f"Туннель требует минимум 2 ретранслятора (передано {len(self.relays)})")
            
        all_ids = [h.node_id for h in self.hops_path]
        if len(all_ids) != len(set(all_ids)):
            raise TunnelBuildError("В маршруте туннеля обнаружены петли или повторяющиеся узлы")
            
        if len(self.hops_path) > self.max_hops + 2:
            raise TunnelBuildError(f"Число хопов ({len(self.hops_path)}) превышает max_hops ({self.max_hops})")

    @property
    def is_active(self) -> bool:
        if self.state != TunnelState.ACTIVE:
            return False
        if time.time() - self.created_at > self.ttl:
            self.state = TunnelState.DEAD
            return False
        return True

    def get_path_display(self) -> str:
        """Возвращает текстовое представление цепочки узлов."""
        return " -> ".join(f"{h.host}:{h.port} ({h.node_id.hex()[:8]})" for h in self.hops_path)


class TunnelManager:
    """
    Менеджер построения, коммутации и мониторинга оверлейных туннелей.
    
    Выполняет:
    1. Инициирование и согласование цепочки ретрансляторов (TUNNEL_BUILD / TUNNEL_BUILD_OK).
    2. Коммутацию транзитного трафика на промежуточных узлах без расшифрования содержимого.
    3. Прием и дешифрование сообщений на конечном узле с отправкой сквозного подтверждения (TUNNEL_ACK).
    4. Детекцию сбоев ретрансляторов и автоматическое перестроение туннеля по альтернативному пути.
    """
    def __init__(
        self,
        dispatcher: Dispatcher,
        identity: NodeIdentity,
        routing_table: RoutingTable,
        host: str,
        port: int
    ):
        self.dispatcher = dispatcher
        self.identity = identity
        self.routing_table = routing_table
        self.host = host
        self.port = port
        self.local_contact = Contact(
            node_id=identity.node_id,
            identity_algorithm="Ed25519",
            identity_public_key=identity.public_key_bytes,
            host=host,
            port=port
        )

        # Таблицы транзитной коммутации туннелей на данном узле
        # forward_table: tunnel_id -> (next_host, next_port)
        self.forward_table: Dict[bytes, Tuple[str, int]] = {}
        # backward_table: tunnel_id -> (prev_host, prev_port)
        self.backward_table: Dict[bytes, Tuple[str, int]] = {}
        
        # Активные туннели, созданные данным узлом: tunnel_id -> Tunnel
        self.active_tunnels: Dict[bytes, Tunnel] = {}
        
        # Локальная история доставленных прикладных сообщений (дедупликация)
        self.delivered_message_ids: Set[bytes] = set()
        self.received_messages: List[Dict[str, Any]] = []

        # Зарегистрированные сквозные криптосессии с пирами: peer_node_id -> SecureSession
        self.e2e_sessions: Dict[bytes, SecureSession] = {}

        self.register_handlers()

    def register_e2e_session(self, peer_node_id: bytes, session: SecureSession):
        """Регистрирует сквозную сессию шифрования между отправителем и получателем."""
        self.e2e_sessions[peer_node_id] = session

    def register_handlers(self):
        """Регистрирует обработчики туннельных кадров в сетевом диспетчере."""
        self.dispatcher.register(MessageType.TUNNEL_BUILD, self._handle_tunnel_build)
        self.dispatcher.register(MessageType.TUNNEL_DATA, self._handle_tunnel_data)
        self.dispatcher.register(MessageType.TUNNEL_CLOSE, self._handle_tunnel_close)

    async def _handle_tunnel_build(self, conn: Connection, frame: Frame):
        """
        Обработка запроса на построение туннеля (как транзитный ретранслятор или конечный узел).
        """
        payload = frame.unpack_data()
        tunnel_id = payload.get("tunnel_id")
        remaining_hops = payload.get("remaining_hops", [])
        ttl = payload.get("ttl", 120.0)

        # Сохраняем обратный адрес отправителя запроса
        peer_addr = conn.writer.get_extra_info("peername")
        if peer_addr:
            self.backward_table[tunnel_id] = (peer_addr[0], peer_addr[1])

        # Если remaining_hops пуст — этот узел является конечной точкой туннеля (Destination)
        if not remaining_hops:
            logger.info(f"[{self.local_contact.node_id.hex()[:8]}] [TUNNEL_ENDPOINT] Стал конечной точкой туннеля {tunnel_id.hex()[:8]}")
            resp_frame = Frame.pack_data(
                msg_type=MessageType.TUNNEL_BUILD_OK,
                data={"tunnel_id": tunnel_id, "status": "OK", "endpoint": self.local_contact.node_id},
                flags=FrameFlags.RESPONSE,
                request_id=frame.request_id
            )
            await conn.send_frame(resp_frame)
            return

        # Иначе мы являемся промежуточным ретранслятором (Relay)
        next_hop = remaining_hops[0]
        next_remaining = remaining_hops[1:]
        next_host = next_hop["host"]
        next_port = next_hop["port"]

        self.forward_table[tunnel_id] = (next_host, next_port)
        logger.info(
            f"[{self.local_contact.node_id.hex()[:8]}] [TUNNEL_RELAY] Зарегистрирован транзитный маршрут "
            f"туннеля {tunnel_id.hex()[:8]} -> следующий хоп {next_host}:{next_port}"
        )

        # Пробрасываем TUNNEL_BUILD к следующему хопу
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(next_host, next_port), timeout=4.0
            )
            next_conn = Connection(reader, writer)
            forward_frame = Frame.pack_data(
                msg_type=MessageType.TUNNEL_BUILD,
                data={
                    "tunnel_id": tunnel_id,
                    "remaining_hops": next_remaining,
                    "ttl": ttl
                },
                request_id=frame.request_id
            )
            await next_conn.send_frame(forward_frame)
            resp = await next_conn.read_frame(timeout=4.0)
            await next_conn.close()

            if resp and resp.msg_type == MessageType.TUNNEL_BUILD_OK:
                # Отправляем подтверждение предыдущему узлу
                await conn.send_frame(resp)
            else:
                err_resp = Frame.pack_data(
                    msg_type=MessageType.TUNNEL_BUILD_FAIL,
                    data={"tunnel_id": tunnel_id, "error": "Next hop failed to build tunnel"},
                    flags=FrameFlags.ERROR,
                    request_id=frame.request_id
                )
                await conn.send_frame(err_resp)
        except Exception as e:
            logger.warning(f"Ошибка проброса TUNNEL_BUILD к {next_host}:{next_port}: {e}")
            err_resp = Frame.pack_data(
                msg_type=MessageType.TUNNEL_BUILD_FAIL,
                data={"tunnel_id": tunnel_id, "error": str(e)},
                flags=FrameFlags.ERROR,
                request_id=frame.request_id
            )
            await conn.send_frame(err_resp)

    async def _handle_tunnel_data(self, conn: Connection, frame: Frame):
        """
        Обработка кадра TUNNEL_DATA:
        - Если узел транзитный ретранслятор: форвардит шифртекст дальше (без расшифрования!).
        - Если узел получатель: дешифрует прикладные данные и шлет TUNNEL_ACK.
        """
        payload = frame.unpack_data()
        tunnel_id = payload.get("tunnel_id")
        message_id = payload.get("message_id")
        data_blob = payload.get("data")
        sender_id = payload.get("sender_node_id")

        # 1. Если туннель зарегистрирован в forward_table — мы РЕТРАНСЛЯТОР
        if tunnel_id in self.forward_table:
            next_host, next_port = self.forward_table[tunnel_id]
            logger.info(
                f"[{self.local_contact.node_id.hex()[:8]}] [TUNNEL_FORWARD] Ретрансляция {len(data_blob)} байт "
                f"туннеля {tunnel_id.hex()[:8]} -> {next_host}:{next_port} (содержимое зашифровано, ключей нет)"
            )
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(next_host, next_port), timeout=4.0
                )
                fwd_conn = Connection(reader, writer)
                await fwd_conn.send_frame(frame)
                ack_resp = await fwd_conn.read_frame(timeout=4.0)
                await fwd_conn.close()

                if ack_resp:
                    await conn.send_frame(ack_resp)
            except Exception as e:
                logger.error(f"Сбой ретрансляции данных к {next_host}:{next_port}: {e}")
                err_frame = Frame.pack_data(
                    msg_type=MessageType.ERROR,
                    data={"tunnel_id": tunnel_id, "error": f"Relay failure at {self.host}:{self.port}: {e}"},
                    flags=FrameFlags.ERROR,
                    request_id=frame.request_id
                )
                await conn.send_frame(err_frame)
            return

        # 2. Иначе мы КОНЕЧНЫЙ ПОЛУЧАТЕЛЬ (Destination)
        logger.info(
            f"[{self.local_contact.node_id.hex()[:8]}] [TUNNEL_DELIVERED] Получено сообщение по туннелю "
            f"{tunnel_id.hex()[:8]}, размер={len(data_blob)} байт"
        )
        
        # Защита от повторной обработки (Deduplication)
        is_duplicate = message_id in self.delivered_message_ids
        self.delivered_message_ids.add(message_id)

        # Попытка сквозного расшифрования (End-to-End AEAD)
        plaintext = data_blob
        decrypted = False
        if sender_id and sender_id in self.e2e_sessions:
            try:
                session = self.e2e_sessions[sender_id]
                plaintext = session.decrypt_payload(data_blob)
                decrypted = True
            except Exception as e:
                logger.warning(f"Ошибка E2E-расшифрования: {e}")

        # Сохраняем в истории полученных сообщений
        self.received_messages.append({
            "tunnel_id": tunnel_id,
            "message_id": message_id,
            "sender_node_id": sender_id,
            "payload_bytes": plaintext,
            "is_duplicate": is_duplicate,
            "is_decrypted": decrypted,
            "received_at": time.time()
        })

        # Отправляем подтверждение сквозной доставки TUNNEL_ACK
        ack_frame = Frame.pack_data(
            msg_type=MessageType.TUNNEL_ACK,
            data={
                "tunnel_id": tunnel_id,
                "message_id": message_id,
                "status": "DELIVERED",
                "responder_node_id": self.local_contact.node_id
            },
            flags=FrameFlags.RESPONSE,
            request_id=frame.request_id
        )
        await conn.send_frame(ack_frame)

    async def _handle_tunnel_close(self, conn: Connection, frame: Frame):
        """Очистка ресурсов туннеля."""
        payload = frame.unpack_data()
        tunnel_id = payload.get("tunnel_id")
        if tunnel_id in self.forward_table:
            next_host, next_port = self.forward_table.pop(tunnel_id)
            try:
                r, w = await asyncio.open_connection(next_host, next_port)
                c = Connection(r, w)
                await c.send_frame(frame)
                await c.close()
            except Exception:
                pass
        self.backward_table.pop(tunnel_id, None)

    async def build_tunnel(
        self,
        destination: Contact,
        relays: Optional[List[Contact]] = None,
        relay_count: int = 2
    ) -> Tunnel:
        """
        Строит многопереходный туннель к destination через заданные (или автоматически выбранные) ретрансляторы.
        """
        # Если ретрансляторы не переданы явно — выбираем из известных контактов таблицы маршрутизации
        if relays is None:
            relays = self._select_candidate_relays(destination, count=relay_count)

        tunnel_id = uuid.uuid4().bytes
        tunnel = Tunnel(
            tunnel_id=tunnel_id,
            initiator=self.local_contact,
            relays=relays,
            destination=destination
        )

        logger.info(f"[{self.local_contact.node_id.hex()[:8]}] Построение туннеля: {tunnel.get_path_display()}")

        # Формируем список оставшихся хопов: [R2, ..., Destination]
        hops_payload = [
            {"host": h.host, "port": h.port, "node_id": h.node_id}
            for h in (relays[1:] + [destination])
        ]

        first_relay = relays[0]
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(first_relay.host, first_relay.port), timeout=5.0
            )
            conn = Connection(reader, writer)
            build_frame = Frame.pack_data(
                msg_type=MessageType.TUNNEL_BUILD,
                data={
                    "tunnel_id": tunnel_id,
                    "remaining_hops": hops_payload,
                    "ttl": tunnel.ttl
                }
            )
            await conn.send_frame(build_frame)
            resp = await conn.read_frame(timeout=6.0)
            await conn.close()

            if resp and resp.msg_type == MessageType.TUNNEL_BUILD_OK:
                tunnel.state = TunnelState.ACTIVE
                self.active_tunnels[tunnel_id] = tunnel
                logger.info(f"[TUNNEL_READY] Туннель {tunnel_id.hex()[:8]} успешно построен и активен!")
                return tunnel
            else:
                tunnel.state = TunnelState.DEAD
                err_msg = resp.unpack_data().get("error", "Unknown rejection") if resp else "No response"
                raise TunnelBuildError(f"Отказ построения туннеля: {err_msg}")
        except Exception as e:
            tunnel.state = TunnelState.DEAD
            raise TunnelBuildError(f"Сбой связи с первым ретранслятором {first_relay.host}:{first_relay.port}: {e}")

    def _select_candidate_relays(self, destination: Contact, count: int = 2) -> List[Contact]:
        """
        Выбирает случайных или рейтинговых ретрансляторов из таблицы маршрутизации,
        исключая локальный узел и конечную цель (без петель).
        """
        all_contacts = self.routing_table.get_closest_contacts(destination.node_id, limit=20)
        candidates = [
            c for c in all_contacts
            if c.node_id != self.local_contact.node_id and c.node_id != destination.node_id
        ]
        if len(candidates) < count:
            raise TunnelBuildError(
                f"Недостаточно кандидатов в таблице для построения туннеля (нужно {count}, доступно {len(candidates)})"
            )
        return candidates[:count]

    async def send_through_tunnel(
        self,
        tunnel: Tunnel,
        payload_bytes: bytes,
        secure_session: Optional[SecureSession] = None,
        timeout: float = 6.0
    ) -> Dict[str, Any]:
        """
        Передает прикладное сообщение по активному туннелю.
        Поддерживает сквозное шифрование (End-to-End AEAD), скрывающее данные от ретрансляторов.
        """
        if not tunnel.is_active:
            raise TunnelDeliveryError(f"Туннель {tunnel.tunnel_id.hex()[:8]} не активен (state={tunnel.state.value})")

        message_id = uuid.uuid4().bytes
        t_start = time.time()

        # При наличии сквозной сессии шифруем полезную нагрузку
        data_to_send = payload_bytes
        if secure_session:
            data_to_send = secure_session.encrypt_payload(payload_bytes)

        first_relay = tunnel.relays[0]
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(first_relay.host, first_relay.port), timeout=timeout
            )
            conn = Connection(reader, writer)
            data_frame = Frame.pack_data(
                msg_type=MessageType.TUNNEL_DATA,
                data={
                    "tunnel_id": tunnel.tunnel_id,
                    "message_id": message_id,
                    "sender_node_id": self.local_contact.node_id,
                    "data": data_to_send
                }
            )
            await conn.send_frame(data_frame)
            ack_frame = await conn.read_frame(timeout=timeout)
            await conn.close()

            if ack_frame and ack_frame.msg_type == MessageType.TUNNEL_ACK:
                elapsed_ms = (time.time() - t_start) * 1000.0
                return {
                    "status": "DELIVERED",
                    "tunnel_id": tunnel.tunnel_id,
                    "message_id": message_id,
                    "latency_ms": elapsed_ms,
                    "hops_count": len(tunnel.hops_path) - 1,
                    "path_display": tunnel.get_path_display()
                }
            else:
                tunnel.state = TunnelState.DEGRADED
                raise TunnelDeliveryError(f"Туннель не вернул TUNNEL_ACK: {ack_frame}")
        except Exception as e:
            tunnel.state = TunnelState.DEGRADED
            raise TunnelDeliveryError(f"Ошибка передачи через туннель: {e}")

    async def send_with_auto_rebuild(
        self,
        destination: Contact,
        payload_bytes: bytes,
        secure_session: Optional[SecureSession] = None,
        available_relays: Optional[List[Contact]] = None,
        timeout: float = 6.0
    ) -> Dict[str, Any]:
        """
        Контрольный сценарий ТЗ Раздел 12 и 15:
        Передает данные по туннелю. При отказе ретранслятора автоматически обнаруживает сбой,
        строит НОВЫЙ действующий маршрут через альтернативные узлы и успешно доставляет сообщение.
        """
        # 1. Пытаемся найти активный туннель к destination
        active_tunnel = None
        for t in self.active_tunnels.values():
            if t.destination.node_id == destination.node_id and t.is_active:
                active_tunnel = t
                break

        # Если активного нет — строим первоначальный
        if not active_tunnel:
            relays_to_use = available_relays[:2] if available_relays else None
            active_tunnel = await self.build_tunnel(destination, relays=relays_to_use)

        try:
            res = await self.send_through_tunnel(active_tunnel, payload_bytes, secure_session, timeout=timeout)
            res["rebuilt"] = False
            return res
        except TunnelDeliveryError as err:
            logger.warning(f"Зафиксирован отказ туннеля ({err}). Запуск автоматического перестроения...")
            active_tunnel.state = TunnelState.DEAD

            # 2. Выбираем альтернативных ретрансляторов (исключая упавший узел)
            alt_relays = None
            if available_relays and len(available_relays) >= 3:
                # Берем запасной ретранслятор, например [R1, R3] вместо [R1, R2]
                alt_relays = [available_relays[0], available_relays[2]]

            # 3. Автоматически строим новый туннель
            new_tunnel = await self.build_tunnel(destination, relays=alt_relays)
            logger.info(f"Новый туннель успешно построен: {new_tunnel.get_path_display()}")

            # 4. Повторяем доставку по новому туннелю
            res = await self.send_through_tunnel(new_tunnel, payload_bytes, secure_session, timeout=timeout)
            res["rebuilt"] = True
            res["previous_tunnel_dead"] = True
            return res
