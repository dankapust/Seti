import asyncio
import pytest
import uuid
import struct
from src.transport import (
    Frame,
    MessageType,
    FrameFlags,
    Connection,
    Dispatcher,
    PROTOCOL_VERSION,
    MAX_FRAME_PAYLOAD,
    FramingError,
    PayloadLengthExceededError,
    InvalidProtocolVersionError,
    ReadTimeoutError,
)
from src.transport.protocol import (
    HEADER_SIZE, 
    HEADER_FORMAT
)

@pytest.mark.asyncio
async def test_frame_encoding_decoding():
    request_id = uuid.uuid4().bytes
    original_frame = Frame.pack_data(
        msg_type=MessageType.PING,
        data={"sender": "node_1", "timestamp": 123456789},
        flags=FrameFlags.NONE,
        request_id=request_id,
    )
    
    encoded_data = original_frame.encode()
    assert len(encoded_data) == HEADER_SIZE + len(original_frame.payload)
    
    version, msg_type, flags, req_id, payload_len = Frame.decode_header(encoded_data[:HEADER_SIZE])
    assert version == PROTOCOL_VERSION
    assert msg_type == MessageType.PING
    assert flags == FrameFlags.NONE
    assert req_id == request_id
    assert payload_len == len(original_frame.payload)
    
    decoded_frame = Frame(
        msg_type=msg_type,
        payload=encoded_data[HEADER_SIZE:],
        flags=flags,
        request_id=req_id,
        version=version,
    )
    unpacked = decoded_frame.unpack_data()
    assert unpacked == {"sender": "node_1", "timestamp": 123456789}

@pytest.mark.asyncio
async def test_payload_length_exceeded():
    with pytest.raises(PayloadLengthExceededError):
        Frame(msg_type=MessageType.PING, payload=b"X" * (MAX_FRAME_PAYLOAD + 1))
        
    bad_header = struct.pack(
        HEADER_FORMAT,
        PROTOCOL_VERSION,
        int(MessageType.PING),
        int(FrameFlags.NONE),
        uuid.uuid4().bytes,
        MAX_FRAME_PAYLOAD + 1000,
    )
    with pytest.raises(PayloadLengthExceededError):
        Frame.decode_header(bad_header)

@pytest.mark.asyncio
async def test_stream_framing_concatenated_and_partial():
    """Tests receiving 100 frames of varying payload lengths over TCP stream with partial & concatenated reads."""
    server_received_frames = []

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        conn = Connection(reader, writer)
        while True:
            frame = await conn.read_frame()
            if frame is None:
                break
            server_received_frames.append(frame)
        await conn.close()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    server_port = server.sockets[0].getsockname()[1]

    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", server_port)
        client_conn = Connection(reader, writer)

        sent_frames = []
        blob_stream = bytearray()
        
        for i in range(100):
            payload_data = {"seq": i, "content": "A" * (i * 50)}
            frame = Frame.pack_data(msg_type=MessageType.PING, data=payload_data)
            sent_frames.append(frame)
            blob_stream.extend(frame.encode())

        # Send in random chunk sizes to simulate TCP fragmentation and concatenation
        chunk_sizes = [7, 13, 256, 1024, 4096, 50]
        offset = 0
        idx = 0
        while offset < len(blob_stream):
            sz = chunk_sizes[idx % len(chunk_sizes)]
            chunk = blob_stream[offset:offset + sz]
            writer.write(chunk)
            await writer.drain()
            offset += sz
            idx += 1
            await asyncio.sleep(0.001)

        await client_conn.close()
        await asyncio.sleep(0.1)

    assert len(server_received_frames) == 100
    for i in range(100):
        recv_data = server_received_frames[i].unpack_data()
        assert recv_data["seq"] == i
        assert recv_data["content"] == "A" * (i * 50)

@pytest.mark.asyncio
async def test_invalid_protocol_version():
    """Test protocol version validation"""
    bad_header = struct.pack(
        HEADER_FORMAT,
        99, # Invalid version
        int(MessageType.PING),
        int(FrameFlags.NONE),
        uuid.uuid4().bytes,
        50,
    )
    with pytest.raises(InvalidProtocolVersionError):
        Frame.decode_header(bad_header)

@pytest.mark.asyncio
async def test_invalid_message_type():
    """Test invalid message type error"""
    bad_header = struct.pack(
        HEADER_FORMAT,
        PROTOCOL_VERSION,
        99, # Invalid type
        int(FrameFlags.NONE),
        uuid.uuid4().bytes,
        50,
    )
    with pytest.raises(FramingError, match="Unknown message type"):
        Frame.decode_header(bad_header)

@pytest.mark.asyncio
async def test_independent_nodes_different_ports_concurrent():
    """E1-1 / E1-8: Test independent simultaneous processes/servers running on different ports concurrently."""
    nodes_received = {}

    def make_node_server(node_name):
        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            conn = Connection(reader, writer)
            frame = await conn.read_frame()
            if frame:
                nodes_received[node_name] = frame.unpack_data()
                pong = Frame.pack_data(
                    msg_type=MessageType.PONG,
                    data={"responder": node_name, "status": "OK"},
                    request_id=frame.request_id,
                )
                await conn.send_frame(pong)
            await conn.close()
        return handle_client

    server1 = await asyncio.start_server(make_node_server("node_8101"), "127.0.0.1", 0)
    server2 = await asyncio.start_server(make_node_server("node_8102"), "127.0.0.1", 0)
    port1 = server1.sockets[0].getsockname()[1]
    port2 = server2.sockets[0].getsockname()[1]

    async def send_to(port, sender_id):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        conn = Connection(reader, writer)
        frame = Frame.pack_data(MessageType.PING, {"sender": sender_id})
        await conn.send_frame(frame)
        resp = await conn.read_frame(timeout=2.0)
        await conn.close()
        return resp.unpack_data()

    res1, res2 = await asyncio.gather(
        send_to(port1, "client_A"),
        send_to(port2, "client_B"),
    )

    server1.close()
    server2.close()
    await server1.wait_closed()
    await server2.wait_closed()

    assert nodes_received["node_8101"] == {"sender": "client_A"}
    assert nodes_received["node_8102"] == {"sender": "client_B"}
    assert res1["responder"] == "node_8101"
    assert res2["responder"] == "node_8102"

@pytest.mark.asyncio
async def test_read_frame_timeout():
    """E1-3 / E1-8: Test read_frame timeout raises ReadTimeoutError."""
    async def silent_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        conn = Connection(reader, writer)
        await asyncio.sleep(2.0)
        await conn.close()

    server = await asyncio.start_server(silent_server, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        conn = Connection(reader, writer)

        with pytest.raises((ReadTimeoutError, asyncio.TimeoutError)):
            await conn.read_frame(timeout=0.1)

        await conn.close()

@pytest.mark.asyncio
async def test_dispatcher_error_handling():
    """E1-6 / E1-8: Test dispatcher sending ERROR frame when handler or unknown msg type occurs."""
    dispatcher = Dispatcher()

    async def faulty_handler(conn: Connection, frame: Frame):
        raise ValueError("Simulated handler exception")

    dispatcher.register(MessageType.PING, faulty_handler)

    sent_frames = []

    class MockConnection:
        async def send_frame(self, frame: Frame):
            sent_frames.append(frame)

    mock_conn = MockConnection()
    ping_frame = Frame.pack_data(MessageType.PING, {"test": True})
    await dispatcher.dispatch(mock_conn, ping_frame)

    assert len(sent_frames) == 1
    assert sent_frames[0].msg_type == MessageType.ERROR
    assert sent_frames[0].flags == FrameFlags.ERROR
    assert "Simulated handler exception" in sent_frames[0].unpack_data()["error"]
