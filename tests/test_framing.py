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
)
from src.transport.protocol import PayloadLengthExceededError, FramingError, HEADER_SIZE, HEADER_FORMAT

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
