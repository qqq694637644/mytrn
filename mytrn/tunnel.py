"""QUIC-over-UDP transport and allowlisted TCP port forwarding.

B initiates QUIC via a WARP SOCKS5 UDP relay. A listens on the same UDP
socket used for STUN; QUIC provides encryption, reliable ordered streams,
retransmission, flow control and congestion control. No home-side TCP port is
opened by mytrn.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import ssl
import time
from typing import Callable

from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted, PingAcknowledged, StreamDataReceived
from aioquic.quic.packet import QuicPacketType, pull_quic_header

from .config import SERVER_NAME

LOG = logging.getLogger("mytrn.tunnel")
ALPN = "mytrn/1"
MAX_ACTIVE_STREAMS = 32
MAX_BUFFERED_PER_STREAM = 512 * 1024


def make_server_quic_config(certfile: str, keyfile: str) -> QuicConfiguration:
    config = QuicConfiguration(is_client=False, alpn_protocols=[ALPN], max_datagram_size=1200,
                               max_data=1024 * 1024, max_stream_data=256 * 1024, idle_timeout=90.0)
    config.load_cert_chain(certfile, keyfile)
    return config


def make_client_quic_config(cert_pem: str) -> QuicConfiguration:
    return QuicConfiguration(is_client=True, alpn_protocols=[ALPN], server_name=SERVER_NAME,
                             cadata=cert_pem.encode("ascii"), verify_mode=ssl.CERT_REQUIRED,
                             max_datagram_size=1200, max_data=1024 * 1024,
                             max_stream_data=256 * 1024, idle_timeout=90.0)


def stream_proof(psk: str, rule: str, timestamp: int, nonce: str) -> str:
    return hmac.new(psk.encode(), f"{rule}|{timestamp}|{nonce}".encode(), hashlib.sha256).hexdigest()


class QuicSession:
    """Run aioquic's I/O-independent state machine over an arbitrary UDP sender."""

    def __init__(self, quic: QuicConnection, send_packet: Callable[[bytes, tuple], None], peer: tuple,
                 on_new_stream=None):
        self.quic = quic
        self.send_packet = send_packet
        self.peer = peer
        self.on_new_stream = on_new_stream
        self.connected = asyncio.Event()
        self.closed = asyncio.Event()
        self.streams: dict[int, asyncio.Queue] = {}
        self.last_packet_at = time.monotonic()
        self.last_ping_at = 0.0
        self.last_pong_at = 0.0
        self.error = ""
        self._timer_task: asyncio.Task | None = None
        self._tasks: set[asyncio.Task] = set()
        self._ping_uid = 0
        self._loop = asyncio.get_running_loop()

    def start(self):
        self._timer_task = asyncio.create_task(self._timer_loop())
        self.flush()

    def client_connect(self):
        self.quic.connect(self.peer, self._loop.time())
        self.start()

    def flush(self):
        if self.closed.is_set():
            return
        for packet, address in self.quic.datagrams_to_send(self._loop.time()):
            self.send_packet(packet, address)

    async def _timer_loop(self):
        try:
            while not self.closed.is_set():
                timer = self.quic.get_timer()
                delay = 0.1 if timer is None else max(0.001, min(0.1, timer - self._loop.time()))
                await asyncio.sleep(delay)
                if timer is not None and self._loop.time() >= timer:
                    self.quic.handle_timer(self._loop.time())
                    self._drain_events()
                    self.flush()
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            self.error = f"timer error: {exc}"
            LOG.exception("QUIC timer error")
            self._finish()

    def receive(self, packet: bytes, src: tuple):
        if self.closed.is_set():
            return
        try:
            self.quic.receive_datagram(packet, src, self._loop.time())
            self.last_packet_at = time.monotonic()
            self._drain_events()
            self.flush()
        except Exception as exc:
            # A single malformed datagram must not bring the daemon down.
            LOG.debug("bad QUIC datagram ignored: %s", exc)

    def _drain_events(self):
        while True:
            event = self.quic.next_event()
            if event is None:
                break
            if isinstance(event, HandshakeCompleted):
                self.connected.set()
                self.last_pong_at = time.monotonic()
            elif isinstance(event, PingAcknowledged):
                self.last_pong_at = time.monotonic()
            elif isinstance(event, ConnectionTerminated):
                self.error = event.reason_phrase or f"QUIC code={event.error_code}"
                self._finish()
            elif isinstance(event, StreamDataReceived):
                queue = self.streams.get(event.stream_id)
                if queue is None:
                    if len(self.streams) >= MAX_ACTIVE_STREAMS:
                        self.quic.stop_stream(event.stream_id, error_code=1)
                        self.quic.reset_stream(event.stream_id, error_code=1)
                        continue
                    queue = asyncio.Queue(maxsize=256)
                    self.streams[event.stream_id] = queue
                    if self.on_new_stream:
                        task = asyncio.create_task(self.on_new_stream(self, event.stream_id, queue))
                        self._tasks.add(task)
                        task.add_done_callback(self._tasks.discard)
                try:
                    queue.put_nowait((event.data, event.end_stream))
                except asyncio.QueueFull:
                    self.error = "inbound stream buffer exhausted"
                    self.quic.close(reason_phrase=self.error)
                    self._finish()
                    break

    def _finish(self):
        if self.closed.is_set():
            return
        self.closed.set()
        for queue in self.streams.values():
            try:
                queue.put_nowait((b"", True))
            except asyncio.QueueFull:
                pass

    def new_stream(self):
        if not self.connected.is_set() or self.closed.is_set():
            raise ConnectionError("QUIC data plane is not connected")
        if len(self.streams) >= MAX_ACTIVE_STREAMS:
            raise ConnectionError("maximum active streams reached")
        stream_id = self.quic.get_next_available_stream_id()
        queue = asyncio.Queue(maxsize=256)
        self.streams[stream_id] = queue
        return stream_id, queue

    def send_stream(self, stream_id: int, data: bytes, end=False):
        if self.closed.is_set():
            raise ConnectionError("QUIC session closed")
        self.quic.send_stream_data(stream_id, data, end_stream=end)
        self.flush()

    async def send_stream_bounded(self, stream_id: int, data: bytes):
        """Backpressure local TCP reads when QUIC has too much unacknowledged data.

        aioquic 1.3 has no public per-stream buffered-byte metric. Since the
        dependency is pinned, read its sender buffer (never mutate it).
        """
        while not self.closed.is_set():
            stream = self.quic._streams.get(stream_id)
            sender = stream.sender if stream else None
            pending = len(sender._buffer) if sender else 0
            if pending < MAX_BUFFERED_PER_STREAM:
                self.send_stream(stream_id, data)
                return
            await asyncio.sleep(0.02)
        raise ConnectionError("QUIC session closed")

    def ping(self):
        if self.connected.is_set() and not self.closed.is_set():
            self._ping_uid += 1
            self.last_ping_at = time.monotonic()
            self.quic.send_ping(self._ping_uid)
            self.flush()

    async def close(self):
        if not self.closed.is_set():
            self.quic.close(reason_phrase="shutdown")
            self.flush()
            self._finish()
        if self._timer_task:
            self._timer_task.cancel()
            await asyncio.gather(self._timer_task, return_exceptions=True)
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)


class AQuicServer:
    """Allow exactly one active B-initiated QUIC session per A node."""

    def __init__(self, config: QuicConfiguration, send_packet, handle_stream):
        self.config = config
        self.send_packet = send_packet
        self.handle_stream = handle_stream
        self.session: QuicSession | None = None
        self.original_cid: bytes | None = None
        self.last_accept = 0.0

    def receive(self, packet: bytes, src: tuple):
        try:
            header = pull_quic_header(Buffer(data=packet), host_cid_length=self.config.connection_id_length)
        except Exception:
            return
        new_initial = header.packet_type == QuicPacketType.INITIAL and header.destination_cid != self.original_cid
        if new_initial:
            # Never displace a healthy session with unauthenticated Initial packets.
            if self.session and not self.session.closed.is_set() and time.monotonic() - self.session.last_packet_at < 12:
                return
            if time.monotonic() - self.last_accept < 2:
                return
            if self.session:
                asyncio.create_task(self.session.close())
            try:
                quic = QuicConnection(configuration=self.config,
                                      original_destination_connection_id=header.destination_cid)
            except Exception:
                return
            self.session = QuicSession(quic, self.send_packet, src, self.handle_stream)
            self.original_cid = header.destination_cid
            self.last_accept = time.monotonic()
            # aioquic's server has no validated network path until it has
            # processed the first Initial. Flush only *after* receive_datagram.
            self.session.receive(packet, src)
            self.session.start()
            return
        if self.session and not self.session.closed.is_set():
            self.session.receive(packet, src)

    async def close(self):
        if self.session:
            await self.session.close()


async def pull_line(queue: asyncio.Queue, max_bytes=1024) -> tuple[bytes, bytes, bool]:
    """Read one newline-delimited stream header, retaining trailing data."""
    buff = bytearray()
    while b"\n" not in buff:
        data, end = await queue.get()
        buff.extend(data)
        if len(buff) > max_bytes:
            raise ValueError("stream header exceeds 1024 bytes")
        if end and b"\n" not in buff:
            raise EOFError("stream ended before header")
    line, remainder = bytes(buff).split(b"\n", 1)
    return line, remainder, end


async def bridge_stream(session: QuicSession, sid: int, queue: asyncio.Queue,
                        reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                        first_data: bytes = b"", first_end: bool = False):
    """Bidirectional TCP<->QUIC stream bridge, including TCP half-close."""

    async def quic_to_tcp():
        if first_data:
            writer.write(first_data); await writer.drain()
        if first_end:
            if writer.can_write_eof():
                writer.write_eof()
            return
        while not session.closed.is_set():
            data, end = await queue.get()
            if data:
                writer.write(data)
                await writer.drain()
            if end:
                if writer.can_write_eof():
                    writer.write_eof()
                return

    async def tcp_to_quic():
        while not session.closed.is_set():
            block = await reader.read(8192)
            if not block:
                try:
                    session.send_stream(sid, b"", end=True)
                except ConnectionError:
                    pass
                return
            await session.send_stream_bounded(sid, block)
            # Yield often on high-RTT links; QUIC handles retransmission/flow-control.
            await asyncio.sleep(0)

    inbound = asyncio.create_task(quic_to_tcp())
    outbound = asyncio.create_task(tcp_to_quic())
    terminated = asyncio.create_task(session.closed.wait())
    try:
        done, pending = await asyncio.wait((inbound, outbound, terminated), return_when=asyncio.FIRST_COMPLETED)
        if terminated in done or any(t.exception() for t in done if t is not terminated and not t.cancelled()):
            for task in pending:
                task.cancel()
        else:
            # A TCP half-close is legitimate. Give the other direction time to finish.
            await asyncio.wait((inbound, outbound, terminated), timeout=60, return_when=asyncio.ALL_COMPLETED)
    finally:
        for task in (inbound, outbound, terminated):
            if not task.done():
                task.cancel()
        await asyncio.gather(inbound, outbound, terminated, return_exceptions=True)
        writer.close()
        await writer.wait_closed()
        session.streams.pop(sid, None)


class AStreamHandler:
    def __init__(self, targets: dict, data_psk: str):
        self.targets = targets
        self.data_psk = data_psk
        self.seen_nonces: dict[str, float] = {}

    async def __call__(self, session: QuicSession, sid: int, queue: asyncio.Queue):
        try:
            line, remaining, ended = await asyncio.wait_for(pull_line(queue), 10)
            request = json.loads(line)
            rule = request.get("rule", "")
            timestamp = request.get("ts", 0)
            nonce = request.get("nonce", "")
            mac = request.get("mac", "")
            now = time.time()
            if (not isinstance(rule, str) or rule not in self.targets or
                type(timestamp) is not int or abs(now - timestamp) > 120 or
                not isinstance(nonce, str) or len(nonce) < 16 or
                nonce in self.seen_nonces or not isinstance(mac, str) or
                not hmac.compare_digest(mac, stream_proof(self.data_psk, rule, timestamp, nonce))):
                raise PermissionError("unauthorized or unknown port rule")
            self.seen_nonces = {k: t for k, t in self.seen_nonces.items() if now - t < 180}
            self.seen_nonces[nonce] = now
            target = self.targets[rule]
            reader, writer = await asyncio.wait_for(asyncio.open_connection(target["host"], target["port"]), 8)
        except Exception as exc:
            LOG.warning("A rejected forwarding stream %s: %s", sid, exc)
            try:
                session.send_stream(sid, b"ERR\n", end=True)
            except ConnectionError:
                pass
            session.streams.pop(sid, None)
            return
        LOG.info("A accepted stream %s to allowlisted target %s:%s", sid, target["host"], target["port"])
        try:
            session.send_stream(sid, b"OK\n")
            await bridge_stream(session, sid, queue, reader, writer, remaining, ended)
        except (ConnectionError, OSError):
            pass


async def b_forward_tcp(session: QuicSession, rule: str, data_psk: str,
                        reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    if not session.connected.is_set() or session.closed.is_set():
        writer.close(); await writer.wait_closed()
        return
    try:
        sid, queue = session.new_stream()
        timestamp = int(time.time())
        nonce = secrets.token_hex(12)
        open_request = {
            "rule": rule, "ts": timestamp, "nonce": nonce,
            "mac": stream_proof(data_psk, rule, timestamp, nonce),
        }
        session.send_stream(sid, json.dumps(open_request, separators=(",", ":")).encode() + b"\n")
        response, remaining, ended = await asyncio.wait_for(pull_line(queue), 15)
        if response != b"OK":
            raise ConnectionError("A refused allowlisted TCP target")
        await bridge_stream(session, sid, queue, reader, writer, remaining, ended)
    except (OSError, ValueError, asyncio.TimeoutError, ConnectionError) as exc:
        LOG.warning("B local forwarding %s failed: %s", rule, exc)
        writer.close()
        await writer.wait_closed()
