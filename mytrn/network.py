"""Low-level SOCKS5 UDP transport, SOCKS5 TCP control and STUN."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import struct
from typing import Callable
from urllib.parse import unquote, urlsplit

MAGIC = 0x2112A442


class SocksError(OSError):
    pass


def host_port(text: str, default: int) -> tuple[str, int]:
    if text.startswith("["):
        host, sep, tail = text[1:].partition("]")
        if not sep:
            raise ValueError("invalid host:port")
        return host, int(tail[1:]) if tail.startswith(":") else default
    if text.count(":") == 1:
        host, port = text.rsplit(":", 1)
        return host, int(port)
    return text, default


def socks_address(host: str, port: int) -> bytes:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        name = host.encode("idna")
        if len(name) > 255:
            raise ValueError("SOCKS hostname too long")
        encoded = b"\x03" + bytes([len(name)]) + name
    else:
        encoded = (b"\x01" if addr.version == 4 else b"\x04") + addr.packed
    return encoded + struct.pack("!H", port)


def unpack_socks_address(raw: bytes, pos: int = 0) -> tuple[tuple[str, int], int]:
    atyp = raw[pos]
    pos += 1
    if atyp == 1:
        n = 4
        host = socket.inet_ntop(socket.AF_INET, raw[pos:pos+n]); pos += n
    elif atyp == 4:
        n = 16
        host = socket.inet_ntop(socket.AF_INET6, raw[pos:pos+n]); pos += n
    elif atyp == 3:
        n = raw[pos]; pos += 1
        host = raw[pos:pos+n].decode("idna"); pos += n
    else:
        raise SocksError("invalid SOCKS address type")
    if len(raw) < pos + 2:
        raise SocksError("short SOCKS address")
    port = struct.unpack_from("!H", raw, pos)[0]
    return (host, port), pos + 2


async def read_socks_address(reader: asyncio.StreamReader) -> tuple[str, int]:
    atyp = (await reader.readexactly(1))[0]
    if atyp == 1:
        raw = bytes([atyp]) + await reader.readexactly(4 + 2)
    elif atyp == 4:
        raw = bytes([atyp]) + await reader.readexactly(16 + 2)
    elif atyp == 3:
        length = await reader.readexactly(1)
        raw = bytes([atyp]) + length + await reader.readexactly(length[0] + 2)
    else:
        raise SocksError("unknown SOCKS address type")
    return unpack_socks_address(raw)[0]


async def socks_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, url: str):
    proxy = urlsplit(url)
    methods = [0]
    if proxy.username is not None:
        methods.append(2)
    writer.write(bytes([5, len(methods), *methods])); await writer.drain()
    response = await reader.readexactly(2)
    if response[0] != 5 or response[1] == 0xff:
        raise SocksError("SOCKS5 auth negotiation rejected")
    if response[1] == 2:
        if proxy.username is None:
            raise SocksError("SOCKS proxy requires credentials")
        user = unquote(proxy.username).encode(); password = unquote(proxy.password or "").encode()
        if len(user) > 255 or len(password) > 255:
            raise SocksError("SOCKS credentials too long")
        writer.write(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
        await writer.drain()
        if await reader.readexactly(2) != b"\x01\x00":
            raise SocksError("SOCKS credentials rejected")
    elif response[1] != 0:
        raise SocksError("unsupported SOCKS5 authentication method")


async def socks_command(reader, writer, command: int, target: tuple[str, int]):
    writer.write(b"\x05" + bytes([command, 0]) + socks_address(*target))
    await writer.drain()
    header = await reader.readexactly(3)
    if header[0] != 5 or header[1] != 0:
        raise SocksError(f"SOCKS command {command} failed, reply {header.hex()}")
    return await read_socks_address(reader)


async def open_socks(url: str, command: int, target: tuple[str, int], timeout: float = 10):
    parsed = urlsplit(url)
    if parsed.scheme != "socks5" or not parsed.hostname:
        raise SocksError("use socks5://[user:password@]hostname:port")
    reader, writer = await asyncio.wait_for(asyncio.open_connection(parsed.hostname, parsed.port or 1080), timeout)
    try:
        await asyncio.wait_for(socks_handshake(reader, writer, url), timeout)
        bound = await asyncio.wait_for(socks_command(reader, writer, command, target), timeout)
        return reader, writer, bound
    except Exception:
        writer.close()
        await writer.wait_closed()
        raise


async def control_post(url: str, host: str, port: int, token: str, payload: dict, timeout: float = 10) -> dict:
    """POST JSON over SOCKS5 TCP CONNECT (never send UDP through VLESS control)."""
    import json
    reader, writer, _ = await open_socks(url, 1, (host, port), timeout)
    try:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = (
            "POST /control/mapping HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"X-Control-Token: {token}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        writer.write(headers + body); await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout)
        status_line = head.split(b"\r\n", 1)[0].decode("ascii", "replace")
        try:
            status = int(status_line.split()[1])
        except (ValueError, IndexError) as e:
            raise OSError("bad HTTP control response") from e
        content_len = None
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                content_len = int(line.split(b":", 1)[1].strip())
        if content_len is None or content_len > 16384:
            raise OSError("missing or excessive control response Content-Length")
        reply = json.loads((await asyncio.wait_for(reader.readexactly(content_len), timeout)).decode())
        if status != 200:
            raise OSError(f"control HTTP {status}: {reply.get('error', 'rejected')}")
        return reply
    finally:
        writer.close(); await writer.wait_closed()


class PacketProtocol(asyncio.DatagramProtocol):
    def __init__(self, callback: Callable[[bytes, tuple], None]):
        self.callback = callback

    def datagram_received(self, data, addr):
        self.callback(data, addr)

    def error_received(self, error):
        # Receive-side errors are surfaced by STUN timeout or QUIC reconnection.
        pass


class RawUDP:
    def __init__(self, bind_host: str, bind_port: int):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.transport = None
        self.callback = None

    async def open(self, callback):
        self.callback = callback
        self.transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: PacketProtocol(callback), local_addr=(self.bind_host, self.bind_port), family=socket.AF_INET
        )
        return self

    def send(self, data: bytes, peer: tuple[str, int]):
        if self.transport:
            self.transport.sendto(data, peer)

    def local_address(self):
        return self.transport.get_extra_info("sockname")

    async def close(self):
        if self.transport:
            self.transport.close(); self.transport = None


class SocksUDP:
    """B-to-A datagram transport via WARP SOCKS5 UDP ASSOCIATE."""

    def __init__(self, proxy_url: str):
        self.proxy_url = proxy_url
        self.reader = None
        self.writer = None
        self.raw = None
        self.relay = None
        self.peer_callback = None
        self.monitor = None
        self.closed = asyncio.Event()

    async def open(self, callback):
        self.peer_callback = callback
        self.reader, self.writer, relay = await open_socks(self.proxy_url, 3, ("0.0.0.0", 0))
        parsed = urlsplit(self.proxy_url)
        if relay[0] in ("0.0.0.0", "::"):
            relay = (parsed.hostname, relay[1])
        relay_ip = (await asyncio.get_running_loop().getaddrinfo(relay[0], relay[1], family=socket.AF_INET, type=socket.SOCK_DGRAM))[0][4]
        self.relay = relay_ip
        self.raw = await RawUDP("0.0.0.0", 0).open(self._receive)
        self.monitor = asyncio.create_task(self._watch_tcp())
        return self

    async def _watch_tcp(self):
        try:
            await self.reader.read(1)
        finally:
            self.closed.set()

    def _receive(self, data: bytes, src):
        if src != self.relay or len(data) < 10 or data[:3] != b"\x00\x00\x00":
            return
        try:
            remote, cursor = unpack_socks_address(data, 3)
        except (IndexError, ValueError, OSError):
            return
        self.peer_callback(data[cursor:], remote)

    def send(self, data: bytes, peer: tuple[str, int]):
        self.raw.send(b"\x00\x00\x00" + socks_address(*peer) + data, self.relay)

    async def close(self):
        if self.monitor:
            self.monitor.cancel()
            try:
                await self.monitor
            except asyncio.CancelledError:
                pass
        if self.raw:
            await self.raw.close()
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
        self.closed.set()


class StunClient:
    """STUN binding discovery on an existing RawUDP socket shared with QUIC."""

    def __init__(self, transport: RawUDP):
        self.transport = transport
        self.pending = {}

    def receive(self, packet: bytes) -> bool:
        if len(packet) < 20 or packet[:2] != b"\x01\x01" or packet[4:8] != struct.pack("!I", MAGIC):
            return False
        txid = packet[8:20]
        future = self.pending.get(txid)
        if future and not future.done():
            try:
                future.set_result(parse_stun(packet, txid))
            except ValueError as error:
                future.set_exception(error)
        return True

    async def discover(self, server: str, timeout: float = 3, retries: int = 3) -> tuple[str, int]:
        host, port = host_port(server, 3478)
        info = await asyncio.get_running_loop().getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_DGRAM)
        destination = info[0][4]
        for _ in range(retries):
            txid = os.urandom(12)
            message = struct.pack("!HHI", 1, 0, MAGIC) + txid
            future = asyncio.get_running_loop().create_future()
            self.pending[txid] = future
            self.transport.send(message, destination)
            try:
                return await asyncio.wait_for(future, timeout)
            except (asyncio.TimeoutError, ValueError):
                pass
            finally:
                self.pending.pop(txid, None)
        raise TimeoutError(f"STUN timeout from {server}")


def parse_stun(raw: bytes, expected_txid: bytes) -> tuple[str, int]:
    if len(raw) < 20 or raw[:2] != b"\x01\x01" or raw[4:8] != struct.pack("!I", MAGIC) or raw[8:20] != expected_txid:
        raise ValueError("invalid STUN response")
    length = struct.unpack_from("!H", raw, 2)[0]
    if len(raw) < 20 + length:
        raise ValueError("truncated STUN response")
    cursor = 20
    fallback = None
    while cursor + 4 <= 20 + length:
        kind, size = struct.unpack_from("!HH", raw, cursor)
        cursor += 4
        value = raw[cursor:cursor + size]
        cursor += size + (4 - size % 4) % 4
        if len(value) < 8 or value[1] != 1:
            continue
        port = struct.unpack_from("!H", value, 2)[0]
        address = value[4:8]
        if kind == 0x20:
            port ^= MAGIC >> 16
            address = bytes(a ^ b for a, b in zip(address, struct.pack("!I", MAGIC)))
            return socket.inet_ntoa(address), port
        if kind == 0x01:
            fallback = socket.inet_ntoa(address), port
    if fallback:
        return fallback
    raise ValueError("no mapped IPv4 address in STUN response")
