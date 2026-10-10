"""A-side UDP 39999: same-socket STUN discovery and opaque mKCP forwarding.

This is NOT a KCP implementation: Xray remains the only KCP/VLESS endpoint.
An independent loopback UDP socket per remote peer prevents reply misrouting.
"""

from __future__ import annotations

import asyncio
import os
import logging
import secrets
import socket
import struct
import time

from .config import parse_host_port

LOG = logging.getLogger("mytrn.udp")
STUN_MAGIC = 0x2112A442
MAX_PEERS = 12
PEER_IDLE_SECONDS = 180


def bound_udp_socket(address: tuple[str, int]) -> socket.socket:
    """Keep Windows A UDP sockets usable after an old WARP port disappears.

    By default Windows delivers ICMP Port Unreachable from a closed remote
    UDP port to the *next recvfrom* as WSAECONNRESET (10054). That can break
    the shared external STUN+mKCP socket when the B SOCKS relay is restarted.
    Disable this Winsock behaviour without masking ordinary UDP errors.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(address)
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            fn = ctypes.WinDLL("Ws2_32.dll").WSAIoctl
            fn.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p,
                           wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                           ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, ctypes.c_void_p]
            fn.restype = ctypes.c_int
            disabled = wintypes.DWORD(0)
            transferred = wintypes.DWORD(0)
            if fn(wintypes.HANDLE(sock.fileno()), 0x9800000C, ctypes.byref(disabled),
                  ctypes.sizeof(disabled), None, 0, ctypes.byref(transferred), None, None):
                raise OSError("cannot disable Windows UDP ICMP connection reset")
        sock.setblocking(False)
        return sock
    except Exception:
        sock.close()
        raise


def parse_stun(packet: bytes, transaction_id: bytes) -> tuple[str, int]:
    if (len(packet) < 20 or packet[:2] != b"\x01\x01" or
            packet[4:8] != struct.pack("!I", STUN_MAGIC) or
            packet[8:20] != transaction_id):
        raise ValueError("invalid STUN Binding Response")
    end = 20 + struct.unpack_from("!H", packet, 2)[0]
    if end > len(packet) or end > 2048:
        raise ValueError("invalid STUN response length")
    cursor = 20
    fallback = None
    while cursor + 4 <= end:
        kind, n = struct.unpack_from("!HH", packet, cursor)
        cursor += 4
        if cursor + n > end:
            raise ValueError("STUN attribute truncated")
        data = packet[cursor:cursor + n]
        cursor += n + (4 - n % 4) % 4
        if kind not in (0x20, 0x01) or n < 8 or data[1] != 1:
            continue
        target_port = struct.unpack_from("!H", data, 2)[0]
        raw_addr = data[4:8]
        if kind == 0x20:
            target_port ^= STUN_MAGIC >> 16
            raw_addr = bytes(a ^ b for a, b in zip(raw_addr, struct.pack("!I", STUN_MAGIC)))
            return socket.inet_ntoa(raw_addr), target_port
        fallback = socket.inet_ntoa(raw_addr), target_port
    if fallback:
        return fallback
    raise ValueError("STUN response does not contain mapped IPv4 address")


class Outside(asyncio.DatagramProtocol):
    def __init__(self, gate):
        self.gate = gate

    def datagram_received(self, data: bytes, sender: tuple):
        self.gate.receive_external(data, sender)

    def error_received(self, error):
        LOG.warning("outside UDP error: %s", error)


class Inside(asyncio.DatagramProtocol):
    def __init__(self, gate, peer):
        self.gate, self.peer = gate, peer

    def datagram_received(self, data: bytes, sender: tuple):
        if sender == self.gate.xray_address:
            self.gate.send_external(data, self.peer)


class UdpGateway:
    def __init__(self, bind: str, port: int, xray_port: int):
        self.bind = (bind, port)
        self.xray_address = ("127.0.0.1", xray_port)
        self.outside = None
        self.peers: dict[tuple, tuple[asyncio.DatagramTransport, float]] = {}
        self.opening: dict[tuple, list[bytes]] = {}
        self.open_tasks: set[asyncio.Task] = set()
        self.pending: dict[bytes, tuple[asyncio.Future, tuple]] = {}
        self.rx_external = 0
        self.rx_internal = 0
        self.last_external = None
        self._loop = asyncio.get_running_loop()

    async def start(self):
        self.outside, _ = await self._loop.create_datagram_endpoint(
            lambda: Outside(self), sock=bound_udp_socket(self.bind))
        LOG.info("A UDP %s → Xray mKCP %s", self.outside.get_extra_info("sockname"), self.xray_address)
        return self

    def receive_external(self, data: bytes, sender: tuple):
        if (len(data) >= 20 and data[4:8] == struct.pack("!I", STUN_MAGIC)
                and data[0] & 0xC0 == 0):
            transaction_id = data[8:20]
            pending = self.pending.get(transaction_id)
            if pending and sender == pending[1] and not pending[0].done():
                try:
                    pending[0].set_result(parse_stun(data, transaction_id))
                except ValueError as exc:
                    pending[0].set_exception(exc)
            # Never feed STUN control traffic to Xray.
            return
        self.rx_external += 1
        self.last_external = time.time()
        if sender in self.peers:
            transport, _ = self.peers[sender]
            self.peers[sender] = transport, time.monotonic()
            transport.sendto(data, self.xray_address)
        elif sender in self.opening:
            if len(self.opening[sender]) < 16:
                self.opening[sender].append(data)
        else:
            self.prune()
            if len(self.peers) + len(self.opening) >= MAX_PEERS:
                return
            self.opening[sender] = [data]
            task = asyncio.create_task(self._open_peer(sender))
            self.open_tasks.add(task)
            task.add_done_callback(self.open_tasks.discard)

    async def _open_peer(self, sender):
        try:
            transport, _ = await self._loop.create_datagram_endpoint(
                lambda: Inside(self, sender), sock=bound_udp_socket(("127.0.0.1", 0)))
            self.peers[sender] = (transport, time.monotonic())
            for packet in self.opening.get(sender, []):
                transport.sendto(packet, self.xray_address)
        except OSError as exc:
            LOG.warning("failed creating UDP relay for %s: %s", sender, exc)
        finally:
            self.opening.pop(sender, None)

    def send_external(self, packet: bytes, peer):
        if peer in self.peers and self.outside:
            self.rx_internal += 1
            self.outside.sendto(packet, peer)
            transport, _ = self.peers[peer]
            self.peers[peer] = transport, time.monotonic()

    def prune(self):
        cutoff = time.monotonic() - PEER_IDLE_SECONDS
        for addr, (transport, seen) in list(self.peers.items()):
            if seen < cutoff:
                transport.close()
                del self.peers[addr]

    async def stun(self, server: str, timeout=3.0) -> tuple[str, int]:
        host, port = parse_host_port(server)
        results = await self._loop.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_DGRAM)
        remote = results[0][4]
        txid = secrets.token_bytes(12)
        fut = self._loop.create_future()
        self.pending[txid] = fut, remote
        try:
            self.outside.sendto(struct.pack("!HHI", 1, 0, STUN_MAGIC) + txid, remote)
            return await asyncio.wait_for(fut, timeout)
        finally:
            self.pending.pop(txid, None)

    async def close(self):
        for task in list(self.open_tasks):
            task.cancel()
        if self.open_tasks:
            await asyncio.gather(*self.open_tasks, return_exceptions=True)
        for transport, _ in self.peers.values():
            transport.close()
        self.peers.clear()
        if self.outside:
            self.outside.close()
            self.outside = None
        for fut, _ in self.pending.values():
            if not fut.done():
                fut.cancel()
        self.pending.clear()

    def status(self):
        self.prune()
        return {"peers": len(self.peers), "rx_external": self.rx_external,
                "rx_internal": self.rx_internal, "last_external": self.last_external}
