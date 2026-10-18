"""PoC tests. Offline end-to-end with a real Xray binary is opt-in."""
from __future__ import annotations

import asyncio
import json
import os
import secrets
import socket
import struct
from pathlib import Path

import pytest

from poc.xray26327.demo import (MAGIC, UdpGate, configurations, generate,
                               local_selftest, public_endpoint, read_stun,
                               update_b_endpoint)


def test_generate_xray_reverse_config_and_tls(tmp_path: Path):
    root = tmp_path / "poc"
    generate(root, ("198.51.100.5", 55781), ("127.0.0.1", 40000),
             b_ca_path="/opt/mytrn-poc/a-cert.pem")
    a = json.loads((root / "a.json").read_text(encoding="utf-8"))
    b = json.loads((root / "b.json").read_text(encoding="utf-8"))
    assert a["inbounds"][1]["settings"]["clients"][0]["reverse"]["tag"] == "reverse-out"
    assert a["routing"]["rules"][0]["outboundTag"] == "reverse-out"
    outbound = b["outbounds"][0]
    assert outbound["settings"]["reverse"]["tag"] == "reverse-in"
    assert outbound["settings"]["address"] == "198.51.100.5"
    assert outbound["settings"]["port"] == 55781
    assert outbound["streamSettings"]["sockopt"]["dialerProxy"] == "warp-socks5"
    assert outbound["streamSettings"]["tlsSettings"]["allowInsecure"] is False
    assert outbound["streamSettings"]["tlsSettings"]["disableSystemRoot"] is True
    assert outbound["streamSettings"]["tlsSettings"]["certificates"][0]["certificateFile"] == "/opt/mytrn-poc/a-cert.pem"
    assert b["routing"]["rules"][0]["outboundTag"] == "b-internet"
    assert b["outbounds"][2]["protocol"] == "freedom"
    assert all(x["protocol"] != "freedom" for x in a["outbounds"]), "A must not bypass B"
    assert (root / "a-cert.pem").exists()
    assert (root / "a-key.pem").exists()
    with pytest.raises(FileExistsError):
        generate(root, ("198.51.100.6", 55781), ("127.0.0.1", 40000))
    update_b_endpoint(root / "b.json", ("203.0.113.2", 49999))
    updated = json.loads((root / "b.json").read_text(encoding="utf-8"))
    assert updated["outbounds"][0]["settings"]["address"] == "203.0.113.2"
    assert updated["outbounds"][0]["settings"]["port"] == 49999
    assert updated["outbounds"][0]["settings"]["id"] == outbound["settings"]["id"]
    assert updated["outbounds"][0]["streamSettings"] == outbound["streamSettings"]


def test_endpoint_parsing():
    assert public_endpoint("119.98.144.218:55781") == ("119.98.144.218", 55781)
    for bad in ("not-an-ip:1234", "1.2.3.4:0", "1.2.3.4:65536", "2001:db8::1:3478"):
        with pytest.raises((ValueError, IndexError)):
            public_endpoint(bad)


class FakeStun(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, packet: bytes, src):
        if packet[:2] != b"\x00\x01" or len(packet) != 20:
            return
        port = src[1] ^ (MAGIC >> 16)
        host = bytes(a ^ b for a, b in zip(socket.inet_aton(src[0]), struct.pack("!I", MAGIC)))
        attr = struct.pack("!HHBBH", 0x20, 8, 0, 1, port) + host
        reply = struct.pack("!HHI", 0x0101, 12, MAGIC) + packet[8:20] + attr
        self.transport.sendto(reply, src)


class EchoUDP(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.transport.sendto(b"ACK:" + data, addr)


class Receiver(asyncio.DatagramProtocol):
    def __init__(self, future):
        self.future = future

    def datagram_received(self, data, addr):
        if not self.future.done():
            self.future.set_result(data)


def test_stun_and_opaque_udp_share_one_external_socket():
    async def scenario():
        loop = asyncio.get_running_loop()
        backend, _ = await loop.create_datagram_endpoint(EchoUDP, local_addr=("127.0.0.1", 0))
        fake_stun, _ = await loop.create_datagram_endpoint(FakeStun, local_addr=("127.0.0.1", 0))
        backend_addr = backend.get_extra_info("sockname")
        gate = await UdpGate(("127.0.0.1", 0), backend_addr).start()
        callback = loop.create_future()
        client, _ = await loop.create_datagram_endpoint(lambda: Receiver(callback), local_addr=("127.0.0.1", 0))
        try:
            mapped = await gate.stun(fake_stun.get_extra_info("sockname"))
            assert mapped == gate.ingress.get_extra_info("sockname")
            assert gate.rx_backend == 0, "STUN should not be misrouted into Xray"
            client.sendto(b"opaque-mkcp-payload", mapped)
            assert await asyncio.wait_for(callback, 2) == b"ACK:opaque-mkcp-payload"
            assert gate.rx_external > 0 and gate.rx_backend > 0
        finally:
            client.close()
            await gate.close()
            fake_stun.close()
            backend.close()

    asyncio.run(scenario())


@pytest.mark.skipif(not os.environ.get("MYTRN_XRAY_BIN"),
                    reason="set MYTRN_XRAY_BIN to test actual Xray v26.3.27")
def test_real_xray_end_to_end_over_socks5_udp():
    asyncio.run(local_selftest(os.environ["MYTRN_XRAY_BIN"]))
