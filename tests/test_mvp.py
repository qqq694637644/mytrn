"""Offline real-socket integration tests; no Cloudflare or external network needed."""

import asyncio
import json
import os
import socket
import struct
from pathlib import Path

import pytest
from aiohttp import ClientSession

from mytrn.agent import Agent
from mytrn.config import certificate_fingerprint, defaults, ensure_a_certificate, load_json, save_json, validate_config
from mytrn.network import MAGIC, PacketProtocol, socks_address, unpack_socks_address, parse_stun
from mytrn.tunnel import stream_proof


def free_tcp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_config_validation_and_cert(tmp_path):
    a = defaults("a")
    b = defaults("b")
    validate_config(a, "a")
    validate_config(b, "b")
    a["targets"]["demo"]["port"] = 65536
    with pytest.raises(ValueError):
        validate_config(a, "a")
    certfile, keyfile, pem = ensure_a_certificate(tmp_path)
    assert certfile.exists() and keyfile.exists()
    assert len(certificate_fingerprint(pem)) == 64
    assert ensure_a_certificate(tmp_path)[2] == pem


def test_socks_addresses_and_stun():
    packet = socks_address("127.0.0.1", 8080)
    assert unpack_socks_address(packet) == (("127.0.0.1", 8080), len(packet))
    txid = os.urandom(12)
    ip = socket.inet_aton("127.0.0.1")
    xip = bytes(a ^ b for a, b in zip(ip, struct.pack("!I", MAGIC)))
    attr = struct.pack("!HHBBH", 0x20, 8, 0, 1, 50000 ^ (MAGIC >> 16)) + xip
    response = struct.pack("!HHI", 0x0101, len(attr), MAGIC) + txid + attr
    assert parse_stun(response, txid) == ("127.0.0.1", 50000)
    assert stream_proof("abc", "rule", 100, "xx") != stream_proof("abc", "rule", 101, "xx")


class MockStun(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        if len(data) != 20 or data[:2] != b"\x00\x01":
            return
        mapped_ip = socket.inet_aton(address[0])
        xip = bytes(a ^ b for a, b in zip(mapped_ip, struct.pack("!I", MAGIC)))
        attr = struct.pack("!HHBBH", 0x20, 8, 0, 1, address[1] ^ (MAGIC >> 16)) + xip
        response = struct.pack("!HHI", 0x0101, len(attr), MAGIC) + data[8:20] + attr
        self.transport.sendto(response, address)


class MockUDPRelay(asyncio.DatagramProtocol):
    def __init__(self):
        self.client = None
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, src):
        if data.startswith(b"\x00\x00\x00"):
            try:
                destination, cursor = unpack_socks_address(data, 3)
                # Only accept clients from loopback, and do not mistake encapsulated
                # replies from A for proxy client traffic.
                if self.client is None or src == self.client:
                    self.client = src
                    self.transport.sendto(data[cursor:], destination)
                    return
            except Exception:
                pass
        if self.client:
            self.transport.sendto(b"\x00\x00\x00" + socks_address(*src) + data, self.client)


class MockSocks:
    def __init__(self):
        self.server = None
        self.port = None
        self.relays = []

    async def start(self):
        self.server = await asyncio.start_server(self.client, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def client(self, reader, writer):
        udp_transport = None
        try:
            hello = await reader.readexactly(2)
            await reader.readexactly(hello[1])
            writer.write(b"\x05\x00"); await writer.drain()
            header = await reader.readexactly(4)
            atyp = header[3]
            if atyp == 1:
                address = socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
            elif atyp == 3:
                size = (await reader.readexactly(1))[0]
                address = (await reader.readexactly(size)).decode()
            else:
                raise ValueError("unsupported address")
            port = struct.unpack("!H", await reader.readexactly(2))[0]
            if header[1] == 1:  # SOCKS5 TCP CONNECT
                other_reader, other_writer = await asyncio.open_connection(address, port)
                writer.write(b"\x05\x00\x00" + socks_address("127.0.0.1", 0))
                await writer.drain()
                async def copy(r, w):
                    try:
                        while True:
                            data = await r.read(16384)
                            if not data:
                                break
                            w.write(data); await w.drain()
                    finally:
                        w.close()
                await asyncio.gather(copy(reader, other_writer), copy(other_reader, writer), return_exceptions=True)
            elif header[1] == 3:  # SOCKS5 UDP ASSOCIATE
                loop = asyncio.get_running_loop()
                udp_transport, relay = await loop.create_datagram_endpoint(MockUDPRelay, local_addr=("127.0.0.1", 0))
                self.relays.append(udp_transport)
                address, bound_port = udp_transport.get_extra_info("sockname")
                writer.write(b"\x05\x00\x00" + socks_address(address, bound_port))
                await writer.drain()
                await reader.read()
            else:
                writer.write(b"\x05\x07\x00" + socks_address("127.0.0.1", 0))
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            pass
        finally:
            if udp_transport:
                udp_transport.close()
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def close(self):
        for relay in self.relays:
            relay.close()
        self.server.close()
        await self.server.wait_closed()


async def echo_handler(reader, writer):
    try:
        while data := await reader.read(16384):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def integration(tmp_path: Path):
    echo = await asyncio.start_server(echo_handler, "127.0.0.1", 0)
    echo_port = echo.sockets[0].getsockname()[1]
    stun_transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(MockStun, local_addr=("127.0.0.1", 0))
    stun_port = stun_transport.get_extra_info("sockname")[1]
    socks = await MockSocks().start()

    cfg_a = defaults("a")
    cfg_b = defaults("b")
    cfg_b["control_token"] = cfg_a["control_token"]
    cfg_b["data_psk"] = cfg_a["data_psk"]
    control_port, local_udp_port, listen_port = free_tcp_port(), free_udp_port(), free_tcp_port()
    cfg_a.update({
        "state_dir": str(tmp_path / "state.a"), "web_port": free_tcp_port(),
        "local_udp_bind": "127.0.0.1", "local_udp_port": local_udp_port,
        "stun_servers": [f"127.0.0.1:{stun_port}"],
        "stun_check_interval": 2, "stun_keepalive_interval": 2,
        "control_retry_interval": 0.5, "control_socks5": f"socks5://127.0.0.1:{socks.port}",
        "control_host": "127.0.0.1", "control_port": control_port,
        "targets": {"echo": {"host": "127.0.0.1", "port": echo_port}},
    })
    cfg_b.update({
        "state_dir": str(tmp_path / "state.b"), "web_port": free_tcp_port(),
        "control_bind": "127.0.0.1", "control_port": control_port,
        "warp_socks5": f"socks5://127.0.0.1:{socks.port}",
        "ping_interval": 1, "reconnect_interval": 0.5,
        "allow_private_endpoint": True,
        "forwards": [{"id": "echo", "listen_host": "127.0.0.1", "listen_port": listen_port}],
    })
    path_a, path_b = tmp_path / "config.a.json", tmp_path / "config.b.json"
    save_json(path_a, cfg_a)
    save_json(path_b, cfg_b)
    agent_b = Agent("b", path_b, cfg_b)
    agent_a = Agent("a", path_a, cfg_a)
    try:
        await agent_b.start()
        await agent_a.start()
        for _ in range(240):
            if agent_b.status["state"] == "DATA_ACTIVE":
                break
            await asyncio.sleep(0.1)
        assert agent_b.status["state"] == "DATA_ACTIVE", (agent_a.status, agent_b.status)
        assert agent_a.status["endpoint"] == f"127.0.0.1:{local_udp_port}"
        assert agent_b.trusted["fingerprint"] == certificate_fingerprint(agent_a.cert_pem)
        reader, writer = await asyncio.open_connection("127.0.0.1", listen_port)
        payload = os.urandom(160_000)
        writer.write(payload)
        await writer.drain()
        writer.write_eof()
        received = await asyncio.wait_for(reader.read(), timeout=20)
        assert received == payload, (len(received), len(payload))
        writer.close(); await writer.wait_closed()
        # HTTP control API and Web UI have separate credentials.
        async with ClientSession() as client:
            base = f"http://127.0.0.1:{cfg_b['web_port']}"
            async with client.get(base + "/api/status") as response:
                assert response.status == 401
            headers = {"X-Admin-Token": cfg_b["admin_token"]}
            async with client.get(base + "/api/status", headers=headers) as response:
                assert response.status == 200
                assert (await response.json())["quic_connected"] is True
            async with client.get(base + "/api/config", headers=headers) as response:
                updated = await response.json()
            updated["ping_interval"] = 2
            async with client.post(base + "/api/config", json=updated, headers=headers) as response:
                assert response.status == 200
            assert load_json(path_b)["ping_interval"] == 2
            assert agent_b.status["config_pending_restart"] is True
            async with client.post(
                f"http://127.0.0.1:{control_port}/control/mapping",
                json={"ip": "127.0.0.1", "port": 39999, "certificate": agent_a.cert_pem},
                headers={"X-Control-Token": "incorrect"},
            ) as response:
                assert response.status == 403
            _, _, forged_pem = ensure_a_certificate(tmp_path / "forged")
            async with client.post(
                f"http://127.0.0.1:{control_port}/control/mapping",
                json={"ip": "127.0.0.1", "port": 39999, "certificate": forged_pem},
                headers={"X-Control-Token": cfg_b["control_token"]},
            ) as response:
                assert response.status == 409
            old_quic_session = agent_b.session
            async with client.post(
                f"http://127.0.0.1:{control_port}/control/mapping",
                json={"ip": "127.0.0.1", "port": local_udp_port, "certificate": agent_a.cert_pem},
                headers={"X-Control-Token": cfg_b["control_token"]},
            ) as response:
                assert response.status == 200
            await asyncio.sleep(0.2)
            assert agent_b.session is old_quic_session, "same-endpoint refresh must not drop QUIC"

        # No CF/VLESS status polling; only registration is required.
        assert agent_b.status["last_registration"] is not None
        assert agent_a.quic_server.session.connected.is_set()
        # B restart must use persisted endpoint and pinned certificate to reconnect.
        await agent_b.stop()
        agent_b = Agent("b", path_b, load_json(path_b))
        await agent_b.start()
        for _ in range(400):
            if agent_b.status["state"] == "DATA_ACTIVE":
                break
            await asyncio.sleep(0.1)
        assert agent_b.status["state"] == "DATA_ACTIVE", agent_b.status
        reader, writer = await asyncio.open_connection("127.0.0.1", listen_port)
        writer.write(b"after B restart"); await writer.drain()
        writer.write_eof()
        assert await asyncio.wait_for(reader.read(), timeout=20) == b"after B restart"
        writer.close(); await writer.wait_closed()
    finally:
        await agent_a.stop()
        await agent_b.stop()
        await socks.close()
        stun_transport.close()
        echo.close(); await echo.wait_closed()


def test_end_to_end_quic_over_socks_udp(tmp_path):
    asyncio.run(integration(tmp_path))
