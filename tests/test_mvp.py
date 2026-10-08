"""Offline real-socket integration tests; no Cloudflare or external network needed."""

import asyncio
import json
import os
import socket
import struct
from pathlib import Path

import pytest
from aiohttp import ClientSession
from aioquic.quic.connection import QuicConnection

from mytrn import tunnel as tunnel_module
from mytrn.agent import Agent
from mytrn.config import certificate_fingerprint, defaults, ensure_a_certificate, load_json, save_json, validate_config
from mytrn.network import MAGIC, PacketProtocol, socks_address, unpack_socks_address, parse_stun
from mytrn.tunnel import (AQuicServer, AStreamHandler, MAX_ACTIVE_STREAMS,
                          make_client_quic_config, make_server_quic_config,
                          pull_line, session_proof, stream_proof)


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
    c = defaults("b")
    c["allow_private_endpoint"] = True
    with pytest.raises(ValueError, match="unknown"):
        validate_config(c, "b")
    c = defaults("b")
    c["forwards"][0]["old_protocol"] = True
    with pytest.raises(ValueError, match="unknown"):
        validate_config(c, "b")
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
    assert session_proof("abc", 100, "xx") != session_proof("different", 100, "xx")


def test_pull_line_header_and_large_payload_same_event():
    async def scenario():
        queue = asyncio.Queue()
        large_data = os.urandom(4096)
        await queue.put((b"OK\n" + large_data, True))
        assert await pull_line(queue) == (b"OK", large_data, True)

        queue = asyncio.Queue()
        await queue.put((b"X" * 1024 + b"\n" + large_data, False))
        assert await pull_line(queue) == (b"X" * 1024, large_data, False)

        queue = asyncio.Queue()
        await queue.put((b"X" * 1025 + b"\n" + large_data, False))
        with pytest.raises(ValueError, match="header exceeds"):
            await pull_line(queue)

    asyncio.run(scenario())


def test_unauthenticated_quic_cannot_reserve_a_server(tmp_path, monkeypatch):
    monkeypatch.setattr(tunnel_module, "UNAUTHENTICATED_TIMEOUT", 0.25)

    async def scenario():
        certfile, keyfile, pem = ensure_a_certificate(tmp_path)
        server = AQuicServer(make_server_quic_config(str(certfile), str(keyfile)),
                             lambda _data, _address: None, AStreamHandler({}, "test" * 8))

        def send_initial(client_port):
            loop = asyncio.get_running_loop()
            client = QuicConnection(configuration=make_client_quic_config(pem))
            client.connect(("127.0.0.1", 39999), loop.time())
            packet, _ = client.datagrams_to_send(loop.time())[0]
            server.receive(packet, ("127.0.0.1", client_port))
            return server.session

        try:
            untrusted = send_initial(51001)
            assert untrusted is not None and not untrusted.authenticated.is_set()
            server.last_accept -= 2
            replacement = send_initial(51002)
            assert replacement is not untrusted, "an untrusted Initial must not lock out B"
            await asyncio.sleep(0.4)
            assert replacement.closed.is_set(), "unauthenticated sessions must expire"
            server.last_accept -= 2
            trusted = send_initial(51003)
            trusted.authenticated.set()  # emulate successful PSK validation
            server.last_accept -= 2
            assert send_initial(51004) is trusted, "authenticated active session must be protected"
        finally:
            await server.close()

    asyncio.run(scenario())


async def wait_until(predicate, timeout=8):
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.02)


class MockStun(asyncio.DatagramProtocol):
    mapping_port = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        if len(data) != 20 or data[:2] != b"\x00\x01":
            return
        mapped_ip = socket.inet_aton(address[0])
        xip = bytes(a ^ b for a, b in zip(mapped_ip, struct.pack("!I", MAGIC)))
        advertised_port = self.mapping_port if self.mapping_port is not None else address[1]
        attr = struct.pack("!HHBBH", 0x20, 8, 0, 1, advertised_port ^ (MAGIC >> 16)) + xip
        response = struct.pack("!HHI", 0x0101, len(attr), MAGIC) + data[8:20] + attr
        self.transport.sendto(response, address)


class MockNatMapping(asyncio.DatagramProtocol):
    """Alternate public endpoint, forwarding B UDP packets to A local UDP."""

    def __init__(self, a_address):
        self.a_address = a_address
        self.b_address = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, src):
        if src == self.a_address:
            if self.b_address:
                self.transport.sendto(data, self.b_address)
        else:
            self.b_address = src
            self.transport.sendto(data, self.a_address)


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


async def integration(tmp_path: Path, *, wrong_data_psk=False):
    echo = await asyncio.start_server(echo_handler, "127.0.0.1", 0)
    echo_port = echo.sockets[0].getsockname()[1]
    stun_transport, stun_server = await asyncio.get_running_loop().create_datagram_endpoint(MockStun, local_addr=("127.0.0.1", 0))
    stun_port = stun_transport.get_extra_info("sockname")[1]
    socks = await MockSocks().start()

    cfg_a = defaults("a")
    cfg_b = defaults("b")
    cfg_b["control_token"] = cfg_a["control_token"]
    cfg_b["data_psk"] = cfg_a["data_psk"]
    control_port, local_udp_port, listen_port = free_tcp_port(), free_udp_port(), free_tcp_port()
    offline_target_port, offline_listen_port = free_tcp_port(), free_tcp_port()
    cfg_a.update({
        "state_dir": str(tmp_path / "state.a"), "web_port": free_tcp_port(),
        "local_udp_bind": "127.0.0.1", "local_udp_port": local_udp_port,
        "stun_servers": [f"127.0.0.1:{stun_port}"],
        "stun_check_interval": 2, "stun_keepalive_interval": 2,
        "control_retry_interval": 0.5, "control_socks5": f"socks5://127.0.0.1:{socks.port}",
        "control_host": "127.0.0.1", "control_port": control_port,
        "targets": {"echo": {"host": "127.0.0.1", "port": echo_port},
                    "offline": {"host": "127.0.0.1", "port": offline_target_port}},
    })
    cfg_b.update({
        "state_dir": str(tmp_path / "state.b"), "web_port": free_tcp_port(),
        "control_bind": "127.0.0.1", "control_port": control_port,
        "warp_socks5": f"socks5://127.0.0.1:{socks.port}",
        "ping_interval": 1, "reconnect_interval": 0.5,
        "forwards": [{"id": "echo", "listen_host": "127.0.0.1", "listen_port": listen_port},
                     {"id": "offline", "listen_host": "127.0.0.1", "listen_port": offline_listen_port}],
    })
    if wrong_data_psk:
        cfg_b["data_psk"] = "wrong-data-psk-for-negative-case-123456789"
    path_a, path_b = tmp_path / "config.a.json", tmp_path / "config.b.json"
    save_json(path_a, cfg_a)
    save_json(path_b, cfg_b)
    agent_b = Agent("b", path_b, cfg_b)
    agent_a = Agent("a", path_a, cfg_a)
    recovered_echo = None
    nat_transport = None
    try:
        await agent_b.start()
        await agent_a.start()
        if wrong_data_psk:
            await wait_until(lambda: agent_b.status["last_error"] is not None, timeout=8)
            assert agent_b.status["state"] != "DATA_ACTIVE", agent_b.status
            assert not (agent_b.session and agent_b.session.authenticated.is_set())
            reader, writer = await asyncio.open_connection("127.0.0.1", listen_port)
            writer.write_eof()
            assert await asyncio.wait_for(reader.read(), timeout=4) == b""
            writer.close(); await writer.wait_closed()
            return
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
        # Simulate A's upper-layer NAT mapping moving to another public port.
        # The alternate UDP relay forwards B packets to the same A local socket.
        nat_transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: MockNatMapping(("127.0.0.1", local_udp_port)),
            local_addr=("127.0.0.1", 0),
        )
        new_mapping_port = nat_transport.get_extra_info("sockname")[1]
        original_session = agent_b.session
        stun_server.mapping_port = new_mapping_port
        await wait_until(lambda: agent_b.status["endpoint"] == f"127.0.0.1:{new_mapping_port}", timeout=12)
        await wait_until(lambda: agent_b.status["state"] == "DATA_ACTIVE" and
                         agent_b.session is not None and agent_b.session is not original_session and
                         agent_b.session.peer == ("127.0.0.1", new_mapping_port) and
                         agent_b.session.authenticated.is_set() and
                         agent_a.quic_server.session.authenticated.is_set(), timeout=25)
        reader, writer = await asyncio.open_connection("127.0.0.1", listen_port)
        writer.write(b"after NAT endpoint changed"); await writer.drain(); writer.write_eof()
        assert await asyncio.wait_for(reader.read(), timeout=15) == b"after NAT endpoint changed"
        writer.close(); await writer.wait_closed()
        await wait_until(lambda: not agent_b.session.streams and
                         not agent_a.quic_server.session.streams, timeout=4)

        # Review P1: short TCP connections must free streams immediately, not
        # 60 seconds or QUIC-session-close later. 100 > MAX_ACTIVE_STREAMS.
        for index in range(100):
            reader, writer = await asyncio.open_connection("127.0.0.1", listen_port)
            packet = f"short-{index}".encode()
            writer.write(packet); await writer.drain()
            writer.write_eof()
            assert await asyncio.wait_for(reader.read(), timeout=5) == packet, index
            writer.close(); await writer.wait_closed()
            if index % 10 == 0:
                assert len(agent_b.session.streams) < MAX_ACTIVE_STREAMS
                assert len(agent_a.quic_server.session.streams) < MAX_ACTIVE_STREAMS
        await wait_until(lambda: not agent_b.session.streams and
                         not agent_a.quic_server.session.streams, timeout=4)

        # Review P1: 40 failing A TCP targets must not consume 32 stream slots.
        for index in range(40):
            reader, writer = await asyncio.open_connection("127.0.0.1", offline_listen_port)
            writer.write_eof()
            assert await asyncio.wait_for(reader.read(), timeout=5) == b"", index
            writer.close(); await writer.wait_closed()
        await wait_until(lambda: not agent_b.session.streams and
                         not agent_a.quic_server.session.streams, timeout=4)

        recovered_echo = await asyncio.start_server(echo_handler, "127.0.0.1", offline_target_port)
        reader, writer = await asyncio.open_connection("127.0.0.1", offline_listen_port)
        writer.write(b"service is back"); await writer.drain(); writer.write_eof()
        assert await asyncio.wait_for(reader.read(), timeout=8) == b"service is back"
        writer.close(); await writer.wait_closed()
        await wait_until(lambda: not agent_b.session.streams and
                         not agent_a.quic_server.session.streams, timeout=4)
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
        # A WARP SOCKS5 UDP relay may silently stop receiving while its TCP
        # control association remains open. QUIC PING timeout must reconnect.
        session_before_relay_failure = agent_b.session
        socks.relays[-1].close()
        await wait_until(lambda: agent_b.session is not None and
                         agent_b.session is not session_before_relay_failure and
                         agent_b.session.authenticated.is_set() and
                         agent_b.status["state"] == "DATA_ACTIVE", timeout=40)
        reader, writer = await asyncio.open_connection("127.0.0.1", listen_port)
        writer.write(b"after WARP relay reconnect"); await writer.drain(); writer.write_eof()
        assert await asyncio.wait_for(reader.read(), timeout=15) == b"after WARP relay reconnect"
        writer.close(); await writer.wait_closed()
    finally:
        await agent_a.stop()
        await agent_b.stop()
        await socks.close()
        stun_transport.close()
        echo.close(); await echo.wait_closed()
        if recovered_echo:
            recovered_echo.close(); await recovered_echo.wait_closed()
        if nat_transport:
            nat_transport.close()


def test_end_to_end_quic_over_socks_udp(tmp_path):
    asyncio.run(integration(tmp_path))


def test_mismatched_data_psk_never_becomes_active(tmp_path):
    asyncio.run(integration(tmp_path, wrong_data_psk=True))
