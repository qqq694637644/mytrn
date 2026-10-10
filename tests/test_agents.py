"""Python agent verification with real Xray v26.3.27 and mock CF/WARP SOCKS5.

Only transport infrastructure is mocked. VLESS reverse, mKCP, TLS and
TCP forwarding all run inside real Xray, never the deleted Python QUIC agent.
"""

import asyncio
import json
import os
import socket
import struct
import time
from pathlib import Path

import pytest
from aiohttp import ClientSession

from mytrn.app import Agent
from mytrn.config import (A_MKCP_DEFAULTS, create_a_identity, defaults, load_json,
                          mkcp_settings, save_json, validate, validate_a_certificate)
from mytrn.control import ControlServer
from mytrn.udp import STUN_MAGIC, UdpGateway, parse_stun
from mytrn.xray import make_a, make_b
from poc.xray26327.demo import proxy_http_request


def free_port(family=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, family) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def wait_until(check, timeout=25):
    async with asyncio.timeout(timeout):
        while not check():
            await asyncio.sleep(0.1)


class FakeStun(asyncio.DatagramProtocol):
    mapped_port = None
    response_enabled = True

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, sender):
        if not self.response_enabled or len(data) != 20 or data[:2] != b"\x00\x01":
            return
        mapped = self.mapped_port or sender[1]
        xor_ip = bytes(a ^ b for a, b in zip(socket.inet_aton(sender[0]), struct.pack("!I", STUN_MAGIC)))
        attr = struct.pack("!HHBBH", 0x20, 8, 0, 1, mapped ^ (STUN_MAGIC >> 16)) + xor_ip
        self.transport.sendto(struct.pack("!HHI", 0x0101, 12, STUN_MAGIC) + data[8:20] + attr, sender)


class FakeNatRelay(asyncio.DatagramProtocol):
    def __init__(self, a_address):
        self.a = a_address
        self.b = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, sender):
        if sender == self.a:
            if self.b:
                self.transport.sendto(data, self.b)
        else:
            self.b = sender
            self.transport.sendto(data, self.a)


class RelayUDP(asyncio.DatagramProtocol):
    def __init__(self, socks):
        self.socks = socks
        self.client = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, sender):
        if self.socks.drop_udp:
            return
        if data.startswith(b"\x00\x00\x00") and (self.client is None or sender == self.client):
            if len(data) < 10 or data[3] != 1:
                return
            target = socket.inet_ntoa(data[4:8]), struct.unpack("!H", data[8:10])[0]
            self.client = sender
            self.socks.udp_requests += 1
            self.transport.sendto(data[10:], target)
        elif self.client:
            self.transport.sendto(b"\x00\x00\x00\x01" + socket.inet_aton(sender[0]) +
                                  struct.pack("!H", sender[1]) + data, self.client)


class FakeSocks:
    def __init__(self):
        self.server = None
        self.port = 0
        self.relays = []
        self.udp_requests = 0
        self.tcp_connects = 0
        self.drop_udp = False

    async def start(self):
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def handle(self, reader, writer):
        udp_transport = None
        try:
            version, nmethods = await reader.readexactly(2)
            assert version == 5
            await reader.readexactly(nmethods)
            writer.write(b"\x05\x00"); await writer.drain()
            header = await reader.readexactly(4)
            assert header[:1] == b"\x05"
            cmd, atyp = header[1], header[3]
            if atyp == 1:
                target = socket.inet_ntoa(await reader.readexactly(4))
            elif atyp == 3:
                n = (await reader.readexactly(1))[0]
                target = (await reader.readexactly(n)).decode()
            else:
                raise ValueError("unsupported SOCKS address type in mock")
            target_port = struct.unpack("!H", await reader.readexactly(2))[0]
            if cmd == 1:
                self.tcp_connects += 1
                other_reader, other_writer = await asyncio.open_connection(target, target_port)
                writer.write(b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + b"\x00\x00")
                await writer.drain()

                async def forward(src, dst):
                    try:
                        while data := await src.read(8192):
                            dst.write(data)
                            await dst.drain()
                    finally:
                        dst.close()

                await asyncio.gather(forward(reader, other_writer), forward(other_reader, writer), return_exceptions=True)
            elif cmd == 3:
                udp_transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                    lambda: RelayUDP(self), local_addr=("127.0.0.1", 0))
                self.relays.append(udp_transport)
                relay = udp_transport.get_extra_info("sockname")
                writer.write(b"\x05\x00\x00\x01" + socket.inet_aton(relay[0]) +
                             struct.pack("!H", relay[1]))
                await writer.drain()
                await reader.read()
        except (ConnectionError, OSError, ValueError, asyncio.IncompleteReadError):
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
        self.server.close()
        await self.server.wait_closed()
        for transport in self.relays:
            transport.close()


def test_strict_config_and_certificates(tmp_path):
    a, b = defaults("a"), defaults("b")
    validate(a, "a"); validate(b, "b")
    a["obsolete_quic_option"] = True
    with pytest.raises(ValueError, match="unknown"):
        validate(a, "a")
    b["vless_uuid"] = "not-a-uuid"
    with pytest.raises(ValueError, match="vless_uuid"):
        validate(b, "b")
    cert, key, pem, fp = create_a_identity(tmp_path)
    assert cert.is_file() and key.is_file() and len(fp) == 64
    assert create_a_identity(tmp_path)[2:] == (pem, fp)
    assert validate_a_certificate(pem) == fp
    a = defaults("a")
    assert make_a(a, cert, key)["inbounds"][1]["settings"]["clients"][0]["reverse"]["tag"] == "reverse-out"
    b = defaults("b")
    wanted = make_b(b, {"ip": "127.0.0.1", "port": 1234}, cert)
    outbound = wanted["outbounds"][0]
    assert outbound["settings"]["reverse"]["tag"] == "reverse-in"
    assert outbound["streamSettings"]["sockopt"]["dialerProxy"] == "warp-socks5"
    assert outbound["streamSettings"]["tlsSettings"]["allowInsecure"] is False
    assert wanted["outbounds"][2]["protocol"] == "freedom"


def test_a_mkcp_defaults_migration_and_generated_xray_settings(tmp_path):
    a = defaults("a")
    # Original A config.a.json never had mKCP fields. It must keep the
    # same effective Xray behaviour and its existing identity and ports.
    original_uuid = a["vless_uuid"]
    original_token = a["control_token"]
    for key in A_MKCP_DEFAULTS:
        del a[key]
    validate(a, "a")
    assert {key: a[key] for key in A_MKCP_DEFAULTS} == A_MKCP_DEFAULTS
    assert a["vless_uuid"] == original_uuid and a["control_token"] == original_token
    assert a["udp_port"] == 39999
    assert mkcp_settings(a) == {"mtu": 1200}

    identity, private_key, _, _ = create_a_identity(tmp_path)
    initial = make_a(a, identity, private_key)
    assert initial["inbounds"][1]["streamSettings"]["kcpSettings"] == {"mtu": 1200}

    a.update({"mkcp_mtu": 1100, "mkcp_tti": 25, "mkcp_uplink_capacity": 10,
              "mkcp_downlink_capacity": 40, "mkcp_congestion": True,
              "mkcp_read_buffer_size": 4, "mkcp_write_buffer_size": 8})
    validate(a, "a")
    tuned = make_a(a, identity, private_key)["inbounds"][1]["streamSettings"]["kcpSettings"]
    assert tuned == {"mtu": 1100, "tti": 25, "uplinkCapacity": 10,
                     "downlinkCapacity": 40, "congestion": True,
                     "readBufferSize": 4, "writeBufferSize": 8}


@pytest.mark.parametrize("key,value", [
    ("mkcp_mtu", 575), ("mkcp_mtu", 1461),
    ("mkcp_tti", 9), ("mkcp_tti", 1001),
    ("mkcp_uplink_capacity", 0), ("mkcp_downlink_capacity", 1001),
    ("mkcp_read_buffer_size", 0), ("mkcp_write_buffer_size", 257),
    ("mkcp_congestion", 1), ("mkcp_mtu", True),
])
def test_a_mkcp_strict_bounds(key, value):
    a = defaults("a")
    a[key] = value
    with pytest.raises(ValueError, match="mkcp_"):
        validate(a, "a")


def test_a_mkcp_web_save_applies_without_restart_python_gateway(tmp_path):
    async def scenario():
        a = defaults("a")
        a["web_port"] = free_port()
        a["state_dir"] = str(tmp_path / "state")
        for key in A_MKCP_DEFAULTS:
            del a[key]  # Simulate an existing real-world A installation.
        path = tmp_path / "config.a.json"
        save_json(path, a)
        agent = Agent("a", path)
        await agent.ui.start()  # Only the Web listener, never the UDP gateway.
        headers = {"X-Admin-Token": a["admin_token"]}
        base = f"http://127.0.0.1:{a['web_port']}"
        try:
            async with ClientSession() as client:
                async with client.get(base + "/api/config", headers=headers) as response:
                    assert response.status == 200
                    current = await response.json()
                assert current["mkcp_mtu"] == 1200 and current["mkcp_tti"] == 50
                current["mkcp_tti"] = 25
                current["mkcp_write_buffer_size"] = 8
                async with client.post(base + "/api/config", json=current, headers=headers) as response:
                    assert response.status == 200
                    result = await response.json()
                    assert "无需重启" in result["message"]
                assert agent.config["mkcp_tti"] == 25
                assert not agent.restart_required
                assert load_json(path)["mkcp_write_buffer_size"] == 8
                # Reject bad tunings without changing the saved or live state.
                invalid = dict(current, mkcp_tti=1001)
                async with client.post(base + "/api/config", json=invalid, headers=headers) as response:
                    assert response.status == 400
                assert agent.config["mkcp_tti"] == 25
                assert load_json(path)["mkcp_tti"] == 25
                # Unrelated config changes preserve the original manual
                # Python Agent restart workflow.
                changed_other = dict(current, register_refresh=1200)
                async with client.post(base + "/api/config", json=changed_other, headers=headers) as response:
                    assert response.status == 200
                assert agent.restart_required
                assert agent.config["register_refresh"] == 1800
        finally:
            await agent.ui.close()

    asyncio.run(scenario())


def test_stun_binding_and_bad_packets():
    txid = os.urandom(12)
    address = socket.inet_aton("127.0.0.1")
    xor_addr = bytes(x ^ y for x, y in zip(address, struct.pack("!I", STUN_MAGIC)))
    attr = struct.pack("!HHBBH", 0x20, 8, 0, 1, 55555 ^ (STUN_MAGIC >> 16)) + xor_addr
    response = struct.pack("!HHI", 0x0101, len(attr), STUN_MAGIC) + txid + attr
    assert parse_stun(response, txid) == ("127.0.0.1", 55555)
    with pytest.raises(ValueError):
        parse_stun(response, b"bad" * 4)


def test_b_control_certificate_pin_and_token(tmp_path):
    async def scenario():
        config = defaults("b")
        config["control_port"] = free_port()
        server = ControlServer(config, tmp_path / "b-registration")
        cert_1 = create_a_identity(tmp_path / "A-1")[2]
        cert_2 = create_a_identity(tmp_path / "A-2")[2]
        await server.start()
        url = f"http://127.0.0.1:{config['control_port']}/control/mapping"
        req = {"node": "a", "ip": "127.0.0.1", "port": 39999, "certificate": cert_1}
        try:
            async with ClientSession() as client:
                async with client.post(url, json=req, headers={"X-Control-Token": "bad"}) as response:
                    assert response.status == 403
                headers = {"X-Control-Token": config["control_token"]}
                async with client.post(url, json=req, headers=headers) as response:
                    assert response.status == 200
                    assert (await response.json())["changed"] is True
                async with client.post(url, json=req, headers=headers) as response:
                    assert response.status == 200
                    assert (await response.json())["changed"] is False
                req["certificate"] = cert_2
                async with client.post(url, json=req, headers=headers) as response:
                    assert response.status == 409
            assert load_json(server.registration_path)["fingerprint"] == validate_a_certificate(cert_1)
        finally:
            await server.close()

    asyncio.run(scenario())


async def actual_integration(tmp_path, xray_bin):
    cfg_a, cfg_b = defaults("a"), defaults("b")
    cfg_b["control_token"] = cfg_a["control_token"]
    cfg_b["vless_uuid"] = cfg_a["vless_uuid"]
    fake_socks = await FakeSocks().start()
    loop = asyncio.get_running_loop()
    stun_transport, stun = await loop.create_datagram_endpoint(FakeStun, local_addr=("127.0.0.1", 0))
    nat_transport = None
    http_requests = []
    marker = os.urandom(12).hex().encode()

    async def http_handler(reader, writer):
        try:
            data = await reader.readuntil(b"\r\n\r\n")
            http_requests.append(data)
            output = marker + b"\n"
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(output)).encode() +
                         b"\r\nConnection: close\r\n\r\n" + output)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(http_handler, "127.0.0.1", 0)
    http_port = server.sockets[0].getsockname()[1]
    a_udp, a_backend, a_socks = free_port(socket.SOCK_DGRAM), free_port(socket.SOCK_DGRAM), free_port()
    control_port, web_a, web_b = free_port(), free_port(), free_port()
    cfg_a.update({
        "state_dir": str(tmp_path / "a-state"), "web_port": web_a,
        "xray_bin": str(xray_bin), "udp_bind": "127.0.0.1", "udp_port": a_udp,
        "xray_udp_port": a_backend, "socks_port": a_socks,
        "stun_servers": [f"127.0.0.1:{stun_transport.get_extra_info('sockname')[1]}"],
        "stun_interval": 1, "stun_confirm": 2,
        "control_socks5": f"socks5://127.0.0.1:{fake_socks.port}",
        "control_host": "127.0.0.1", "control_port": control_port,
        "register_retry": 1, "register_refresh": 300,
    })
    cfg_b.update({"xray_bin": str(xray_bin), "state_dir": str(tmp_path / "b-state"),
                  "web_port": web_b, "control_port": control_port,
                  "warp_socks5": f"socks5://127.0.0.1:{fake_socks.port}"})
    path_a, path_b = tmp_path / "config.a.json", tmp_path / "config.b.json"
    save_json(path_a, cfg_a); save_json(path_b, cfg_b)
    b = Agent("b", path_b)
    a = Agent("a", path_a)
    try:
        await b.start()
        await a.start()
        await wait_until(lambda: b.control.registration is not None and
                         a.xray is not None and a.xray.status()["running"] and
                         b.xray is not None and b.xray.status()["running"] and
                         a.gateway.rx_external > 0, timeout=35)
        async def check_browser():
            # Both Xray child processes may be running before reverse-in/out
            # finishes its initial handshake; retry the actual user request.
            try:
                async with asyncio.timeout(30):
                    while True:
                        try:
                            return await proxy_http_request(a_socks, http_port, marker)
                        except (OSError, asyncio.TimeoutError):
                            await asyncio.sleep(0.4)
            except TimeoutError:
                print("DIAG A", a.status(), "B", b.status(),
                      "MOCK SOCKS UDP", fake_socks.udp_requests,
                      "GATE PEERS", list(a.gateway.peers.keys()), flush=True)
                raise
        await check_browser()
        assert fake_socks.udp_requests > 0
        assert fake_socks.tcp_connects > 0  # A -> B control via SOCKS5 TCP CONNECT
        assert b.control.registration["port"] == a_udp
        assert a.gateway.status()["rx_internal"] > 0
        # Same endpoint refresh must not restart Xray.
        current_pid = b.xray.proc.pid
        async with ClientSession() as client:
            web_url = f"http://127.0.0.1:{web_b}"
            async with client.get(web_url + "/api/status") as response:
                assert response.status == 401
            async with client.get(web_url + "/api/status", headers={"X-Admin-Token": cfg_b["admin_token"]}) as response:
                assert response.status == 200
            async with client.get(web_url + "/api/config", headers={"X-Admin-Token": cfg_b["admin_token"]}) as response:
                amended = await response.json()
            amended["control_port"] = 77777
            async with client.post(web_url + "/api/config", headers={"X-Admin-Token": cfg_b["admin_token"]}, json=amended) as response:
                assert response.status == 400
            amended["control_port"] = cfg_b["control_port"]
            amended["web_bind"] = "127.0.0.1"
            async with client.post(web_url + "/api/config", headers={"X-Admin-Token": cfg_b["admin_token"]}, json=amended) as response:
                assert response.status == 200
            assert b.restart_required
            async with client.post(f"http://127.0.0.1:{control_port}/control/mapping",
                                   headers={"X-Control-Token": "wrong"}, json={}) as response:
                assert response.status == 403
            async with client.post(f"http://127.0.0.1:{control_port}/control/mapping",
                                   headers={"X-Control-Token": cfg_b["control_token"]},
                                   json={"node": "a", "ip": "127.0.0.1", "port": a_udp,
                                         "certificate": a.certificate}) as response:
                assert response.status == 200
                assert (await response.json())["changed"] is False
        await asyncio.sleep(4)
        assert b.xray.proc.pid == current_pid
        # B restart recovers the persisted endpoint+certificate independently.
        await b.stop()
        b = Agent("b", path_b)
        await b.start()
        await wait_until(lambda: b.xray is not None and b.xray.status()["running"], timeout=15)
        await asyncio.sleep(2)
        assert await check_browser()
        # Operator/service failure: supervisor must relaunch only its own Xray.
        old = b.xray.proc.pid
        b.xray.proc.terminate()
        await wait_until(lambda: b.xray.proc and b.xray.proc.pid != old and
                         b.xray.proc.returncode is None, timeout=15)
        await asyncio.sleep(2)
        assert await check_browser()
        # Endpoint change: a fake NAT gateway exposes a new reachable port.
        nat_transport, _ = await loop.create_datagram_endpoint(
            lambda: FakeNatRelay(("127.0.0.1", a_udp)), local_addr=("127.0.0.1", 0))
        new_endpoint = nat_transport.get_extra_info("sockname")[1]
        previous_pid = b.xray.proc.pid
        stun.mapped_port = new_endpoint
        await wait_until(lambda: a.endpoint == ("127.0.0.1", new_endpoint) and
                         b.control.registration["port"] == new_endpoint and
                         b.xray.proc is not None and
                         b.xray.proc.returncode is None and
                         b.xray.proc.pid != previous_pid, timeout=25)
        await asyncio.sleep(2)
        assert await check_browser()
        # STUN timeout should not reset a proven mapping nor restart Xray.
        previous_pid = b.xray.proc.pid
        stun.response_enabled = False
        await asyncio.sleep(5)
        assert a.endpoint == ("127.0.0.1", new_endpoint)
        assert b.xray.proc.pid == previous_pid
    finally:
        await a.stop()
        await b.stop()
        if nat_transport:
            nat_transport.close()
        stun_transport.close()
        await fake_socks.close()
        server.close(); await server.wait_closed()


@pytest.mark.skipif(not os.environ.get("MYTRN_XRAY_BIN"), reason="set MYTRN_XRAY_BIN for real v26.3.27")
def test_full_python_agents_real_xray_reverse_and_recovery(tmp_path):
    asyncio.run(actual_integration(tmp_path, os.environ["MYTRN_XRAY_BIN"]))
