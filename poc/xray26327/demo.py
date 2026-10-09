"""Xray-core v26.3.27: B-initiated VLESS reverse over mKCP/SOCKS5 UDP PoC.

Does not replace either existing x-ui or CF/VLESS/WARP services. Xray owns
SOCKS, VLESS reverse, TLS and KCP. Python only owns the UDP/STUN entry and
an offline SOCKS5 UDP relay used to test the same Xray configuration.

Commands:
  python demo.py generate --output _private --endpoint 1.2.3.4:55781
  python demo.py gate --config _private/a.json --xray /path/to/xray
  python demo.py selftest --xray /path/to/xray
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import json
import logging
import os
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

LOG = logging.getLogger("mytrn.poc")
MAGIC = 0x2112A442
SNI = "mytrn-a.test"
VERSION = "26.3.27"


def pair(raw: str) -> tuple[str, int]:
    host, sep, port = raw.rpartition(":")
    if not sep or not host or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError(f"invalid IPv4 host:port: {raw!r}")
    return host, int(port)


def public_endpoint(raw: str) -> tuple[str, int]:
    host, port = pair(raw)
    if ipaddress.ip_address(host).version != 4:
        raise ValueError("STUN endpoint must contain an IPv4 address")
    return host, port


def save_json(path: Path, obj: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)


def gen_certificate(out: Path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SNI)])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=5))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(SNI)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    (out / "a-cert.pem").write_bytes(pem)
    (out / "a-key.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    if os.name != "nt":
        (out / "a-cert.pem").chmod(0o600)
        (out / "a-key.pem").chmod(0o600)
    return cert.fingerprint(hashes.SHA256()).hex()


def configurations(endpoint: tuple[str, int], warp_socks: tuple[str, int],
                   socks_port: int, backend_port: int, user_id: str,
                   certificate_path: str, key_path: str,
                   b_ca_path: str) -> tuple[dict, dict]:
    # v26.3.27: VLESS inbound account.reverse creates the A-side dynamic
    # reverse-out outbound; VLESS outbound settings.reverse creates the B-side
    # reverse-in inbound. This is NOT legacy app.reverse portal/bridge.
    a_config = {
        "log": {"loglevel": "info"},
        "inbounds": [
            {"tag": "a-local-socks", "listen": "127.0.0.1", "port": socks_port,
             "protocol": "socks", "settings": {"auth": "noauth", "udp": False}},
            {"tag": "a-mkcp", "listen": "127.0.0.1", "port": backend_port,
             "protocol": "vless", "settings": {
                 "decryption": "none",
                 "clients": [{"id": user_id, "reverse": {"tag": "reverse-out"}}],
             },
             "streamSettings": {
                 "network": "kcp", "security": "tls",
                 "kcpSettings": {"mtu": 1200},
                 "tlsSettings": {"certificates": [
                     {"certificateFile": certificate_path, "keyFile": key_path}
                 ]},
             }},
        ],
        "outbounds": [{"tag": "deny", "protocol": "blackhole"}],
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "inboundTag": ["a-local-socks"], "outboundTag": "reverse-out"},
        ]},
    }
    b_config = {
        "log": {"loglevel": "info"},
        "inbounds": [],
        "outbounds": [
            {"tag": "b-reverse-dial", "protocol": "vless",
             "settings": {"address": endpoint[0], "port": endpoint[1],
                          "id": user_id, "encryption": "none",
                          "reverse": {"tag": "reverse-in"}},
             "streamSettings": {
                 "network": "kcp", "security": "tls",
                 "kcpSettings": {"mtu": 1200},
                 "tlsSettings": {
                     "serverName": SNI, "allowInsecure": False, "disableSystemRoot": True,
                     "certificates": [{"certificateFile": b_ca_path, "usage": "verify"}],
                 },
                 "sockopt": {"dialerProxy": "warp-socks5"},
             }},
            {"tag": "warp-socks5", "protocol": "socks", "settings": {
                "servers": [{"address": warp_socks[0], "port": warp_socks[1]}],
            }},
            {"tag": "b-internet", "protocol": "freedom", "settings": {}},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "inboundTag": ["reverse-in"], "outboundTag": "b-internet"},
        ]},
    }
    return a_config, b_config


def generate(out: Path, endpoint: tuple[str, int], warp: tuple[str, int],
             socks_port: int = 10808, backend_port: int = 40001,
             ingress_port: int = 39999, b_ca_path: str | None = None):
    if out.exists() and list(out.iterdir()):
        raise FileExistsError(f"refusing to overwrite populated folder: {out}")
    out.mkdir(parents=True, exist_ok=True)
    user_id = str(uuid.uuid4())
    fingerprint = gen_certificate(out)
    a, b = configurations(endpoint, warp, socks_port, backend_port, user_id,
                          str((out / "a-cert.pem").resolve()),
                          str((out / "a-key.pem").resolve()),
                          b_ca_path or str((out / "a-cert.pem").resolve()))
    save_json(out / "a.json", a)
    save_json(out / "b.json", b)
    save_json(out / "gate.json", {
        "listen": f"0.0.0.0:{ingress_port}", "backend": f"127.0.0.1:{backend_port}",
        "stun": "stun.cloudflare.com:3478", "stun_interval": 20,
    })
    print(f"Generated private PoC configs in {out}; A TLS SHA256={fingerprint}")
    print("A needs a.json, gate.json, a-cert.pem and a-key.pem.")
    print("B needs b.json and a-cert.pem. Do NOT upload the private key to B or GitHub.")


def update_b_endpoint(config_file: Path, endpoint: tuple[str, int]):
    config = json.loads(config_file.read_text(encoding="utf-8"))
    outbounds = [x for x in config["outbounds"] if x.get("tag") == "b-reverse-dial"]
    if len(outbounds) != 1 or outbounds[0].get("protocol") != "vless":
        raise ValueError("not a PoC B config: expected one b-reverse-dial VLESS outbound")
    outbounds[0]["settings"]["address"], outbounds[0]["settings"]["port"] = endpoint
    save_json(config_file, config)
    print(f"B new dial destination: {endpoint[0]}:{endpoint[1]} (restart B Xray to apply)")


def assert_xray_version(binary: str):
    result = subprocess.run([binary, "version"], capture_output=True, text=True, timeout=12, check=True)
    summary = result.stdout.splitlines()[0] if result.stdout else ""
    if VERSION not in summary:
        raise RuntimeError(f"PoC requires Xray {VERSION}, got: {summary}")
    return summary


def verify_xray_config(binary: str, config: Path):
    result = subprocess.run([binary, "run", "-test", "-config", config.name],
                            cwd=config.parent, capture_output=True, text=True, timeout=20)
    if result.returncode != 0:
        raise RuntimeError(f"Xray config check failed for {config.name}: {result.stderr[-3500:]} {result.stdout[-3500:]}")


class Ingress(asyncio.DatagramProtocol):
    def __init__(self, gate: "UdpGate"):
        self.gate = gate

    def connection_made(self, transport):
        self.gate.ingress = transport

    def datagram_received(self, data: bytes, addr):
        self.gate.rx_external += 1
        txid = data[8:20] if len(data) >= 20 else None
        future = self.gate.pending.get(txid)
        if (future and not future.done() and addr == self.gate.stun_source and
                len(data) >= 20 and data[0:2] == b"\x01\x01" and
                data[4:8] == struct.pack("!I", MAGIC)):
            try:
                future.set_result(read_stun(data, txid))
            except ValueError as exc:
                future.set_exception(exc)
            return
        # A single external mKCP peer for this experimental PoC. A new peer
        # may take over only after the old one goes idle.
        now = time.monotonic()
        if self.gate.peer and addr != self.gate.peer and now - self.gate.last_peer < 35:
            return
        self.gate.peer, self.gate.last_peer = addr, now
        self.gate.backend.sendto(data, self.gate.backend_addr)


class Backend(asyncio.DatagramProtocol):
    def __init__(self, gate: "UdpGate"):
        self.gate = gate

    def connection_made(self, transport):
        self.gate.backend = transport

    def datagram_received(self, data: bytes, addr):
        self.gate.rx_backend += 1
        if addr != self.gate.backend_addr or not self.gate.peer:
            return
        self.gate.ingress.sendto(data, self.gate.peer)


def read_stun(data: bytes, txid: bytes) -> tuple[str, int]:
    if (len(data) < 20 or data[:2] != b"\x01\x01" or
            data[4:8] != struct.pack("!I", MAGIC) or data[8:20] != txid):
        raise ValueError("invalid STUN binding response")
    end = 20 + struct.unpack_from("!H", data, 2)[0]
    if end > len(data):
        raise ValueError("truncated STUN")
    at = 20
    while at + 4 <= end:
        typ, size = struct.unpack_from("!HH", data, at)
        at += 4
        value = data[at:at + size]
        at += size + (4 - size % 4) % 4
        if size >= 8 and value[1] == 1 and typ in (0x20, 0x01):
            port = struct.unpack_from("!H", value, 2)[0]
            address = value[4:8]
            if typ == 0x20:
                port ^= MAGIC >> 16
                address = bytes(x ^ y for x, y in zip(address, struct.pack("!I", MAGIC)))
            return socket.inet_ntoa(address), port
    raise ValueError("no mapped IPv4 address in STUN")


class UdpGate:
    def __init__(self, listen: tuple[str, int], backend: tuple[str, int]):
        self.listen_addr = listen
        self.backend_addr = backend
        self.ingress = None
        self.backend = None
        self.peer = None
        self.last_peer = 0.0
        self.stun_source = None
        self.pending = {}
        self.rx_external = 0
        self.rx_backend = 0

    async def start(self):
        loop = asyncio.get_running_loop()
        self.ingress, _ = await loop.create_datagram_endpoint(
            lambda: Ingress(self), local_addr=self.listen_addr, family=socket.AF_INET)
        self.backend, _ = await loop.create_datagram_endpoint(
            lambda: Backend(self), local_addr=("127.0.0.1", 0), family=socket.AF_INET)
        print(f"A UDP ingress={self.ingress.get_extra_info('sockname')} -> Xray={self.backend_addr}", flush=True)
        return self

    async def stun(self, address: tuple[str, int], timeout=3):
        loop = asyncio.get_running_loop()
        server = (await loop.getaddrinfo(*address, type=socket.SOCK_DGRAM, family=socket.AF_INET))[0][4]
        self.stun_source = server
        txid = secrets.token_bytes(12)
        packet = struct.pack("!HHI", 1, 0, MAGIC) + txid
        fut = loop.create_future()
        self.pending[txid] = fut
        try:
            self.ingress.sendto(packet, server)
            return await asyncio.wait_for(fut, timeout)
        finally:
            self.pending.pop(txid, None)

    async def close(self):
        if self.backend:
            self.backend.close()
        if self.ingress:
            self.ingress.close()


class SocksUdpRelay(asyncio.DatagramProtocol):
    def __init__(self, metrics):
        self.transport = None
        self.client = None
        self.metrics = metrics

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, src):
        self.metrics["relay_datagrams"] += 1
        if data.startswith(b"\x00\x00\x00") and (self.client is None or src == self.client):
            if len(data) < 10:
                return
            atyp, at = data[3], 4
            if atyp == 1:
                target = socket.inet_ntop(socket.AF_INET, data[at:at + 4]); at += 4
            else:
                return
            port = struct.unpack_from("!H", data, at)[0]; at += 2
            self.client = src
            self.metrics["relay_outbound"] += 1
            self.transport.sendto(data[at:], (target, port))
        elif self.client:
            self.metrics["relay_inbound"] += 1
            # Encapsulate response; peer address must reflect the A endpoint.
            prefix = b"\x00\x00\x00\x01" + socket.inet_aton(src[0]) + struct.pack("!H", src[1])
            self.transport.sendto(prefix + data, self.client)


class MockSocksServer:
    """Minimal local-only SOCKS5 UDP ASSOCIATE stand-in for B's WARP proxy."""
    def __init__(self):
        self.server = None
        self.udp_transports = []
        self.port = 0
        self.metrics = {"tcp_associations": 0, "relay_datagrams": 0,
                        "relay_outbound": 0, "relay_inbound": 0, "tcp_errors": 0}

    async def start(self):
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def handle(self, reader, writer):
        udp = None
        try:
            header = await reader.readexactly(2)
            if header != b"\x05\x01":
                raise OSError("unexpected SOCKS auth")
            if await reader.readexactly(1) != b"\x00":
                raise OSError("unexpected SOCKS auth method")
            writer.write(b"\x05\x00"); await writer.drain()
            header = await reader.readexactly(4)
            if header != b"\x05\x03\x00\x01":
                raise OSError("expected SOCKS5 UDP ASSOCIATE")
            await reader.readexactly(6)
            loop = asyncio.get_running_loop()
            udp, _ = await loop.create_datagram_endpoint(
                lambda: SocksUdpRelay(self.metrics), local_addr=("127.0.0.1", 0))
            self.metrics["tcp_associations"] += 1
            self.udp_transports.append(udp)
            host, port = udp.get_extra_info("sockname")
            writer.write(b"\x05\x00\x00\x01" + socket.inet_aton(host) + struct.pack("!H", port))
            await writer.drain()
            await reader.read()
        except (OSError, asyncio.IncompleteReadError) as exc:
            self.metrics["tcp_errors"] += 1
            LOG.info("local SOCKS5 mock control close: %s", exc)
        finally:
            if udp:
                udp.close()
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    async def close(self):
        for udp in self.udp_transports:
            udp.close()
        if self.server:
            self.server.close()
            await self.server.wait_closed()


async def proxy_http_request(socks_port: int, target_port: int, token: bytes) -> bytes:
    reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", socks_port), 3)
    try:
        writer.write(b"\x05\x01\x00"); await writer.drain()
        if await asyncio.wait_for(reader.readexactly(2), 3) != b"\x05\x00":
            raise OSError("A SOCKS rejected noauth")
        # SOCKS5 ATYP=domain: B's freedom resolves the target name. A doesn't
        # perform local DNS lookups for this browser/application request.
        hostname = b"localhost"
        writer.write(b"\x05\x01\x00\x03" + bytes([len(hostname)]) + hostname + struct.pack("!H", target_port))
        await writer.drain()
        response = await asyncio.wait_for(reader.readexactly(4), 4)
        if response[:2] != b"\x05\x00":
            raise OSError(f"SOCKS CONNECT rejected: {response.hex()}")
        if response[3] == 1:
            await reader.readexactly(6)
        elif response[3] == 4:
            await reader.readexactly(18)
        elif response[3] == 3:
            length = (await reader.readexactly(1))[0]
            await reader.readexactly(length + 2)
        else:
            raise OSError("invalid SOCKS address type")
        writer.write(b"GET /proof HTTP/1.1\r\nHost: test.mytrn\r\nConnection: close\r\n\r\n")
        await writer.drain()
        response = await asyncio.wait_for(reader.read(16384), 7)
        if token not in response:
            raise OSError(f"end-to-end HTTP marker not received: {response[:300]!r}")
        return response
    finally:
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()


async def local_selftest(binary: str):
    print(assert_xray_version(binary), flush=True)
    with tempfile.TemporaryDirectory(prefix="mytrn-xray26327-") as td:
        root = Path(td)
        def freeport(type_):
            with socket.socket(socket.AF_INET, type_) as sock:
                sock.bind(("127.0.0.1", 0))
                return sock.getsockname()[1]
        gate_port = freeport(socket.SOCK_DGRAM)
        backend_port = freeport(socket.SOCK_DGRAM)
        socks_port = freeport(socket.SOCK_STREAM)
        marker = secrets.token_hex(12).encode("ascii")
        http_requests = []

        async def echo(reader, writer):
            try:
                request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
                http_requests.append(request)
                payload = marker + b"\n"
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(payload)).encode() +
                             b"\r\nConnection: close\r\n\r\n" + payload)
                await writer.drain()
            finally:
                writer.close()
                with contextlib.suppress(OSError):
                    await writer.wait_closed()

        http_server = await asyncio.start_server(echo, "127.0.0.1", 0)
        http_port = http_server.sockets[0].getsockname()[1]
        proxy = await MockSocksServer().start()
        gate = await UdpGate(("127.0.0.1", gate_port), ("127.0.0.1", backend_port)).start()
        processes = []
        output_logs = []
        try:
            (root / "a-cert.pem").parent.mkdir(parents=True, exist_ok=True)
            gen_certificate(root)
            a, b = configurations(("127.0.0.1", gate_port), ("127.0.0.1", proxy.port),
                                  socks_port, backend_port, str(uuid.uuid4()),
                                  str((root / "a-cert.pem").resolve()),
                                  str((root / "a-key.pem").resolve()),
                                  str((root / "a-cert.pem").resolve()))
            save_json(root / "a.json", a)
            save_json(root / "b.json", b)
            verify_xray_config(binary, root / "a.json")
            verify_xray_config(binary, root / "b.json")
            print("CONFIG_CHECK: PASS (Xray v26.3.27 A/B)", flush=True)
            for label in ("a", "b"):
                logfile = (root / f"xray-{label}.log").open("w+", encoding="utf-8")
                output_logs.append(logfile)
                process = subprocess.Popen([binary, "run", "-config", f"{label}.json"], cwd=root,
                                           stdout=logfile, stderr=subprocess.STDOUT)
                processes.append(process)
            deadline = time.monotonic() + float(os.getenv("MYTRN_POC_WAIT_SECONDS", "30"))
            error = ""
            while time.monotonic() < deadline:
                for proc in processes:
                    if proc.poll() is not None:
                        raise OSError(f"Xray exited with code {proc.returncode}")
                try:
                    response = await proxy_http_request(socks_port, http_port, marker)
                    if not http_requests:
                        raise OSError("HTTP server never received a request")
                    print(f"SOCKS_TO_B_FREEDOM: PASS ({len(response)} response bytes)", flush=True)
                    print(f"SOCKS5_UDP_ASSOCIATE: PASS ({len(proxy.udp_transports)} relays)", flush=True)
                    print("XRAY_VLESS_REVERSE_MKCP_OVER_SOCKS5_UDP: PASS", flush=True)
                    print("The B mock is local-only; real Cloudflare WARP/GFW route NOT verified.", flush=True)
                    return
                except (ConnectionError, OSError, asyncio.TimeoutError) as exc:
                    error = str(exc)
                    await asyncio.sleep(0.6)
            raise TimeoutError(f"Xray reverse connection or proxy failed: {error}")
        except Exception:
            print(f"DEBUG mock_socks={proxy.metrics} A_ingress_rx={gate.rx_external}"
                  f" A_backend_rx={gate.rx_backend}", file=sys.stderr)
            for label, logfile in zip(("a", "b"), output_logs):
                logfile.flush()
                logfile.seek(0)
                output = logfile.read()
                print(f"--- xray {label} log head ---\n{output[:3000]}", file=sys.stderr)
                print(f"--- xray {label} log tail ---\n{output[-2800:]}", file=sys.stderr)
            raise
        finally:
            for proc in processes:
                proc.terminate()
            for proc in processes:
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=4)
                if proc.poll() is None:
                    proc.kill(); proc.wait(timeout=4)
            for logfile in output_logs:
                logfile.close()
            await gate.close()
            await proxy.close()
            http_server.close()
            await http_server.wait_closed()


async def run_gateway(config: Path, binary: str | None, stun_override: str | None):
    cfg = json.loads(config.read_text(encoding="utf-8"))
    listen, backend = pair(cfg["listen"]), pair(cfg["backend"])
    gate = await UdpGate(listen, backend).start()
    proc = None
    try:
        if binary:
            assert_xray_version(binary)
            xray_config = config.parent / "a.json"
            verify_xray_config(binary, xray_config)
            proc = subprocess.Popen([binary, "run", "-config", xray_config.name], cwd=config.parent)
        stun_server = pair(stun_override or cfg.get("stun", "stun.cloudflare.com:3478"))
        interval = float(cfg.get("stun_interval", 20))
        if interval < 5:
            raise ValueError("stun_interval must be >=5")
        latest = None
        while True:
            try:
                candidate = await gate.stun(stun_server)
                if candidate != latest:
                    latest = candidate
                    print(f"STUN_MAPPING: {candidate[0]}:{candidate[1]}", flush=True)
                else:
                    print(f"STUN_ALIVE: {candidate[0]}:{candidate[1]}", flush=True)
            except (OSError, asyncio.TimeoutError, ValueError) as exc:
                LOG.warning("STUN failed: %s", exc)
            if proc and proc.poll() is not None:
                raise RuntimeError(f"A Xray exited unexpectedly: {proc.returncode}")
            await asyncio.sleep(interval)
    finally:
        await gate.close()
        if proc:
            proc.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=5)
            if proc.poll() is None:
                proc.kill(); proc.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description="Xray-core v26.3.27 mKCP + VLESS native reverse PoC")
    sub = parser.add_subparsers(dest="action", required=True)
    g = sub.add_parser("generate", help="Generate disposable, private A/B config pairs")
    g.add_argument("--output", type=Path, required=True)
    g.add_argument("--endpoint", required=True, help="A public IP:port as measured by same-socket STUN")
    g.add_argument("--warp-socks", default="127.0.0.1:40000")
    g.add_argument("--a-socks-port", type=int, default=10808)
    g.add_argument("--a-backend-port", type=int, default=40001)
    g.add_argument("--a-udp-port", type=int, default=39999)
    g.add_argument("--b-ca-path", help="Absolute path where a-cert.pem will be saved on B")
    update = sub.add_parser("set-endpoint", help="Update only the B dial target after A STUN mapping changes")
    update.add_argument("--config", type=Path, required=True, help="B's b.json")
    update.add_argument("--endpoint", required=True, help="Latest A public IP:port from same-socket STUN")
    gate = sub.add_parser("gate", help="Run A same-socket STUN/UDP ingress + optionally Xray")
    gate.add_argument("--config", type=Path, required=True, help="Generated gate.json")
    gate.add_argument("--xray", help="Path to the Xray v26.3.27 executable")
    gate.add_argument("--stun", help="Override STUN server host:port")
    local = sub.add_parser("selftest", help="Real Xray v26.3.27 A+B over local mock SOCKS5 UDP")
    local.add_argument("--xray", required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        if args.action == "generate":
            generate(args.output, public_endpoint(args.endpoint), pair(args.warp_socks),
                     args.a_socks_port, args.a_backend_port, args.a_udp_port,
                     args.b_ca_path)
        elif args.action == "set-endpoint":
            update_b_endpoint(args.config, public_endpoint(args.endpoint))
        elif args.action == "gate":
            asyncio.run(run_gateway(args.config.resolve(), str(Path(args.xray).resolve()) if args.xray else None, args.stun))
        else:
            asyncio.run(local_selftest(str(Path(args.xray).resolve())))
    except KeyboardInterrupt:
        print("Stopped", flush=True)
    except Exception as exc:
        print(f"PoC failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
