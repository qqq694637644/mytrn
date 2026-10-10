"""Xray-core v26.3.27 config generator and dedicated process supervisor.

Xray is the ONLY SOCKS/VLESS reverse/mKCP/TLS/TCP forwarding implementation.
These configurations were verified using the real v26.3.27 binary; do not
replace them with the legacy VMess portal/bridge protocol.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from collections import deque
from pathlib import Path
from urllib.parse import urlsplit

from .config import TLS_NAME, XRAY_VERSION, control_cf_ready, mkcp_settings, save_json

LOG = logging.getLogger("mytrn.xray")


def binary_path(value: str) -> str:
    result = shutil.which(value)
    if not result and Path(value).is_file():
        result = str(Path(value).resolve())
    if not result:
        raise FileNotFoundError(f"Xray binary not found: {value}")
    return str(Path(result).resolve())


def make_a(c: dict, certfile: Path, keyfile: Path) -> dict:
    # The same managed Xray process carries TWO strictly separated paths:
    # local user SOCKS5 -> native VLESS reverse/mKCP (B -> A transport), and
    # Python's own control SOCKS5 -> CF CDN/VLESS over TLS+WebSocket.
    # The UDP 39999/STUN gateway remains a separate Python socket; 40001 is
    # Xray's private mKCP UDP listener, not a second public NAT mapping.
    outbounds = [{"tag": "deny", "protocol": "blackhole"}]
    control_outbound = "deny"
    if control_cf_ready(c):
        outbounds.append({
            "tag": "cf-control", "protocol": "vless",
            "settings": {"address": c["control_cf_address"],
                         "port": c["control_cf_port"], "id": c["control_cf_uuid"],
                         "encryption": "none"},
            "streamSettings": {
                "network": "ws", "security": "tls",
                "tlsSettings": {"serverName": c["control_cf_server_name"],
                                "allowInsecure": False},
                "wsSettings": {"path": c["control_cf_ws_path"],
                               "headers": {"Host": c["control_cf_ws_host"]}},
            },
        })
        control_outbound = "cf-control"
    return {
        "log": {"loglevel": "info"},
        "inbounds": [
            {"tag": "a-local-socks", "listen": "127.0.0.1", "port": c["socks_port"],
             "protocol": "socks", "settings": {"auth": "noauth", "udp": False}},
            {"tag": "a-control-socks", "listen": "127.0.0.1", "port": c["control_proxy_port"],
             "protocol": "socks", "settings": {"auth": "noauth", "udp": False}},
            {"tag": "a-mkcp", "listen": "127.0.0.1", "port": c["xray_udp_port"],
             "protocol": "vless", "settings": {"decryption": "none", "clients": [
                 {"id": c["vless_uuid"], "reverse": {"tag": "reverse-out"}},
             ]},
             "streamSettings": {"network": "kcp", "security": "tls",
                                "kcpSettings": mkcp_settings(c),
                                "tlsSettings": {"certificates": [
                                    {"certificateFile": str(certfile.resolve()),
                                     "keyFile": str(keyfile.resolve())},
                                ]}}},
        ],
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "inboundTag": ["a-local-socks"], "outboundTag": "reverse-out"},
            {"type": "field", "inboundTag": ["a-control-socks"], "outboundTag": control_outbound},
        ]},
    }


def make_b(c: dict, record: dict, certfile: Path) -> dict:
    proxy = urlsplit(c["warp_socks5"])
    if proxy.username or proxy.password:
        socks_entry = {"address": proxy.hostname, "port": proxy.port or 1080,
                       "users": [{"user": proxy.username, "pass": proxy.password or ""}]}
    else:
        socks_entry = {"address": proxy.hostname, "port": proxy.port or 1080}
    return {
        "log": {"loglevel": "info"},
        "inbounds": [],
        "outbounds": [
            {"tag": "b-reverse-dial", "protocol": "vless", "settings": {
                "address": record["ip"], "port": record["port"],
                "id": c["vless_uuid"], "encryption": "none",
                "reverse": {"tag": "reverse-in"},
            }, "streamSettings": {
                "network": "kcp", "security": "tls", "kcpSettings": {"mtu": 1200},
                "tlsSettings": {
                    "serverName": TLS_NAME, "allowInsecure": False,
                    "disableSystemRoot": True,
                    "certificates": [{"certificateFile": str(certfile.resolve()),
                                      "usage": "verify"}],
                },
                "sockopt": {"dialerProxy": "warp-socks5"},
            }},
            {"tag": "warp-socks5", "protocol": "socks", "settings": {
                "servers": [socks_entry],
            }},
            {"tag": "b-internet", "protocol": "freedom", "settings": {}},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "inboundTag": ["reverse-in"], "outboundTag": "b-internet"},
        ]},
    }


class XrayProcess:
    """Supervise only our own child Xray; do not touch the existing x-ui daemon."""

    def __init__(self, binary: str, folder: Path, role: str):
        self.bin = binary_path(binary)
        self.folder = folder.resolve()
        self.role = role
        self.config_file = self.folder / f"xray-{role}.json"
        self.proc: asyncio.subprocess.Process | None = None
        self.reader_task: asyncio.Task | None = None
        self.last_error = None
        self.log_tail = deque(maxlen=100)
        self.desired_bytes = None
        self.lock = asyncio.Lock()
        self._checked_version = False

    async def _invoke(self, *args, timeout=15):
        proc = await asyncio.create_subprocess_exec(
            self.bin, *args, cwd=self.folder, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT)
        try:
            output, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise RuntimeError(f"Xray {' '.join(args[:2])} timeout")
        return proc.returncode, output.decode("utf-8", errors="replace")

    async def check_version(self):
        if not self._checked_version:
            rc, output = await self._invoke("version", timeout=10)
            if rc != 0 or XRAY_VERSION not in output.splitlines()[0]:
                raise RuntimeError(f"mytrn requires Xray {XRAY_VERSION}, got {output[:220]!r}")
            self._checked_version = True
            LOG.info("%s using %s", self.role.upper(), output.splitlines()[0])

    async def ensure(self, desired: dict):
        """Check candidate before replacing live config; restart only on changes/death."""
        self.folder.mkdir(parents=True, exist_ok=True)
        await self.check_version()
        text = json.dumps(desired, ensure_ascii=False, indent=2) + "\n"
        desired_data = text.encode("utf-8")
        async with self.lock:
            live = bool(self.proc and self.proc.returncode is None)
            if live and self.desired_bytes == desired_data:
                return False
            candidate = self.folder / f"xray-{self.role}.candidate.json"
            try:
                save_json(candidate, desired)
                rc, output = await self._invoke("run", "-test", "-config", candidate.name)
                if rc:
                    raise RuntimeError(f"Xray config rejected: {output[-1000:]}")
                # A failed validation leaves the running child untouched.
                await self._stop_unlocked()
                os.replace(candidate, self.config_file)
                self.proc = await asyncio.create_subprocess_exec(
                    self.bin, "run", "-config", self.config_file.name, cwd=self.folder,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
                self.reader_task = asyncio.create_task(self._drain(self.proc))
                await asyncio.sleep(0.4)
                if self.proc.returncode is not None:
                    raise RuntimeError(f"Xray exited at startup rc={self.proc.returncode}: {list(self.log_tail)[-5:]}")
                self.desired_bytes = desired_data
                self.last_error = None
                LOG.info("%s Xray active pid=%s", self.role.upper(), self.proc.pid)
                return True
            except Exception as exc:
                self.last_error = str(exc)
                raise
            finally:
                if candidate.exists():
                    candidate.unlink()

    async def _drain(self, proc):
        logfile = self.folder / f"xray-{self.role}.log"
        try:
            with logfile.open("a", encoding="utf-8") as f:
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    line = line.decode("utf-8", errors="replace").rstrip("\r\n")
                    self.log_tail.append(line)
                    f.write(line + "\n")
                    f.flush()
                await proc.wait()
                if proc.returncode:
                    self.last_error = f"Xray process exited rc={proc.returncode}"
        except asyncio.CancelledError:
            pass

    async def _stop_unlocked(self):
        proc = self.proc
        self.proc = None
        if proc and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
        if self.reader_task:
            await asyncio.gather(self.reader_task, return_exceptions=True)
            self.reader_task = None

    async def stop(self):
        async with self.lock:
            await self._stop_unlocked()

    def status(self):
        running = bool(self.proc and self.proc.returncode is None)
        return {"running": running, "pid": self.proc.pid if running else None,
                "last_error": self.last_error, "log_tail": list(self.log_tail)[-20:]}
