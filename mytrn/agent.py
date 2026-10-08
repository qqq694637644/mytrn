"""A/B agent orchestration and local Web UI."""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import logging
import time
from pathlib import Path

from aiohttp import web
from aioquic.quic.connection import QuicConnection

from .config import (certificate_fingerprint, ensure_a_certificate, load_json,
                     save_json, state_path, validate_config)
from .network import RawUDP, SocksUDP, StunClient, control_post
from .tunnel import (AQuicServer, AStreamHandler, QuicSession, b_forward_tcp,
                     authenticate_client, make_client_quic_config, make_server_quic_config)

LOG = logging.getLogger("mytrn.agent")

WEB_HTML = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>mytrn · Web 配置</title><style>
body{font:15px system-ui,sans-serif;max-width:940px;margin:35px auto;padding:0 18px;background:#f6f7fa;color:#182237}
h1{margin-bottom:0}small{color:#64748b}main{background:white;padding:24px;border-radius:12px;border:1px solid #e0e7ef}
textarea{font:13px ui-monospace,monospace;width:100%;box-sizing:border-box;height:360px;padding:14px;border:1px solid #cbd5e1;border-radius:6px}
input{padding:9px;font:inherit;width:320px;max-width:90%}button{padding:9px 17px;margin:8px 5px 8px 0;cursor:pointer}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f5f9;padding:14px;border-radius:6px}
</style></head><body><main><h1>mytrn</h1><small>B 经 WARP SOCKS5 主动连接 A · 本机管理界面</small>
<p>Admin token（初始化时终端输出，仅保存在此浏览器）：</p><input id="token" type="password" autocomplete="off">
<button onclick="load()">读取状态和配置</button><button onclick="save()">保存配置</button>
<p><b>状态</b></p><pre id="status">尚未连接</pre>
<p><b>配置 (JSON)</b></p><textarea id="config" spellcheck="false"></textarea>
<p><small>保存后需重启 agent 才会生效。真实 config、证书私钥和 token 不提交 Git。</small></p>
<pre id="message"></pre></main><script>
const token=document.getElementById('token'),msg=document.getElementById('message');
token.value=localStorage.getItem('mytrn-admin')||'';
async function api(path,method='GET',body){localStorage.setItem('mytrn-admin',token.value);
 const res=await fetch(path,{method,headers:{'X-Admin-Token':token.value,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});
 const out=await res.json();if(!res.ok)throw Error(out.error||'HTTP '+res.status);return out;}
async function load(){try{const s=await api('/api/status');document.getElementById('status').textContent=JSON.stringify(s,null,2);
 const c=await api('/api/config');document.getElementById('config').value=JSON.stringify(c,null,2);msg.textContent='读取成功';}
 catch(e){msg.textContent=e.message;}}
async function save(){try{const data=JSON.parse(document.getElementById('config').value);
 const out=await api('/api/config','POST',data);msg.textContent=out.message;}
 catch(e){msg.textContent=e.message;}}
</script></body></html>"""


class Agent:
    def __init__(self, role: str, config_path: Path, config: dict):
        validate_config(config, role)
        self.role = role
        self.config_path = config_path.resolve()
        self.config = config
        self.state_dir = state_path(self.config_path, config)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.status = {
            "role": role, "state": "STARTING", "last_error": None,
            "endpoint": None, "last_registration": None, "quic_connected": False,
            "last_stun": None, "config_pending_restart": False,
        }
        self.runner = None
        self.control_runner = None
        self.tasks: list[asyncio.Task] = []
        self.shutdown = asyncio.Event()
        self.udp = None
        self.stun = None
        self.quic_server = None
        self.session = None
        self.trusted = None
        self.peer_changed = asyncio.Event()
        self.locals = []
        self._pending_endpoint = None
        self._pending_count = 0

    def _authorized(self, request):
        supplied = request.headers.get("X-Admin-Token", "")
        return hmac.compare_digest(supplied, self.config["admin_token"])

    async def _web_index(self, request):
        return web.Response(text=WEB_HTML, content_type="text/html", headers={"Cache-Control": "no-store"})

    async def _web_status(self, request):
        if not self._authorized(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        status = dict(self.status)
        if self.role == "a" and self.quic_server:
            session = self.quic_server.session
            status["quic_connected"] = bool(session and session.authenticated.is_set() and not session.closed.is_set())
            status["last_data_packet"] = round(session.last_packet_at, 1) if session else None
        if self.role == "b" and self.session:
            status["quic_connected"] = self.session.authenticated.is_set() and not self.session.closed.is_set()
            status["last_pong_age_seconds"] = round(time.monotonic() - self.session.last_pong_at, 1)
        return web.json_response(status)

    async def _web_config(self, request):
        if not self._authorized(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        return web.json_response(load_json(self.config_path), headers={"Cache-Control": "no-store"})

    async def _web_save(self, request):
        if not self._authorized(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        try:
            new_config = await request.json()
            if not isinstance(new_config, dict):
                raise ValueError("config must be a JSON object")
            # The active admin token remains valid until the daemon restarts.
            validate_config(new_config, self.role)
            save_json(self.config_path, new_config)
            self.status["config_pending_restart"] = True
            return web.json_response({"ok": True, "message": "保存成功；请重启 agent 以应用配置。"})
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return web.json_response({"error": str(exc)}, status=400)

    async def _start_web(self):
        app = web.Application(client_max_size=256 * 1024)
        app.router.add_get("/", self._web_index)
        app.router.add_get("/api/status", self._web_status)
        app.router.add_get("/api/config", self._web_config)
        app.router.add_post("/api/config", self._web_save)
        self.runner = web.AppRunner(app, access_log=None)
        await self.runner.setup()
        site = web.TCPSite(self.runner, self.config["web_bind"], self.config["web_port"])
        await site.start()
        LOG.info("%s local Web UI http://%s:%s", self.role.upper(), self.config["web_bind"], self.config["web_port"])

    async def start(self):
        await self._start_web()
        if self.role == "a":
            await self._start_a()
        else:
            await self._start_b()
        self.status["state"] = "RUNNING"

    async def _start_a(self):
        certfile, keyfile, self.cert_pem = ensure_a_certificate(self.state_dir)
        def datagram_received(raw, src):
            if self.stun and self.stun.receive(raw):
                return
            if self.quic_server:
                self.quic_server.receive(raw, src)
        c = self.config
        self.udp = await RawUDP(c["local_udp_bind"], c["local_udp_port"]).open(datagram_received)
        self.stun = StunClient(self.udp)
        self.quic_server = AQuicServer(make_server_quic_config(str(certfile), str(keyfile)),
                                       self.udp.send, AStreamHandler(c["targets"], c["data_psk"]))
        self.tasks.append(asyncio.create_task(self._a_maintenance(), name="a-maintenance"))
        LOG.info("A UDP and QUIC listening on %s", self.udp.local_address())

    async def _stun_once(self):
        last_error = None
        for server in self.config["stun_servers"]:
            try:
                return await self.stun.discover(server, timeout=2.0, retries=2)
            except (OSError, asyncio.TimeoutError) as exc:
                last_error = str(exc)
        raise TimeoutError(last_error or "all STUN servers failed")

    async def _a_maintenance(self):
        c = self.config
        endpoint = None
        next_stun = 0.0
        last_registration = 0.0
        next_registration_retry = 0.0
        registration_required = True
        while not self.shutdown.is_set():
            now = time.monotonic()
            if now >= next_stun:
                try:
                    observed = await self._stun_once()
                    self.status["last_stun"] = time.time()
                    if endpoint is None:
                        endpoint = observed
                        registration_required = True
                    elif observed != endpoint:
                        if observed == self._pending_endpoint:
                            self._pending_count += 1
                        else:
                            self._pending_endpoint = observed
                            self._pending_count = 1
                        if self._pending_count >= c["endpoint_change_confirm"]:
                            LOG.warning("A endpoint changed: %s -> %s", endpoint, observed)
                            endpoint = observed
                            registration_required = True
                            self._pending_endpoint = None
                            self._pending_count = 0
                            # Old QUIC path no longer represents the mapped
                            # address. Make room for the B-initiated reconnect.
                            if self.quic_server and self.quic_server.session:
                                await self.quic_server.session.close()
                    else:
                        self._pending_endpoint = None
                        self._pending_count = 0
                    self.status["endpoint"] = f"{endpoint[0]}:{endpoint[1]}"
                except Exception as exc:
                    self.status["last_error"] = f"STUN: {exc}"
                    LOG.warning("A STUN discovery failed: %s", exc)
                next_stun = time.monotonic() + min(c["stun_check_interval"], c["stun_keepalive_interval"])
            now = time.monotonic()
            no_b_packets = (self.quic_server is None or not self.quic_server.session or
                            now - self.quic_server.session.last_packet_at > max(60, 3 * c["stun_check_interval"]))
            if endpoint and (registration_required or now - last_registration > c["register_refresh_interval"] or
                             (no_b_packets and now - last_registration > 60)) and now >= next_registration_retry:
                try:
                    await control_post(c["control_socks5"], c["control_host"], c["control_port"],
                                       c["control_token"], {
                                           "node": "a", "ip": endpoint[0], "port": endpoint[1],
                                           "certificate": self.cert_pem,
                                       })
                    last_registration = time.monotonic()
                    self.status["last_registration"] = time.time()
                    self.status["last_error"] = None
                    registration_required = False
                    LOG.info("A registered endpoint %s with B through SOCKS5/VLESS control", endpoint)
                except Exception as exc:
                    self.status["last_error"] = f"Control register: {exc}"
                    LOG.warning("A control registration failed: %s", exc)
                    registration_required = True
                next_registration_retry = time.monotonic() + c["control_retry_interval"]
            try:
                await asyncio.wait_for(self.shutdown.wait(), timeout=1)
            except asyncio.TimeoutError:
                pass

    async def _control_mapping(self, request):
        token = request.headers.get("X-Control-Token", "")
        if not hmac.compare_digest(token, self.config["control_token"]):
            return web.json_response({"error": "unauthorized"}, status=403)
        try:
            value = await request.json()
            ip = ipaddress.ip_address(value["ip"])
            port = value["port"]
            if ip.version != 4 or ip.is_unspecified or ip.is_multicast:
                raise ValueError("expected valid unicast IPv4 endpoint")
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError("invalid port")
            pem = value["certificate"]
            if type(pem) is not str or len(pem) > 8192:
                raise ValueError("invalid certificate")
            fingerprint = certificate_fingerprint(pem)
            if self.trusted and fingerprint != self.trusted["fingerprint"]:
                return web.json_response({"error": "A TLS certificate changed; manual re-trust required"}, status=409)
            endpoint_changed = (not self.trusted or self.trusted["ip"] != str(ip)
                                or self.trusted["port"] != port)
            data = {"ip": str(ip), "port": port, "certificate": pem, "fingerprint": fingerprint,
                    "updated_at": time.time()}
            save_json(self.state_dir / "registration.json", data)
            self.trusted = data
            self.status["endpoint"] = f"{ip}:{port}"
            self.status["last_registration"] = time.time()
            # The 30-minute registration refresh must not tear down active
            # TCP/QUIC connections when the endpoint is unchanged.
            if endpoint_changed:
                self.peer_changed.set()
            LOG.info("B received A endpoint update: %s:%s", ip, port)
            return web.json_response({"ok": True})
        except (KeyError, TypeError, ValueError) as exc:
            return web.json_response({"error": str(exc)}, status=400)

    async def _start_b(self):
        persistent = self.state_dir / "registration.json"
        if persistent.exists():
            self.trusted = load_json(persistent)
            self.status["endpoint"] = f"{self.trusted['ip']}:{self.trusted['port']}"
            self.peer_changed.set()
        app = web.Application(client_max_size=32 * 1024)
        app.router.add_post("/control/mapping", self._control_mapping)
        self.control_runner = web.AppRunner(app, access_log=None)
        await self.control_runner.setup()
        site = web.TCPSite(self.control_runner, self.config["control_bind"], self.config["control_port"])
        await site.start()
        LOG.info("B control HTTP listening on %s:%s", self.config["control_bind"], self.config["control_port"])
        for rule in self.config["forwards"]:
            async def accept(reader, writer, rule_id=rule["id"]):
                if self.session:
                    await b_forward_tcp(self.session, rule_id, self.config["data_psk"], reader, writer)
                else:
                    writer.close()
                    await writer.wait_closed()
            server = await asyncio.start_server(accept, rule["listen_host"], rule["listen_port"])
            self.locals.append(server)
            LOG.info("B local TCP %s:%s -> A rule '%s'", rule["listen_host"], rule["listen_port"], rule["id"])
        self.tasks.append(asyncio.create_task(self._b_connection_loop(), name="b-connection-loop"))

    async def _b_connection_loop(self):
        c = self.config
        while not self.shutdown.is_set():
            if not self.trusted:
                self.status["state"] = "WAIT_ENDPOINT"
                try:
                    await asyncio.wait_for(self.peer_changed.wait(), timeout=2)
                except asyncio.TimeoutError:
                    continue
                self.peer_changed.clear()
                continue
            record = self.trusted
            peer = (record["ip"], record["port"])
            # A persisted endpoint is the starting state, not a fresh change.
            # Otherwise peer_changed remains set and immediately tears down
            # the successfully reconnected QUIC session after B restarts.
            self.peer_changed.clear()
            socks = None
            session = None
            try:
                self.status["state"] = "CONNECTING"
                def incoming(raw, src):
                    if session and src == peer:
                        session.receive(raw, src)
                socks = await SocksUDP(c["warp_socks5"]).open(incoming)
                config = make_client_quic_config(record["certificate"])
                quic = QuicConnection(configuration=config)
                session = QuicSession(quic, socks.send, peer)
                self.session = session
                session.client_connect()
                handshake = asyncio.create_task(session.connected.wait())
                changed = asyncio.create_task(self.peer_changed.wait())
                proxy_lost = asyncio.create_task(socks.closed.wait())
                try:
                    done, _ = await asyncio.wait((handshake, changed, proxy_lost),
                                                 timeout=25, return_when=asyncio.FIRST_COMPLETED)
                    if changed in done or proxy_lost in done:
                        raise ConnectionError("endpoint or WARP SOCKS5 changed during handshake")
                    if handshake not in done:
                        raise TimeoutError("QUIC handshake timed out")
                finally:
                    for task in (handshake, changed, proxy_lost):
                        if not task.done():
                            task.cancel()
                    await asyncio.gather(handshake, changed, proxy_lost, return_exceptions=True)
                if session.closed.is_set():
                    raise ConnectionError(session.error or "QUIC handshake terminated")
                await authenticate_client(session, c["data_psk"])
                if session.closed.is_set() or not session.authenticated.is_set():
                    raise PermissionError("QUIC session data_psk authentication failed")
                LOG.info("B authenticated QUIC active via WARP SOCKS5 -> A %s:%s", *peer)
                self.status["state"] = "DATA_ACTIVE"
                self.status["quic_connected"] = True
                self.status["last_error"] = None
                while not self.shutdown.is_set() and not session.closed.is_set():
                    if self.peer_changed.is_set() or socks.closed.is_set():
                        break
                    session.ping()
                    if time.monotonic() - session.last_pong_at > c["ping_interval"] * c["max_failures"] + 10:
                        raise TimeoutError("QUIC PING acknowledgements timed out")
                    try:
                        await asyncio.wait_for(self.shutdown.wait(), timeout=c["ping_interval"])
                    except asyncio.TimeoutError:
                        pass
                if session.closed.is_set():
                    raise ConnectionError(session.error or "QUIC closed")
            except (OSError, ConnectionError, TimeoutError, asyncio.TimeoutError, EOFError, ValueError) as exc:
                self.status["last_error"] = str(exc)
                self.status["state"] = "DATA_DEGRADED"
                LOG.warning("B data plane reconnect needed: %s", exc)
            finally:
                self.status["quic_connected"] = False
                if session:
                    await session.close()
                self.session = None
                if socks:
                    await socks.close()
                self.peer_changed.clear()
            try:
                await asyncio.wait_for(self.shutdown.wait(), timeout=c["reconnect_interval"])
            except asyncio.TimeoutError:
                pass

    async def stop(self):
        self.shutdown.set()
        for task in self.tasks:
            task.cancel()
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        for server in self.locals:
            server.close()
            await server.wait_closed()
        if self.quic_server:
            await self.quic_server.close()
        if self.session:
            await self.session.close()
        if self.udp:
            await self.udp.close()
        if self.control_runner:
            await self.control_runner.cleanup()
        if self.runner:
            await self.runner.cleanup()
