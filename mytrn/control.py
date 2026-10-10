"""A STUN endpoint registration via its OWN Xray CF/VLESS control outbound."""

from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import time
from pathlib import Path

from aiohttp import ClientSession, ClientTimeout, web
from aiohttp_socks import ProxyConnector

from .config import control_cf_ready, load_json, save_json, validate_a_certificate

LOG = logging.getLogger("mytrn.control")


async def register_from_a(config: dict, ip: str, port: int, certificate: str) -> dict:
    if config["control_host"].startswith("CHANGE_"):
        raise ValueError("Set A control_host in Web UI before registering")
    if not control_cf_ready(config):
        raise ValueError("Configure A CF/VLESS address, UUID, TLS SNI and WS Host before registering")
    # Python -> its own Xray loopback SOCKS5 -> CF CDN/VLESS -> B Go HTTP.
    # v2rayN is ONLY the user traffic collector: never use its 10810 port,
    # the MyTRN data SOCKS5 10808, or any direct connection to B as fallback.
    connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{config['control_proxy_port']}", rdns=True)
    url = f"http://{config['control_host']}:{config['control_port']}/control/mapping"
    body = {"node": "a", "ip": ip, "port": port, "certificate": certificate}
    async with ClientSession(connector=connector, timeout=ClientTimeout(total=15), trust_env=False) as session:
        async with session.post(url, headers={"X-Control-Token": config["control_token"]}, json=body) as response:
            if response.content_length is not None and response.content_length > 8192:
                raise OSError("control response too large")
            answer = await response.json()
            if response.status != 200:
                raise OSError(f"control HTTP {response.status}: {answer.get('error', 'rejected')}")
            if answer.get("ok") is not True:
                raise OSError("control did not acknowledge mapping")
            return answer


def validate_registration(value: dict) -> dict:
    if not isinstance(value, dict) or set(value) != {"node", "ip", "port", "certificate"} or value.get("node") != "a":
        raise ValueError("invalid single-A registration request")
    try:
        ip = ipaddress.IPv4Address(value["ip"])
    except (ipaddress.AddressValueError, TypeError, ValueError) as exc:
        raise ValueError("invalid IPv4 endpoint") from exc
    if ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        raise ValueError("non-unicast IPv4 endpoint")
    if type(value["port"]) is not int or not 1 <= value["port"] <= 65535:
        raise ValueError("invalid endpoint port")
    fingerprint = validate_a_certificate(value["certificate"])
    return {"ip": str(ip), "port": value["port"], "certificate": value["certificate"],
            "fingerprint": fingerprint, "updated_at": time.time()}


class ControlServer:
    """Single-node B registration API; never affects the existing x-ui server."""

    def __init__(self, config: dict, state: Path):
        self.config = config
        self.state = state
        self.registration = None
        self.updated = None
        self.runner = None
        self.registration_path = state / "registration.json"

    async def start(self):
        self.state.mkdir(parents=True, exist_ok=True)
        if self.registration_path.is_file():
            item = load_json(self.registration_path)
            checked = validate_registration({"node": "a", "ip": item["ip"], "port": item["port"],
                                             "certificate": item["certificate"]})
            self.registration = {**checked, "updated_at": item.get("updated_at", time.time())}
            LOG.info("B restored A endpoint %s:%s", item["ip"], item["port"])
        app = web.Application(client_max_size=12 * 1024)
        app.router.add_post("/control/mapping", self.handle)
        self.runner = web.AppRunner(app, access_log=None)
        await self.runner.setup()
        await web.TCPSite(self.runner, self.config["control_bind"], self.config["control_port"]).start()
        LOG.info("B control listening on %s:%s", self.config["control_bind"], self.config["control_port"])

    async def handle(self, request: web.Request) -> web.Response:
        supplied = request.headers.get("X-Control-Token", "")
        if not hmac.compare_digest(supplied, self.config["control_token"]):
            return web.json_response({"error": "unauthorized"}, status=403)
        try:
            record = validate_registration(await request.json())
        except (ValueError, KeyError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            return web.json_response({"error": str(exc)}, status=400)
        if self.registration and record["fingerprint"] != self.registration["fingerprint"]:
            LOG.warning("B rejected changed A certificate fingerprint")
            return web.json_response({"error": "A certificate changed: explicit re-trust required"}, status=409)
        changed = not self.registration or (record["ip"], record["port"]) != (
            self.registration["ip"], self.registration["port"])
        save_json(self.registration_path, record)
        self.registration = record
        self.updated = time.time()
        if changed:
            LOG.info("B received changed A endpoint %s:%s", record["ip"], record["port"])
        return web.json_response({"ok": True, "changed": changed,
                                  "certificate_sha256": record["fingerprint"]})

    async def close(self):
        if self.runner:
            await self.runner.cleanup()
            self.runner = None
