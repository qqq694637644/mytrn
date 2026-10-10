"""A/B thin Python orchestrator for existing Xray-core/WARP/CF-VLESS services."""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path

from .config import control_cf_ready, create_a_identity, load_json, state_dir, validate, write_text
from .control import ControlServer, register_from_a
from .udp import UdpGateway
from .web import WebUI
from .xray import XrayProcess, make_a, make_b

LOG = logging.getLogger("mytrn.app")


class Agent:
    def __init__(self, role: str, path: Path):
        self.role = role
        self.path = path.resolve()
        self.config = load_json(self.path)
        validate(self.config, role)
        self.directory = state_dir(self.path, self.config)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.ui = WebUI(self)
        self.gateway = None
        self.control = None
        self.xray = None
        self.certificate = None
        self.certfile = None
        self.keyfile = None
        self.endpoint: tuple[str, int] | None = None
        self.last_stun = None
        self.last_registration = None
        self.last_error = None
        self.proxy_probe = None
        self.restart_required = False
        self.shutdown = asyncio.Event()
        self.tasks: list[asyncio.Task] = []
        self.stun_failures = 0
        self._stun_candidate = None
        self._stun_count = 0
        self._registration_retry_at = 0.0
        self._register_needed = True

    async def start(self):
        await self.ui.start()
        if self.role == "a":
            self.certfile, self.keyfile, self.certificate, fingerprint = create_a_identity(self.directory)
            LOG.info("A Xray TLS certificate SHA256 %s", fingerprint)
            self.gateway = await UdpGateway(self.config["udp_bind"], self.config["udp_port"],
                                            self.config["xray_udp_port"]).start()
            self.tasks.append(asyncio.create_task(self._maintain_stun(), name="A STUN/control"))
        else:
            self.control = ControlServer(self.config, self.directory)
            await self.control.start()
        self.tasks.append(asyncio.create_task(self._supervise_xray(), name="Xray manager"))

    async def _maintain_stun(self):
        cfg = self.config
        last_register_at = 0.0
        last_attempt = 0.0
        while not self.shutdown.is_set():
            try:
                found = None
                failure = None
                for stun_server in cfg["stun_servers"]:
                    try:
                        found = await self.gateway.stun(stun_server, timeout=3)
                        break
                    except (OSError, ValueError, asyncio.TimeoutError) as exc:
                        failure = exc
                if found is None:
                    self.stun_failures += 1
                    self.last_error = f"STUN: {type(failure).__name__}"
                    if self.stun_failures == 1 or self.stun_failures % 10 == 0:
                        LOG.warning("A STUN timeout/error (%d consecutive): %s", self.stun_failures, failure)
                else:
                    self.stun_failures = 0
                    self.last_stun = time.time()
                    if self.endpoint is None:
                        self.endpoint = found
                        self._register_needed = True
                        LOG.info("A discovered public NAT mapping %s:%s", *found)
                    elif found != self.endpoint:
                        if self._stun_candidate == found:
                            self._stun_count += 1
                        else:
                            self._stun_candidate, self._stun_count = found, 1
                        if self._stun_count >= cfg["stun_confirm"]:
                            LOG.warning("A public mapping changed %s -> %s", self.endpoint, found)
                            self.endpoint = found
                            self._register_needed = True
                            self.proxy_probe = None  # Last exit-IP probe no longer proves the new path.
                            self._stun_candidate, self._stun_count = None, 0
                    else:
                        self._stun_candidate, self._stun_count = None, 0
                    if self.last_error and self.last_error.startswith("STUN:"):
                        self.last_error = None
            except Exception as exc:
                # Neither a transient DNS failure nor lost STUN response changes
                # the currently registered/public NAT mapping.
                self.last_error = f"STUN: {type(exc).__name__}: {exc}"
                LOG.warning("A STUN check failed: %s", exc)
            now = time.monotonic()
            peer_inactive = (not self.gateway.last_external or
                             time.time() - self.gateway.last_external > 120)
            refresh_due = now - last_register_at >= cfg["register_refresh"]
            inactive_due = peer_inactive and now - last_register_at >= 120
            if (self.endpoint and now >= self._registration_retry_at and
                    (self._register_needed or refresh_due or inactive_due)):
                try:
                    result = await register_from_a(cfg, *self.endpoint, self.certificate)
                    self.last_registration = time.time()
                    last_register_at = time.monotonic()
                    self._register_needed = False
                    if self.last_error and self.last_error.startswith("control:"):
                        self.last_error = None
                    LOG.info("A registered STUN endpoint %s:%s via CF/VLESS control; B changed=%s",
                             *self.endpoint, result.get("changed"))
                except Exception as exc:
                    self.last_error = f"control: {type(exc).__name__}: {exc}"
                    LOG.warning("A control register failed: %s", exc)
                    # Try again at configured interval, not every STUN cycle.
                    self._register_needed = True
                self._registration_retry_at = time.monotonic() + cfg["register_retry"]
            if self.gateway:
                self.gateway.prune()
            await self._pause(cfg["stun_interval"])

    async def _supervise_xray(self):
        while not self.shutdown.is_set():
            try:
                record = self.control.registration if self.control else None
                if self.role == "a":
                    wanted = make_a(self.config, self.certfile, self.keyfile)
                elif record:
                    certificate = self.directory / "a-cert.pem"
                    pem = record["certificate"]
                    if not certificate.is_file() or certificate.read_text(encoding="ascii") != pem:
                        write_text(certificate, pem)
                    wanted = make_b(self.config, record, certificate)
                else:
                    await self._pause(2)
                    continue
                if not self.xray:
                    self.xray = XrayProcess(self.config["xray_bin"], self.directory, self.role)
                await self.xray.ensure(wanted)
                if self.last_error and self.last_error.startswith("xray:"):
                    self.last_error = None
            except Exception as exc:
                self.last_error = f"xray: {type(exc).__name__}: {exc}"
                LOG.warning("%s Xray supervisor: %s", self.role.upper(), exc)
            await self._pause(3)

    async def _pause(self, seconds):
        try:
            await asyncio.wait_for(self.shutdown.wait(), seconds)
        except asyncio.TimeoutError:
            pass

    def status(self) -> dict:
        status = {"role": self.role, "restart_required": self.restart_required,
                  "last_error": self.last_error,
                  "xray": self.xray.status() if self.xray else {"running": False},
                  "control_endpoint": (f"{self.endpoint[0]}:{self.endpoint[1]}" if self.role == "a" and self.endpoint
                                       else f"{self.control.registration['ip']}:{self.control.registration['port']}"
                                       if self.control and self.control.registration else None)}
        if self.role == "a":
            status.update({"stun_last_success": self.last_stun,
                           "stun_consecutive_failures": self.stun_failures,
                           "control_last_registration": self.last_registration,
                           "control_transport": "own-xray-vless-xhttp-tls-via-cf",
                           "control_configured": control_cf_ready(self.config),
                           "control_local_socks": f"127.0.0.1:{self.config['control_proxy_port']}",
                           "gateway": self.gateway.status() if self.gateway else {},
                           "proxy_end_to_end_test": self.proxy_probe})
        else:
            record = self.control.registration if self.control else None
            status.update({"control_last_registration": record["updated_at"] if record else None,
                           "trusted_certificate_sha256": record["fingerprint"] if record else None})
        return status

    async def stop(self):
        self.shutdown.set()
        for task in self.tasks:
            task.cancel()
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        if self.xray:
            await self.xray.stop()
        if self.gateway:
            await self.gateway.close()
        if self.control:
            await self.control.close()
        await self.ui.close()
