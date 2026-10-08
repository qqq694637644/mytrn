"""Configuration, durable state and A-side QUIC certificate management."""

from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

SERVER_NAME = "mytrn-a"
RULE_ID = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def defaults(role: str) -> dict[str, Any]:
    if role not in ("a", "b"):
        raise ValueError("role must be a or b")
    common = {
        "role": role,
        "control_token": secrets.token_hex(32),
        "data_psk": secrets.token_hex(32),
        "admin_token": secrets.token_hex(24),
        "web_bind": "127.0.0.1",
        "web_port": 18881 if role == "a" else 18882,
        "state_dir": f"state.{role}",
    }
    if role == "a":
        common.update({
            "local_udp_bind": "0.0.0.0",
            "local_udp_port": 39999,
            "stun_servers": ["stun.cloudflare.com:3478"],
            "stun_check_interval": 30,
            "stun_keepalive_interval": 15,
            "endpoint_change_confirm": 2,
            "register_refresh_interval": 1800,
            "control_retry_interval": 15,
            "control_socks5": "socks5://127.0.0.1:10810",
            "control_host": "B_CONTROL_HOST",
            "control_port": 18080,
            "targets": {"demo": {"host": "127.0.0.1", "port": 8080}},
        })
    else:
        common.update({
            "control_bind": "127.0.0.1",
            "control_port": 18080,
            "warp_socks5": "socks5://127.0.0.1:40000",
            "ping_interval": 5,
            "reconnect_interval": 5,
            "max_failures": 3,
            "forwards": [{"id": "demo", "listen_host": "127.0.0.1", "listen_port": 18081}],
        })
    return common


def atomic_write(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".mytrn-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save_json(path: Path, value: dict[str, Any]):
    atomic_write(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as source:
        data = json.load(source)
    if not isinstance(data, dict):
        raise ValueError("configuration must be a JSON object")
    return data


def validate_config(c: dict[str, Any], role: str) -> None:
    if c.get("role") != role:
        raise ValueError(f"config role must be {role!r}")
    for name in ("control_token", "data_psk", "admin_token"):
        if not isinstance(c.get(name), str) or len(c[name]) < 32:
            raise ValueError(f"{name} must be at least 32 characters")
        if c[name].startswith(("GENERATED_", "COPY_", "CHANGE_", "REPLACE_")):
            raise ValueError(f"{name} is an example placeholder; use 'python -m mytrn init'")
    for name in ("web_port", "control_port"):
        port = c.get(name)
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError(f"{name} must be a valid TCP port")
    for name in ("web_bind", "state_dir"):
        if not isinstance(c.get(name), str) or not c[name]:
            raise ValueError(f"{name} required")
    if role == "a":
        if type(c.get("local_udp_port")) is not int or not 1 <= c["local_udp_port"] <= 65535:
            raise ValueError("local_udp_port must be 1..65535")
        if not isinstance(c.get("stun_servers"), list) or not c["stun_servers"]:
            raise ValueError("at least one STUN server required")
        if not all(isinstance(s, str) and s for s in c["stun_servers"]):
            raise ValueError("invalid STUN server")
        if not c.get("control_socks5", "").startswith("socks5://"):
            raise ValueError("control_socks5 must start with socks5://")
        if not isinstance(c.get("control_host"), str) or not c["control_host"]:
            raise ValueError("control_host required")
        for name in ("stun_check_interval", "stun_keepalive_interval", "register_refresh_interval", "control_retry_interval"):
            if type(c.get(name)) not in (int, float) or c[name] <= 0:
                raise ValueError(f"{name} must be positive")
        if type(c.get("endpoint_change_confirm")) is not int or c["endpoint_change_confirm"] < 1:
            raise ValueError("endpoint_change_confirm must be positive integer")
        targets = c.get("targets")
        if not isinstance(targets, dict):
            raise ValueError("targets must be a JSON object")
        for rule, target in targets.items():
            if not isinstance(rule, str) or not RULE_ID.fullmatch(rule):
                raise ValueError("invalid target rule id")
            if not isinstance(target, dict) or not isinstance(target.get("host"), str) or not target["host"]:
                raise ValueError(f"invalid target for {rule}")
            if type(target.get("port")) is not int or not 1 <= target["port"] <= 65535:
                raise ValueError(f"invalid target port for {rule}")
    else:
        if not c.get("warp_socks5", "").startswith("socks5://"):
            raise ValueError("warp_socks5 must start with socks5://")
        if not isinstance(c.get("control_bind"), str) or not c["control_bind"]:
            raise ValueError("control_bind required")
        for name in ("ping_interval", "reconnect_interval"):
            if type(c.get(name)) not in (float, int) or c[name] <= 0:
                raise ValueError(f"{name} must be positive")
        if type(c.get("max_failures")) is not int or c["max_failures"] < 1:
            raise ValueError("max_failures must be positive integer")
        forwards = c.get("forwards")
        if not isinstance(forwards, list):
            raise ValueError("forwards must be a list")
        seen = set()
        for rule in forwards:
            if not isinstance(rule, dict) or not RULE_ID.fullmatch(str(rule.get("id", ""))):
                raise ValueError("invalid forwarding rule id")
            if not isinstance(rule.get("listen_host"), str) or not rule["listen_host"]:
                raise ValueError("listen_host required")
            if type(rule.get("listen_port")) is not int or not 1 <= rule["listen_port"] <= 65535:
                raise ValueError("invalid listen_port")
            key = (rule["listen_host"], rule["listen_port"])
            if key in seen:
                raise ValueError("duplicate listening address")
            seen.add(key)


def initialize(path: Path, role: str, overwrite: bool = False) -> dict[str, Any]:
    if path.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite {path}")
    config = defaults(role)
    save_json(path, config)
    return config


def state_path(config_path: Path, config: dict[str, Any]) -> Path:
    path = Path(config["state_dir"])
    return path if path.is_absolute() else config_path.resolve().parent / path


def ensure_a_certificate(directory: Path) -> tuple[Path, Path, str]:
    directory.mkdir(parents=True, exist_ok=True)
    certfile = directory / "a-cert.pem"
    keyfile = directory / "a-key.pem"
    if not (certfile.exists() and keyfile.exists()):
        if certfile.exists() or keyfile.exists():
            raise RuntimeError("incomplete A certificate/key; restore the missing file")
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SERVER_NAME)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(SERVER_NAME)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        atomic_write(keyfile, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())
        atomic_write(certfile, cert.public_bytes(serialization.Encoding.PEM).decode())
    pem = certfile.read_text(encoding="utf-8")
    x509.load_pem_x509_certificate(pem.encode())
    return certfile, keyfile, pem


def certificate_fingerprint(pem: str) -> str:
    cert = x509.load_pem_x509_certificate(pem.encode())
    return cert.fingerprint(hashes.SHA256()).hex()
