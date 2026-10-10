"""Role-specific, strict configuration; durable private state; TLS identity.

All configuration keys are intentional: unknown keys are errors, not silently
ignored compatibility options. Xray protocol configuration is generated, never
edited by this layer.
"""

from __future__ import annotations

import ipaddress
import json
import os
import secrets
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

XRAY_VERSION = "26.3.27"
TLS_NAME = "mytrn-a.test"
COMMON = {"role", "xray_bin", "web_bind", "web_port", "admin_token",
          "control_token", "vless_uuid", "state_dir"}
A_KEYS = {"udp_bind", "udp_port", "xray_udp_port", "socks_port", "stun_servers",
          "stun_interval", "stun_confirm", "register_refresh", "register_retry",
          "control_host", "control_port", "control_proxy_port",
          "control_cf_address", "control_cf_port", "control_cf_uuid",
          "control_cf_server_name", "control_cf_xhttp_host", "control_cf_xhttp_path",
          "control_cf_xhttp_mode", "control_cf_fingerprint", "control_cf_alpn"}
B_KEYS = {"control_bind", "control_port", "warp_socks5"}

# CF/VLESS is generated directly by Python in A's Xray. Missing node fields
# leave the control route disabled, not redirected through v2rayN or DIRECT.
# Actual working v2rayN node: XHTTP packet-up, TLS fingerprint chrome, ALPN h3.
# XHTTP over h3 uses UDP 443; it is not WebSocket.
A_CF_DEFAULTS = {
    "control_proxy_port": 10909,
    "control_cf_address": "",
    "control_cf_port": 443,
    "control_cf_uuid": "",
    "control_cf_server_name": "",
    "control_cf_xhttp_host": "",
    "control_cf_xhttp_path": "/",
    "control_cf_xhttp_mode": "packet-up",
    "control_cf_fingerprint": "chrome",
    "control_cf_alpn": "h3",
}


def control_cf_ready(c: dict) -> bool:
    return all(c[key] for key in ("control_cf_address", "control_cf_uuid",
                                   "control_cf_server_name", "control_cf_xhttp_host"))

# A originally set MTU=1200 and used the other Xray 26.3.27 defaults.
A_MKCP_DEFAULTS = {
    "mkcp_mtu": 1200,
    "mkcp_tti": 50,
    "mkcp_uplink_capacity": 5,
    "mkcp_downlink_capacity": 20,
    "mkcp_congestion": False,
    "mkcp_read_buffer_size": 2,
    "mkcp_write_buffer_size": 2,
}


def mkcp_settings(config: dict) -> dict:
    """Only emit supported Xray v26.3.27 knobs, preserving the old default JSON."""
    result = {"mtu": config.get("mkcp_mtu", 1200)}
    for key, output in (
        ("mkcp_tti", "tti"),
        ("mkcp_uplink_capacity", "uplinkCapacity"),
        ("mkcp_downlink_capacity", "downlinkCapacity"),
        ("mkcp_read_buffer_size", "readBufferSize"),
        ("mkcp_write_buffer_size", "writeBufferSize"),
    ):
        if config.get(key, A_MKCP_DEFAULTS[key]) != A_MKCP_DEFAULTS[key]:
            result[output] = config[key]
    if config.get("mkcp_congestion", False):
        result["congestion"] = True
    return result


def defaults(role: str) -> dict:
    if role not in ("a", "b"):
        raise ValueError("role must be a or b")
    c = {
        "role": role,
        "xray_bin": "xray",
        "web_bind": "127.0.0.1",
        "web_port": 18881 if role == "a" else 18882,
        "admin_token": secrets.token_hex(32),
        "control_token": secrets.token_hex(32),
        "vless_uuid": str(uuid.uuid4()),
        "state_dir": f"state.{role}",
    }
    if role == "a":
        c.update({
            "udp_bind": "0.0.0.0", "udp_port": 39999,
            "xray_udp_port": 40001, "socks_port": 10808,
            "stun_servers": ["stun.cloudflare.com:3478"],
            "stun_interval": 20, "stun_confirm": 2,
            "register_refresh": 1800, "register_retry": 15,
            "control_host": "CHANGE_TO_B_CONTROL_HOST", "control_port": 18080,
        })
        c.update(A_CF_DEFAULTS)
        c.update(A_MKCP_DEFAULTS)
    else:
        c.update({"control_bind": "127.0.0.1", "control_port": 18080,
                  "warp_socks5": "socks5://127.0.0.1:40000"})
    return c


def exact_keys(value: dict, names: set[str], label: str):
    missing = names - value.keys()
    extra = value.keys() - names
    if missing or extra:
        raise ValueError(f"{label}: missing={sorted(missing)}, unknown={sorted(extra)}")


def port(value, key):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError(f"{key} must be integer port 1..65535")


def parse_host_port(raw: str, default_port=3478) -> tuple[str, int]:
    if not isinstance(raw, str) or not raw:
        raise ValueError("server address missing")
    if raw.startswith("["):
        address, delim, suffix = raw[1:].partition("]")
        if not delim or (suffix and not suffix.startswith(":")):
            raise ValueError(f"invalid address {raw}")
        p = int(suffix[1:]) if suffix else default_port
    elif raw.count(":") == 1:
        address, text_port = raw.rsplit(":", 1)
        p = int(text_port)
    elif ":" not in raw:
        address, p = raw, default_port
    else:
        raise ValueError("IPv6 literal must be bracketed")
    if not address:
        raise ValueError("host must not be empty")
    port(p, "server port")
    return address, p


def socks_uri(raw, key):
    if not isinstance(raw, str):
        raise ValueError(f"{key} must be a string")
    parsed = urlsplit(raw)
    if parsed.scheme != "socks5" or not parsed.hostname or parsed.path not in ("", "/"):
        raise ValueError(f"{key} must be socks5://host:port")
    port(parsed.port or 1080, key)


def validate(c: dict, role: str):
    if role not in ("a", "b") or not isinstance(c, dict):
        raise ValueError("invalid role/config")
    if role == "a":
        # One-time configuration schema update, not a protocol fallback:
        # discard the retired v2rayN control setting and preserve all A
        # identities, UDP settings and mKCP values.
        c.pop("control_socks5", None)
        # The previous A UI incorrectly labelled XHTTP Host/Path as WS.
        # This is a one-time rename of the saved values, not a WS fallback.
        old_host = c.pop("control_cf_ws_host", None)
        old_path = c.pop("control_cf_ws_path", None)
        if "control_cf_xhttp_host" not in c and old_host is not None:
            c["control_cf_xhttp_host"] = old_host
        if "control_cf_xhttp_path" not in c and old_path is not None:
            c["control_cf_xhttp_path"] = old_path
        for key, value in A_CF_DEFAULTS.items():
            c.setdefault(key, value)
        for key, value in A_MKCP_DEFAULTS.items():
            c.setdefault(key, value)
    exact_keys(c, COMMON | (A_KEYS | A_MKCP_DEFAULTS.keys() if role == "a" else B_KEYS), role)
    if c["role"] != role:
        raise ValueError("config role mismatch")
    for key in ("admin_token", "control_token"):
        if (not isinstance(c[key], str) or len(c[key]) < 32 or
                c[key].startswith(("CHANGE_", "REPLACE_", "GENERATED_"))):
            raise ValueError(f"{key} requires random secret of at least 32 characters")
    try:
        if str(uuid.UUID(c["vless_uuid"])) != c["vless_uuid"].lower():
            raise ValueError("invalid UUID")
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("vless_uuid must be valid canonical UUID") from exc
    for key in ("xray_bin", "state_dir", "web_bind"):
        if not isinstance(c[key], str) or not c[key].strip():
            raise ValueError(f"{key} required")
    port(c["web_port"], "web_port")
    if role == "a":
        kcp_ranges = {
            "mkcp_mtu": (576, 1460),
            "mkcp_tti": (10, 1000),
            "mkcp_uplink_capacity": (1, 1000),
            "mkcp_downlink_capacity": (1, 1000),
            "mkcp_read_buffer_size": (1, 256),
            "mkcp_write_buffer_size": (1, 256),
        }
        for key, (minimum, maximum) in kcp_ranges.items():
            if type(c[key]) is not int or not minimum <= c[key] <= maximum:
                raise ValueError(f"{key} must be integer {minimum}..{maximum}")
        if type(c["mkcp_congestion"]) is not bool:
            raise ValueError("mkcp_congestion must be boolean")
        for key in ("udp_port", "xray_udp_port", "socks_port", "control_port",
                    "control_proxy_port", "control_cf_port"):
            port(c[key], key)
        if len({c["udp_port"], c["xray_udp_port"], c["socks_port"],
                c["control_proxy_port"], c["web_port"]}) != 5:
            raise ValueError("A listening ports must be distinct")
        if not isinstance(c["udp_bind"], str) or not c["udp_bind"]:
            raise ValueError("udp_bind required")
        if not isinstance(c["control_host"], str) or not c["control_host"]:
            raise ValueError("control_host required")
        for key in ("control_cf_address", "control_cf_uuid", "control_cf_server_name",
                    "control_cf_xhttp_host", "control_cf_xhttp_path", "control_cf_xhttp_mode",
                    "control_cf_fingerprint", "control_cf_alpn"):
            if not isinstance(c[key], str):
                raise ValueError(f"{key} must be a string")
        for key in ("control_cf_address", "control_cf_server_name", "control_cf_xhttp_host"):
            if c[key] and (any(char.isspace() for char in c[key]) or
                           any(char in c[key] for char in "/@")):
                raise ValueError(f"{key} must be a hostname or IP without URL/whitespace")
        if not c["control_cf_xhttp_path"].startswith("/") or "#" in c["control_cf_xhttp_path"]:
            raise ValueError("control_cf_xhttp_path must begin with / (no fragment)")
        if c["control_cf_xhttp_mode"] not in ("packet-up", "stream-up", "stream-one"):
            raise ValueError("control_cf_xhttp_mode must be packet-up, stream-up or stream-one")
        if c["control_cf_fingerprint"] not in ("chrome", "firefox", "safari", "edge"):
            raise ValueError("control_cf_fingerprint must be chrome, firefox, safari or edge")
        if c["control_cf_alpn"] not in ("h3", "h2"):
            raise ValueError("control_cf_alpn must be h3 or h2")
        if c["control_cf_uuid"]:
            try:
                if str(uuid.UUID(c["control_cf_uuid"])) != c["control_cf_uuid"].lower():
                    raise ValueError("invalid UUID")
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValueError("control_cf_uuid must be canonical VLESS UUID") from exc
        if any(c[key] for key in ("control_cf_address", "control_cf_uuid",
                                 "control_cf_server_name", "control_cf_xhttp_host")) and not control_cf_ready(c):
            raise ValueError("CF node is incomplete: address, UUID, SNI and XHTTP Host are required")
        if not isinstance(c["stun_servers"], list) or not c["stun_servers"] or len(c["stun_servers"]) > 4:
            raise ValueError("stun_servers must contain 1..4 endpoints")
        for server in c["stun_servers"]:
            parse_host_port(server)
        for key in ("stun_interval", "register_refresh", "register_retry"):
            if type(c[key]) not in (int, float) or not 1 <= c[key] <= 86400:
                raise ValueError(f"{key} must be 1..86400 seconds")
        if type(c["stun_confirm"]) is not int or not 1 <= c["stun_confirm"] <= 5:
            raise ValueError("stun_confirm must be 1..5")
    else:
        if not isinstance(c["control_bind"], str) or not c["control_bind"]:
            raise ValueError("control_bind required")
        port(c["control_port"], "control_port")
        if c["control_port"] == c["web_port"]:
            raise ValueError("control and web ports must be distinct")
        socks_uri(c["warp_socks5"], "warp_socks5")


def write_text(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, tmp = tempfile.mkstemp(prefix=".mytrn-", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def save_json(path: Path, value: dict):
    write_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise ValueError("config must be JSON object")
    return obj


def init_config(path: Path, role: str) -> dict:
    if path.exists():
        raise FileExistsError(f"already exists: {path}")
    cfg = defaults(role)
    validate(cfg, role)
    save_json(path, cfg)
    return cfg


def state_dir(config_path: Path, c: dict) -> Path:
    path = Path(c["state_dir"])
    return path if path.is_absolute() else config_path.resolve().parent / path


def create_a_identity(directory: Path) -> tuple[Path, Path, str, str]:
    directory.mkdir(parents=True, exist_ok=True)
    certfile, keyfile = directory / "a-cert.pem", directory / "a-key.pem"
    if certfile.exists() != keyfile.exists():
        raise RuntimeError("A TLS certificate/key incomplete: restore missing file")
    if not certfile.exists():
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, TLS_NAME)])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=5))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(TLS_NAME)]), critical=False)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(key, hashes.SHA256()))
        write_text(keyfile, key.private_bytes(serialization.Encoding.PEM,
                   serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode("ascii"))
        write_text(certfile, cert.public_bytes(serialization.Encoding.PEM).decode("ascii"))
    pem = certfile.read_text(encoding="ascii")
    return certfile, keyfile, pem, validate_a_certificate(pem)


def validate_a_certificate(pem: str) -> str:
    if not isinstance(pem, str) or len(pem) > 8192:
        raise ValueError("certificate too long or missing")
    cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
    if not cert.not_valid_before_utc <= datetime.now(timezone.utc) <= cert.not_valid_after_utc:
        raise ValueError("A TLS certificate expired or not yet valid")
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if TLS_NAME not in san.get_values_for_type(x509.DNSName):
        raise ValueError("wrong TLS serverName in certificate")
    return cert.fingerprint(hashes.SHA256()).hex()
