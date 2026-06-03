from __future__ import annotations

import base64
import json
import re
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import requests
import yaml

SOURCES = [
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/aiboboxx/clashfree/main/clash.yml",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.yml",
]
OUTPUT = Path(__file__).resolve().parents[1] / "config" / "merged.yaml"


def safe_b64decode(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value.strip())
    if not compact:
        return None
    for candidate in (compact, compact + "=" * (-len(compact) % 4)):
        for decoder in (base64.urlsafe_b64decode, base64.b64decode):
            try:
                return decoder(candidate.encode()).decode("utf-8", "ignore")
            except Exception:
                pass
    return None


def as_int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return 0


def clean_name(value: Any, fallback: str) -> str:
    text = unquote(str(value or "").strip()) or fallback
    return re.sub(r"[\r\n\t]+", " ", text)[:120]


def parse_vmess(uri: str) -> dict[str, Any] | None:
    decoded = safe_b64decode(uri.removeprefix("vmess://"))
    if not decoded:
        return None
    try:
        item = json.loads(decoded)
    except Exception:
        return None
    server, port, uuid = item.get("add"), as_int(item.get("port")), item.get("id")
    if not server or not port or not uuid:
        return None
    proxy: dict[str, Any] = {
        "name": clean_name(item.get("ps"), f"vmess-{server}:{port}"),
        "type": "vmess",
        "server": server,
        "port": port,
        "uuid": uuid,
        "alterId": as_int(item.get("aid")),
        "cipher": item.get("scy") or "auto",
        "udp": True,
    }
    network = item.get("net")
    if network:
        proxy["network"] = network
    if str(item.get("tls") or "").lower() in {"tls", "true", "1"}:
        proxy["tls"] = True
        if item.get("sni"):
            proxy["servername"] = item["sni"]
    if network == "ws":
        headers = {}
        if item.get("host"):
            headers["Host"] = item["host"]
        proxy["ws-opts"] = {"path": item.get("path") or "/", "headers": headers}
    return proxy


def parse_ss(uri: str) -> dict[str, Any] | None:
    raw = uri.removeprefix("ss://")
    name = "ss-node"
    if "#" in raw:
        raw, name = raw.split("#", 1)
        name = clean_name(name, name)
    if "?" in raw:
        raw = raw.split("?", 1)[0]
    if "@" not in raw:
        raw = safe_b64decode(raw) or ""
    if "@" not in raw:
        return None
    userinfo, endpoint = raw.split("@", 1)
    if ":" not in userinfo:
        userinfo = safe_b64decode(userinfo) or userinfo
    if "?" in endpoint:
        endpoint = endpoint.split("?", 1)[0]
    if ":" not in userinfo or ":" not in endpoint:
        return None
    cipher, password = userinfo.split(":", 1)
    server, port_text = endpoint.rsplit(":", 1)
    port = as_int(port_text)
    if not server or not port:
        return None
    return {"name": name, "type": "ss", "server": server, "port": port, "cipher": unquote(cipher), "password": unquote(password), "udp": True}


def parse_trojan(uri: str) -> dict[str, Any] | None:
    parsed = urlparse(uri)
    port = as_int(parsed.port)
    if not parsed.hostname or not port or not parsed.username:
        return None
    qs = parse_qs(parsed.query)
    return {
        "name": clean_name(parsed.fragment, f"trojan-{parsed.hostname}:{port}"),
        "type": "trojan",
        "server": parsed.hostname,
        "port": port,
        "password": unquote(parsed.username),
        "sni": qs.get("sni", qs.get("peer", [parsed.hostname]))[0],
        "skip-cert-verify": qs.get("allowInsecure", ["0"])[0] in {"1", "true"},
        "udp": True,
    }


def parse_vless(uri: str) -> dict[str, Any] | None:
    parsed = urlparse(uri)
    port = as_int(parsed.port)
    if not parsed.hostname or not port or not parsed.username:
        return None
    qs = parse_qs(parsed.query)
    proxy: dict[str, Any] = {
        "name": clean_name(parsed.fragment, f"vless-{parsed.hostname}:{port}"),
        "type": "vless",
        "server": parsed.hostname,
        "port": port,
        "uuid": unquote(parsed.username),
        "udp": True,
        "tls": qs.get("security", [""])[0] == "tls",
        "servername": qs.get("sni", qs.get("host", [parsed.hostname]))[0],
    }
    network = qs.get("type", [""])[0]
    if network:
        proxy["network"] = network
    if network == "ws":
        proxy["ws-opts"] = {"path": qs.get("path", ["/"])[0], "headers": {"Host": qs.get("host", [parsed.hostname])[0]}}
    return proxy


def parse_uri(line: str) -> dict[str, Any] | None:
    try:
        if line.startswith("vmess://"):
            return parse_vmess(line)
        if line.startswith("ss://"):
            return parse_ss(line)
        if line.startswith("trojan://"):
            return parse_trojan(line)
        if line.startswith("vless://"):
            return parse_vless(line)
    except Exception:
        return None
    return None


def extract_yaml_proxies(content: str) -> list[dict[str, Any]]:
    try:
        data = yaml.safe_load(content)
    except Exception:
        return []
    if isinstance(data, dict) and isinstance(data.get("proxies"), list):
        return [item for item in data["proxies"] if isinstance(item, dict)]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def parse_content(content: str) -> list[dict[str, Any]]:
    proxies = extract_yaml_proxies(content)
    decoded = safe_b64decode(content)
    lines = content.splitlines()
    if decoded:
        proxies.extend(extract_yaml_proxies(decoded))
        lines.extend(decoded.splitlines())
    for line in lines:
        proxy = parse_uri(line.strip())
        if proxy:
            proxies.append(proxy)
    return proxies


def fetch(url: str) -> str:
    last_error = None
    for attempt in range(1, 4):
        try:
            response = requests.get(url, timeout=30, headers={"User-Agent": "clashfree-action/1.0"})
            response.raise_for_status()
            return response.text
        except Exception as exc:
            last_error = exc
            time.sleep(attempt * 2)
    print(f"Skip source {url}: {last_error}", file=sys.stderr)
    return ""


def dedupe(proxies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, int]] = set()
    names: set[str] = set()
    result: list[dict[str, Any]] = []
    for index, proxy in enumerate(proxies, 1):
        server, port, ptype = str(proxy.get("server") or "").strip(), as_int(proxy.get("port")), proxy.get("type")
        if not server or not port or not ptype:
            continue
        key = (server, port)
        if key in seen:
            continue
        seen.add(key)
        item = dict(proxy)
        item["server"], item["port"] = server, port
        base = clean_name(item.get("name"), f"{ptype}-{server}:{port}-{index}")
        name, suffix = base, 2
        while name in names:
            name = f"{base} {suffix}"
            suffix += 1
        item["name"] = name
        names.add(name)
        result.append(item)
    return result


def build_config(proxies: list[dict[str, Any]]) -> dict[str, Any]:
    names = [item["name"] for item in proxies]
    choices = ["AUTO", "DIRECT"] + names
    return {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "dns": {
            "enable": True,
            "listen": "0.0.0.0:1053",
            "ipv6": False,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "default-nameserver": ["223.5.5.5", "119.29.29.29"],
            "nameserver": ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"],
            "fallback": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
            "fallback-filter": {"geoip": True, "geoip-code": "CN"},
        },
        "proxies": proxies,
        "proxy-groups": [
            {"name": "AUTO", "type": "url-test", "proxies": names or ["DIRECT"], "url": "https://www.gstatic.com/generate_204", "interval": 300, "tolerance": 80},
            {"name": "PROXY", "type": "select", "proxies": choices},
            {"name": "GLOBAL", "type": "select", "proxies": choices},
        ],
        "rules": [
            "DOMAIN-SUFFIX,local,DIRECT",
            "DOMAIN-SUFFIX,localhost,DIRECT",
            "IP-CIDR,127.0.0.0/8,DIRECT",
            "IP-CIDR,10.0.0.0/8,DIRECT",
            "IP-CIDR,172.16.0.0/12,DIRECT",
            "IP-CIDR,192.168.0.0/16,DIRECT",
            "DOMAIN-SUFFIX,cn,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,PROXY",
        ],
    }


def main() -> int:
    proxies = dedupe([proxy for url in SOURCES for proxy in parse_content(fetch(url))])
    config = build_config(proxies)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")
    yaml.safe_load(OUTPUT.read_text(encoding="utf-8"))
    print(f"Generated {OUTPUT} with {len(proxies)} unique nodes")
    return 0 if proxies else 1


if __name__ == "__main__":
    raise SystemExit(main())
