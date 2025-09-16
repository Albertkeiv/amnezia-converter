#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Конвертация AWG/WireGuard-клиентского конфига в vpn://<base64url>
(qCompress(zlib) + Base64 URL-safe без '=').
"""

import argparse
import json
import logging
import re
import struct
import sys
import zlib
from collections import OrderedDict
from pathlib import Path
from ipaddress import ip_interface, IPv4Interface, IPv6Interface

SECTION_RE = re.compile(r"^\s*\[(?P<name>[^\]]+)\]\s*$")
KEYVAL_RE  = re.compile(r"^\s*([^=#;]+?)\s*=\s*(.*?)\s*$")


def qcompress(payload: bytes, level: int = 8) -> bytes:
    compressed = zlib.compress(payload, level)
    return struct.pack(">I", len(payload)) + compressed


def b64url_nopad(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def strip_inline_comment(line: str) -> str:
    out, in_quote = [], False
    for ch in line:
        if ch == '"':
            in_quote = not in_quote
            out.append(ch)
            continue
        if not in_quote and ch in "#;":
            break
        out.append(ch)
    return "".join(out).rstrip()


def parse_cfg(text: str) -> dict:
    section = None
    data = {"Interface": {}, "Peer": {}}
    for raw in text.splitlines():
        line = strip_inline_comment(raw).strip()
        if not line:
            continue
        m = SECTION_RE.match(line)
        if m:
            name = m.group("name").strip().lower()
            section = "Interface" if name == "interface" else ("Peer" if name == "peer" else None)
            continue
        m = KEYVAL_RE.match(line)
        if m and section:
            k = m.group(1).strip()
            v = m.group(2).strip()
            if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
                v = v[1:-1]
            data[section][k] = v
    return data


def parse_dns(dns_value: str) -> tuple[str, str]:
    parts = [p.strip() for p in dns_value.split(",") if p.strip()]
    if not parts:
        return "", ""
    if len(parts) == 1:
        return parts[0], parts[0]
    return parts[0], parts[1]


def endpoint_host_port(endpoint: str) -> tuple[str, str]:
    ep = endpoint.strip()
    if ep.startswith('['):
        host, _, tail = ep[1:].partition(']')
        _, _, port = tail.partition(':')
        return host, port
    host, _, port = ep.rpartition(':')
    return host, port


def list_allowed_ips(val: str) -> list[str]:
    one_line = " ".join(val.split())
    parts = [p.strip() for p in one_line.split(",")]
    return [p for p in parts if p]


def compute_subnet_address(address: str) -> str:
    try:
        iface = ip_interface(address)
    except Exception:
        return ""
    if isinstance(iface, IPv4Interface):
        if iface.network.prefixlen == 32:
            octets = str(iface.ip).split(".")
            if len(octets) == 4:
                return ".".join(octets[:3] + ["0"])
        return str(iface.network.network_address)
    if isinstance(iface, IPv6Interface):
        return str(iface.network.network_address)
    return ""


def build_json(text: str, description: str) -> OrderedDict:
    parsed = parse_cfg(text)
    itf = parsed.get("Interface", {})
    peer = parsed.get("Peer", {})

    address = itf.get("Address", "").strip()
    dns_raw = itf.get("DNS", "").strip()
    dns1, dns2 = parse_dns(dns_raw) if dns_raw else ("", "")

    endpoint = peer.get("Endpoint", "").strip()
    host, port = endpoint_host_port(endpoint) if endpoint else ("", "")

    allowed_ips = list_allowed_ips(peer.get("AllowedIPs", "")) if peer.get("AllowedIPs") else []

    awg_params = {k: itf[k] for k in ("H1", "H2", "H3", "H4", "Jc", "Jmin", "Jmax", "S1", "S2") if k in itf}
    persistent = peer.get("PersistentKeepalive", "").strip()
    priv_key = itf.get("PrivateKey", "").strip()
    server_pub_key = peer.get("PublicKey", "").strip()
    psk_key = peer.get("PresharedKey", "").strip()
    subnet_address = compute_subnet_address(address) if address else ""

    last_cfg_obj = {
        **awg_params,
        "allowed_ips": allowed_ips,
        "client_ip": address.split("/")[0] if address else "",
        "client_priv_key": priv_key,
        "config": text,
        "hostName": host,
        "persistent_keep_alive": persistent,
        "port": int(port) if port.isdigit() else port or None,
        "psk_key": psk_key,
        "server_pub_key": server_pub_key,
    }
    last_cfg_obj = {k: v for k, v in last_cfg_obj.items() if v not in (None, "")}

    awg_block = {
        **awg_params,
        "last_config": json.dumps(last_cfg_obj, ensure_ascii=False, indent=2),
        "port": port,
        "subnet_address": subnet_address,
        "transport_proto": "udp",
    }

    containers = [{"awg": awg_block, "container": "amnezia-awg"}]

    result = OrderedDict()
    result["containers"] = containers
    # Удалены: killSwitchOption, allowedDnsServers, splitTunnelType, splitTunnelSites
    result["defaultContainer"] = "amnezia-awg"
    result["description"] = description
    result["dns1"] = dns1 or "1.1.1.1"
    result["dns2"] = dns2 or dns1 or "1.1.1.1"
    result["hostName"] = host

    return result


def encode_as_vpn_url(obj: OrderedDict) -> str:
    json_text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    blob = qcompress(json_text.encode("utf-8"), level=8)
    return "vpn://" + b64url_nopad(blob)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Конвертировать AWG/WG клиентский конфиг в vpn://<base64url> (qCompress+zlib)"
    )
    parser.add_argument("config", type=Path, help="Путь к файлу с конфигурацией")
    parser.add_argument("-o", "--output", type=Path, help="Куда записать результат (stdout по умолчанию)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Тише (уровень WARNING)")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s"
    )

    try:
        text = args.config.read_text(encoding="utf-8")
    except Exception as exc:
        logging.error("Не удалось прочитать файл %s: %s", args.config, exc)
        sys.exit(1)

    if "[Interface]" not in text or "[Peer]" not in text:
        logging.error("Файл не похож на AWG/WireGuard конфигурацию")
        sys.exit(2)

    description = args.config.stem

    try:
        obj = build_json(text, description=description)
        result = encode_as_vpn_url(obj)
    except Exception as exc:
        logging.error("Ошибка преобразования: %s", exc)
        sys.exit(3)

    if args.output:
        try:
            args.output.write_text(result + "\n", encoding="utf-8")
        except Exception as exc:
            logging.error("Не удалось записать результат: %s", exc)
            sys.exit(4)
    else:
        sys.stdout.write(result)
        if not result.endswith("\n"):
            sys.stdout.write("\n")


if __name__ == "__main__":
    main()
