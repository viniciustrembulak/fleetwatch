"""Leitura do inventário (quais hosts) e da política (o que verificar)."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SECTIONS = ("files", "users", "groups", "ssh_keys", "ports", "services", "suid")

# Padrões de arquivo entram no script remoto; só aceitamos caracteres de caminho e glob.
_SAFE_PATTERN = re.compile(r"^/[A-Za-z0-9_./*?\[\]+@-]*$")


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Host:
    name: str
    address: str
    port: int = 22
    user: str = "root"
    key_file: str | None = None
    become: bool = False
    timeout: float = 10.0
    known_hosts: str | None = None


@dataclass
class Policy:
    files: list[str] = field(default_factory=list)
    enabled: tuple[str, ...] = SECTIONS
    privileged_groups: list[str] = field(
        default_factory=lambda: ["root", "sudo", "wheel", "adm", "docker"]
    )
    suid_paths: list[str] = field(default_factory=lambda: ["/"])
    ignore_ports: list[str] = field(default_factory=list)
    ignore_addresses: list[str] = field(default_factory=list)
    ignore_services: list[str] = field(default_factory=list)
    ignore_users: list[str] = field(default_factory=list)


def _load_yaml(path: str | Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except FileNotFoundError as exc:
        raise ConfigError(f"arquivo não encontrado: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML inválido em {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: esperado um mapeamento no topo do arquivo")
    return data


def expand_address(spec: str) -> list[str]:
    """Expande '10.0.0.5', '10.0.0.0/30' ou '10.0.0.11-13' em uma lista de IPs/nomes."""
    spec = spec.strip()
    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError as exc:
            raise ConfigError(f"CIDR inválido: {spec}") from exc
        hosts = list(net.hosts()) or [net.network_address]
        return [str(ip) for ip in hosts]

    m = re.fullmatch(r"(\d+\.\d+\.\d+\.)(\d+)-(\d+)", spec)
    if m:
        prefix, start, end = m.group(1), int(m.group(2)), int(m.group(3))
        if not (0 <= start <= end <= 255):
            raise ConfigError(f"range inválido: {spec}")
        return [f"{prefix}{i}" for i in range(start, end + 1)]

    return [spec]


def load_inventory(path: str | Path) -> list[Host]:
    data = _load_yaml(path)
    defaults = data.get("defaults") or {}
    entries = data.get("hosts") or []
    if not isinstance(entries, list) or not entries:
        raise ConfigError(f"{path}: 'hosts' precisa ser uma lista não vazia")

    hosts: list[Host] = []
    for entry in entries:
        if not isinstance(entry, dict) or "address" not in entry:
            raise ConfigError(f"{path}: cada host precisa de 'address': {entry!r}")
        opts = {**defaults, **entry}
        addresses = expand_address(str(opts.pop("address")))
        name = opts.pop("name", None)
        for i, addr in enumerate(addresses, start=1):
            host_name = f"{name}-{i:02d}" if name and len(addresses) > 1 else name or addr
            hosts.append(
                Host(
                    name=host_name,
                    address=addr,
                    port=int(opts.get("port", 22)),
                    user=str(opts.get("user", "root")),
                    key_file=opts.get("key_file"),
                    become=bool(opts.get("become", False)),
                    timeout=float(opts.get("timeout", 10)),
                    known_hosts=opts.get("known_hosts"),
                )
            )

    names = [h.name for h in hosts]
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        raise ConfigError(f"{path}: nomes de host duplicados: {', '.join(dupes)}")
    return hosts


def load_policy(path: str | Path) -> Policy:
    data = _load_yaml(path)
    policy = Policy()

    files = data.get("files") or []
    for pattern in files:
        if not isinstance(pattern, str) or not _SAFE_PATTERN.match(pattern):
            raise ConfigError(f"{path}: padrão de arquivo inválido ou inseguro: {pattern!r}")
    policy.files = files

    enabled = data.get("collectors")
    if enabled is not None:
        unknown = set(enabled) - set(SECTIONS)
        if unknown:
            raise ConfigError(f"{path}: coletores desconhecidos: {', '.join(sorted(unknown))}")
        policy.enabled = tuple(s for s in SECTIONS if s in enabled)

    if "privileged_groups" in data:
        policy.privileged_groups = list(data["privileged_groups"])
    if "suid_paths" in data:
        for p in data["suid_paths"]:
            if not _SAFE_PATTERN.match(p) or any(c in p for c in "*?["):
                raise ConfigError(f"{path}: caminho de suid inválido: {p!r}")
        policy.suid_paths = list(data["suid_paths"])

    ignore = data.get("ignore") or {}
    policy.ignore_ports = [str(p) for p in ignore.get("ports", [])]
    policy.ignore_addresses = [str(a) for a in ignore.get("addresses", [])]
    policy.ignore_services = list(ignore.get("services", []))
    policy.ignore_users = list(ignore.get("users", []))
    return policy
