"""Gera o script de coleta enviado ao host e interpreta a saída dele.

A coleta inteira acontece em uma única sessão SSH: um script POSIX sh é
enviado pelo stdin e imprime cada seção entre marcadores. Nada é instalado
no host monitorado.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import shlex

from fleetwatch.config import Policy

MARK = "@@FW:"
UNSUPPORTED = "@@FW:UNSUPPORTED@@"

Section = dict[str, dict[str, object]]


def build_script(policy: Policy) -> str:
    parts = [
        "export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        f"echo '{MARK}meta@@'",
        'echo "hostname=$(hostname 2>/dev/null || cat /etc/hostname)"',
        'echo "kernel=$(uname -r)"',
        'echo "os=$( . /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")"',
    ]

    if "files" in policy.enabled:
        # Padrões já validados em config.py; ficam sem aspas para o shell expandir os globs.
        patterns = " ".join(policy.files) or "/dev/null"
        parts += [
            f"echo '{MARK}files@@'",
            f"for f in {patterns}; do",
            '  [ -f "$f" ] || continue',
            "  h=$(sha256sum -- \"$f\" 2>/dev/null | cut -d' ' -f1)",
            '  [ -n "$h" ] || continue',
            '  printf \'%s\\t%s\\t%s\\n\' "$h" "$(stat -c \'%a:%U:%G\' -- "$f")" "$f"',
            "done",
        ]

    if "users" in policy.enabled:
        parts += [f"echo '{MARK}users@@'", "getent passwd"]

    if "groups" in policy.enabled:
        parts += [f"echo '{MARK}groups@@'", "getent group"]

    if "ssh_keys" in policy.enabled:
        parts += [
            f"echo '{MARK}ssh_keys@@'",
            "getent passwd | while IFS=: read -r u _ _ _ _ home _; do",
            '  for k in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do',
            '    [ -f "$k" ] && awk -v u="$u" \'NF && $1 !~ /^#/ {print u "\\t" $0}\' "$k"',
            "  done",
            "done | sort -u",
        ]

    if "ports" in policy.enabled:
        parts += [
            f"echo '{MARK}ports@@'",
            f"if command -v ss >/dev/null 2>&1; then ss -H -tulpn; else echo '{UNSUPPORTED}'; fi",
        ]

    if "services" in policy.enabled:
        parts += [
            f"echo '{MARK}services@@'",
            "if [ -d /run/systemd/system ]; then",
            "  systemctl list-units --type=service --state=running --no-legend --plain --no-pager",
            f"else echo '{UNSUPPORTED}'; fi",
        ]

    if "suid" in policy.enabled:
        paths = " ".join(shlex.quote(p) for p in policy.suid_paths)
        parts += [
            f"echo '{MARK}suid@@'",
            f"find {paths} -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null | sort",
        ]

    parts.append(f"echo '{MARK}END@@'")
    return "\n".join(parts) + "\n"


def split_sections(output: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    finished = False
    for line in output.splitlines():
        m = re.fullmatch(r"@@FW:(\w+)@@", line.strip())
        if m:
            if m.group(1) == "END":
                finished = True
                break
            if m.group(1) != "UNSUPPORTED":
                current = m.group(1)
                sections[current] = []
                continue
        if current is not None:
            sections[current].append(line)
    if not finished:
        raise ValueError("saída de coleta incompleta (marcador END ausente)")
    return sections


def _unsupported(lines: list[str]) -> bool:
    return any(line.strip() == UNSUPPORTED for line in lines)


def parse_meta(lines: list[str]) -> dict[str, str]:
    meta = {}
    for line in lines:
        key, sep, value = line.partition("=")
        if sep:
            meta[key.strip()] = value.strip()
    return meta


def parse_files(lines: list[str]) -> Section:
    out: Section = {}
    for line in lines:
        fields = line.split("\t", 2)
        if len(fields) != 3:
            continue
        digest, perms, path = fields
        mode, _, rest = perms.partition(":")
        owner, _, group = rest.partition(":")
        out[path] = {"sha256": digest, "mode": mode, "owner": owner, "group": group}
    return out


def parse_users(lines: list[str]) -> Section:
    out: Section = {}
    for line in lines:
        fields = line.split(":")
        if len(fields) < 7:
            continue
        name, _, uid, gid, _, home, shell = fields[:7]
        out[name] = {"uid": int(uid), "gid": int(gid), "home": home, "shell": shell}
    return out


def parse_groups(lines: list[str], privileged: list[str]) -> Section:
    out: Section = {}
    for line in lines:
        fields = line.split(":")
        if len(fields) < 4 or fields[0] not in privileged:
            continue
        members = sorted(m for m in fields[3].split(",") if m)
        out[fields[0]] = {"gid": int(fields[2]), "members": members}
    return out


_KEY_TYPE = re.compile(r"^(ssh-|ecdsa-|sk-)")


def key_fingerprint(blob_b64: str) -> str:
    raw = base64.b64decode(blob_b64, validate=True)
    digest = base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    return f"SHA256:{digest}"


def parse_ssh_keys(lines: list[str]) -> Section:
    out: Section = {}
    for line in lines:
        user, sep, keyline = line.partition("\t")
        if not sep:
            continue
        tokens = keyline.split()
        for i, tok in enumerate(tokens[:-1]):
            if _KEY_TYPE.match(tok):
                try:
                    fp = key_fingerprint(tokens[i + 1])
                except (binascii.Error, ValueError):
                    break
                out[f"{user}:{fp}"] = {
                    "user": user,
                    "type": tok,
                    "fingerprint": fp,
                    "comment": " ".join(tokens[i + 2 :]),
                    "options": " ".join(tokens[:i]),
                }
                break
    return out


def _split_hostport(local: str) -> tuple[str, str]:
    addr, _, port = local.rpartition(":")
    addr = addr.strip("[]")
    addr = addr.split("%", 1)[0]  # remove interface: 127.0.0.53%lo
    return addr, port


def parse_ports(lines: list[str], policy: Policy) -> Section:
    out: Section = {}
    for line in lines:
        fields = line.split()
        if len(fields) < 5:
            continue
        proto, local = fields[0], fields[4]
        addr, port = _split_hostport(local)
        if port in policy.ignore_ports or addr in policy.ignore_addresses:
            continue
        rest = " ".join(fields[6:])
        procs = sorted(set(re.findall(r'\("([^"]+)"', rest)))
        out[f"{proto}/{addr}:{port}"] = {"process": ",".join(procs) or "?"}
    return out


def parse_services(lines: list[str], policy: Policy) -> Section:
    out: Section = {}
    for line in lines:
        fields = line.split(None, 4)
        if len(fields) < 4 or fields[0] in policy.ignore_services:
            continue
        out[fields[0]] = {"description": fields[4] if len(fields) > 4 else ""}
    return out


def parse_suid(lines: list[str]) -> Section:
    return {line.strip(): {} for line in lines if line.strip()}


def parse_output(output: str, policy: Policy) -> tuple[dict[str, str], dict[str, Section | None]]:
    """Retorna (meta, seções). Seções não suportadas pelo host ficam como None."""
    raw = split_sections(output)
    meta = parse_meta(raw.pop("meta", []))
    parsers = {
        "files": parse_files,
        "users": parse_users,
        "groups": lambda lines: parse_groups(lines, policy.privileged_groups),
        "ssh_keys": parse_ssh_keys,
        "ports": lambda lines: parse_ports(lines, policy),
        "services": lambda lines: parse_services(lines, policy),
        "suid": parse_suid,
    }
    sections: dict[str, Section | None] = {}
    for name in policy.enabled:
        lines = raw.get(name, [])
        sections[name] = None if _unsupported(lines) else parsers[name](lines)

    if sections.get("users") is not None:
        for user in policy.ignore_users:
            sections["users"].pop(user, None)
    return meta, sections
