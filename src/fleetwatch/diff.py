"""Compara um snapshot com a baseline e classifica cada desvio."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")

# (seção, tipo de mudança) -> severidade
_SEVERITY = {
    ("host_key", "changed"): "critical",
    ("ssh_keys", "added"): "critical",
    ("ssh_keys", "removed"): "low",
    ("ssh_keys", "changed"): "high",
    ("users", "added"): "high",
    ("users", "removed"): "medium",
    ("users", "changed"): "high",
    ("groups", "added"): "high",
    ("groups", "removed"): "medium",
    ("groups", "changed"): "high",
    ("files", "added"): "high",
    ("files", "removed"): "high",
    ("files", "changed"): "high",
    ("ports", "added"): "high",
    ("ports", "removed"): "medium",
    ("ports", "changed"): "high",
    ("services", "added"): "medium",
    ("services", "removed"): "medium",
    ("services", "changed"): "low",
    ("suid", "added"): "critical",
    ("suid", "removed"): "low",
}

_TITLES = {
    "host_key": "Chave SSH do host",
    "files": "Arquivo monitorado",
    "users": "Usuário",
    "groups": "Grupo privilegiado",
    "ssh_keys": "Chave autorizada (authorized_keys)",
    "ports": "Porta em escuta",
    "services": "Serviço systemd",
    "suid": "Binário SUID/SGID",
    "connectivity": "Coleta",
}


@dataclass
class Finding:
    host: str
    section: str
    change: str
    key: str
    severity: str
    before: Any = None
    after: Any = None
    detail: str = ""

    @property
    def title(self) -> str:
        return _TITLES.get(self.section, self.section)

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "title": self.title}


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)


def _escalate(section: str, change: str, before: Any, after: Any) -> tuple[str, str]:
    """Regras que tornam um desvio mais grave do que o padrão da tabela."""
    severity = _SEVERITY.get((section, change), "medium")
    detail = ""
    became_root = (
        isinstance(after, dict)
        and after.get("uid") == 0
        and not (isinstance(before, dict) and before.get("uid") == 0)
    )
    if section == "users" and became_root:
        severity, detail = "critical", "usuário com UID 0 (equivalente a root)"
    if section == "groups" and change == "changed" and before and after:
        added = sorted(set(after["members"]) - set(before["members"]))
        removed = sorted(set(before["members"]) - set(after["members"]))
        if added:
            detail = f"novos membros: {', '.join(added)}"
        elif removed:
            severity, detail = "low", f"membros removidos: {', '.join(removed)}"
    if section == "files" and change == "changed" and before and after:
        changed = [k for k in ("sha256", "mode", "owner", "group") if before.get(k) != after.get(k)]
        detail = "alterado: " + ", ".join("conteúdo" if k == "sha256" else k for k in changed)
    return severity, detail


def diff_section(host: str, section: str, before: dict, after: dict) -> list[Finding]:
    findings = []
    for key in sorted(after.keys() - before.keys()):
        sev, detail = _escalate(section, "added", None, after[key])
        findings.append(Finding(host, section, "added", key, sev, None, after[key], detail))
    for key in sorted(before.keys() - after.keys()):
        sev, detail = _escalate(section, "removed", before[key], None)
        findings.append(Finding(host, section, "removed", key, sev, before[key], None, detail))
    for key in sorted(before.keys() & after.keys()):
        if before[key] != after[key]:
            sev, detail = _escalate(section, "changed", before[key], after[key])
            findings.append(
                Finding(host, section, "changed", key, sev, before[key], after[key], detail)
            )
    return findings


def diff_snapshots(baseline: dict, current: dict) -> list[Finding]:
    host = current["host"]
    findings: list[Finding] = []

    if baseline.get("host_key") and baseline["host_key"] != current.get("host_key"):
        findings.append(
            Finding(
                host,
                "host_key",
                "changed",
                host,
                "critical",
                baseline["host_key"],
                current.get("host_key"),
                "possível MITM ou máquina substituída/reinstalada",
            )
        )

    base_sections = baseline.get("sections", {})
    for section, after in current.get("sections", {}).items():
        before = base_sections.get(section)
        # Seção ausente na baseline ou não suportada em um dos lados: nada a comparar.
        if before is None or after is None:
            continue
        findings.extend(diff_section(host, section, before, after))

    findings.sort(key=lambda f: (-severity_rank(f.severity), f.section, f.key))
    return findings
