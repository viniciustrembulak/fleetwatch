"""Saídas do scan: console, JSON e HTML."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape
from rich.console import Console
from rich.table import Table

from fleetwatch import __version__
from fleetwatch.diff import SEVERITIES, Finding, severity_rank

_COLORS = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

_CHANGE_LABEL = {"added": "novo", "removed": "removido", "changed": "alterado", "error": "erro"}


@dataclass
class HostResult:
    name: str
    address: str
    status: str  # ok | drift | error | no-baseline
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    meta: dict[str, str] = field(default_factory=dict)


@dataclass
class ScanReport:
    hosts: list[HostResult]
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    @property
    def findings(self) -> list[Finding]:
        return [f for h in self.hosts for f in h.findings]

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-severity_rank(f.severity), f.host, f.key))

    def summary(self) -> dict[str, Any]:
        statuses = Counter(h.status for h in self.hosts)
        severities = Counter(f.severity for f in self.findings)
        return {
            "hosts": len(self.hosts),
            "ok": statuses["ok"],
            "drift": statuses["drift"],
            "error": statuses["error"],
            "no_baseline": statuses["no-baseline"],
            "findings": {s: severities[s] for s in reversed(SEVERITIES)},
        }

    def max_severity(self) -> str | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=severity_rank)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "fleetwatch",
            "version": __version__,
            "generated_at": self.generated_at,
            "summary": self.summary(),
            "hosts": [
                {
                    "name": h.name,
                    "address": h.address,
                    "status": h.status,
                    "error": h.error,
                    "meta": h.meta,
                    "findings": [f.to_dict() for f in h.findings],
                }
                for h in self.hosts
            ],
        }


def _fmt(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        return ", ".join(f"{k}={_fmt(v)}" for k, v in value.items() if v not in ("", None, []))
    if isinstance(value, list):
        return ",".join(map(str, value))
    return str(value)


def _value(v: Any) -> str:
    if isinstance(v, list):
        return ",".join(map(str, v)) or "∅"
    if isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v):
        return v[:16] + "…"
    return str(v)


def _diff_pair(f: Finding) -> tuple[str | None, str | None]:
    """Antes/depois só com os campos que mudaram (para o HTML)."""
    before, after = f.before, f.after
    if isinstance(before, dict) and isinstance(after, dict):
        keys = [k for k in after if before.get(k) != after.get(k)]
        return (
            ", ".join(f"{k}={_value(before.get(k))}" for k in keys),
            ", ".join(f"{k}={_value(after.get(k))}" for k in keys),
        )

    def one(v: Any) -> str | None:
        if v is None:
            return None
        if isinstance(v, dict):
            parts = [f"{k}={_value(x)}" for k, x in v.items() if x not in ("", None)]
            return ", ".join(parts) or "presente"
        return _value(v)

    return one(before), one(after)


def _short(f: Finding) -> str:
    """Resumo de uma linha para o console; o JSON/HTML guardam o valor completo."""
    if f.detail:
        return f.detail
    value = f.after if f.after is not None else f.before
    if not isinstance(value, dict):
        return _fmt(value)
    if f.section == "ssh_keys":
        return f"{value.get('type', '')} {value.get('comment', '')}".strip()
    if f.section == "files":
        return f"{value['mode']} {value['owner']}:{value['group']} sha256={value['sha256'][:12]}…"
    if f.section == "users":
        return f"uid={value['uid']} shell={value['shell']}"
    return _fmt(value)


def print_console(report: ScanReport, console: Console | None = None) -> None:
    console = console or Console()

    hosts = Table(title="Hosts", title_justify="left", header_style="bold")
    hosts.add_column("Host")
    hosts.add_column("Endereço")
    hosts.add_column("Status")
    hosts.add_column("Desvios", justify="right")
    status_style = {"ok": "green", "drift": "red", "error": "magenta", "no-baseline": "yellow"}
    for h in report.hosts:
        hosts.add_row(
            h.name,
            h.address,
            f"[{status_style[h.status]}]{h.status}[/]",
            str(len(h.findings)) if h.status != "error" else "-",
        )
    console.print(hosts)

    if report.findings:
        table = Table(title="Desvios encontrados", title_justify="left", header_style="bold")
        table.add_column("Severidade")
        table.add_column("Host")
        table.add_column("Tipo")
        table.add_column("Mudança")
        table.add_column("Item", overflow="fold")
        table.add_column("Detalhe", overflow="fold")
        for f in report.sorted_findings():
            table.add_row(
                f"[{_COLORS[f.severity]}]{f.severity.upper()}[/]",
                f.host,
                f.title,
                _CHANGE_LABEL.get(f.change, f.change),
                f.key,
                _short(f),
            )
        console.print(table)

    s = report.summary()
    counts = " · ".join(f"{k}: {v}" for k, v in s["findings"].items() if v)
    console.print(
        f"\n[bold]{s['hosts']}[/] hosts · [green]{s['ok']} ok[/] · [red]{s['drift']} com desvio[/]"
        f" · [magenta]{s['error']} com erro[/]"
        + (f" · [yellow]{s['no_baseline']} sem baseline[/]" if s["no_baseline"] else "")
        + (f"\n{counts}" if counts else "")
    )


def write_json(report: ScanReport, path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n")


def write_html(report: ScanReport, path: str | Path) -> None:
    env = Environment(
        loader=PackageLoader("fleetwatch", "templates"),
        autoescape=select_autoescape(["html", "j2"]),
    )
    env.filters["diff_pair"] = _diff_pair
    template = env.get_template("report.html.j2")
    html = template.render(
        report=report,
        summary=report.summary(),
        change_label=_CHANGE_LABEL,
        version=__version__,
    )
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(html, encoding="utf-8")
