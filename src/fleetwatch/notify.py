"""Envio de alertas para um webhook HTTP (Slack, Discord, n8n, etc.)."""

from __future__ import annotations

import json
import urllib.request

from fleetwatch.diff import severity_rank
from fleetwatch.report import ScanReport


def build_message(report: ScanReport, min_severity: str) -> str | None:
    threshold = severity_rank(min_severity)
    relevant = [f for f in report.findings if severity_rank(f.severity) >= threshold]
    errors = [h for h in report.hosts if h.status == "error"]
    if not relevant and not errors:
        return None

    lines = [f"fleetwatch: {len(relevant)} desvio(s) em {len({f.host for f in relevant})} host(s)"]
    for f in relevant[:20]:
        lines.append(f"[{f.severity.upper()}] {f.host} · {f.title} {f.change}: {f.key}")
    if len(relevant) > 20:
        lines.append(f"... e mais {len(relevant) - 20}")
    for h in errors:
        lines.append(f"[ERRO] {h.name} ({h.address}): {h.error}")
    return "\n".join(lines)


def send_webhook(url: str, report: ScanReport, min_severity: str, timeout: float = 10) -> bool:
    """Envia o alerta. Retorna False se não havia nada para notificar."""
    text = build_message(report, min_severity)
    if text is None:
        return False
    # "text" é lido por Slack/Mattermost, "content" pelo Discord; o resto vai para automações.
    payload = {"text": text, "content": text[:2000], "report": report.to_dict()}
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "fleetwatch"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        resp.read()
    return True
