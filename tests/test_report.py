import json

from fleetwatch.diff import Finding
from fleetwatch.notify import build_message
from fleetwatch.report import HostResult, ScanReport, write_html, write_json


def _report():
    finding = Finding(
        "pdv-02", "ports", "added", "tcp/0.0.0.0:4444", "high", None, {"process": "nc"}
    )
    return ScanReport(
        [
            HostResult("pdv-01", "10.0.0.1", "ok"),
            HostResult("pdv-02", "10.0.0.2", "drift", [finding]),
            HostResult("pdv-03", "10.0.0.3", "error", error="timeout"),
        ]
    )


def test_json_report(tmp_path):
    path = tmp_path / "r.json"
    write_json(_report(), path)
    data = json.loads(path.read_text())
    assert data["summary"]["drift"] == 1
    assert data["summary"]["findings"]["high"] == 1
    assert data["hosts"][1]["findings"][0]["title"] == "Porta em escuta"


def test_html_report_escapes_content(tmp_path):
    report = _report()
    report.hosts[1].findings[0].key = "<script>alert(1)</script>"
    path = tmp_path / "r.html"
    write_html(report, path)
    html = path.read_text()
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_notify_message_threshold():
    report = _report()
    msg = build_message(report, "high")
    assert "tcp/0.0.0.0:4444" in msg and "[ERRO] pdv-03" in msg
    assert "tcp/0.0.0.0:4444" not in build_message(report, "critical")
