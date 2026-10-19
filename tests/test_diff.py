import copy

from fleetwatch.diff import diff_snapshots

BASE = {
    "host": "pdv-01",
    "host_key": "ssh-ed25519 SHA256:aaa",
    "sections": {
        "files": {
            "/etc/ssh/sshd_config": {"sha256": "1", "mode": "644", "owner": "root", "group": "root"}
        },
        "users": {"root": {"uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash"}},
        "groups": {"sudo": {"gid": 27, "members": ["auditor"]}},
        "ssh_keys": {},
        "ports": {"tcp/0.0.0.0:22": {"process": "sshd"}},
        "services": None,
        "suid": {"/usr/bin/sudo": {}},
    },
}


def _current():
    return copy.deepcopy(BASE)


def _by(findings):
    return {(f.section, f.change, f.key): f for f in findings}


def test_identical_snapshot_has_no_findings():
    assert diff_snapshots(BASE, _current()) == []


def test_detects_persistence_techniques():
    cur = _current()
    s = cur["sections"]
    s["files"]["/etc/ssh/sshd_config"]["sha256"] = "2"
    s["users"]["svc-backup"] = {"uid": 1001, "gid": 1001, "home": "/home/x", "shell": "/bin/bash"}
    s["groups"]["sudo"]["members"].append("svc-backup")
    s["ssh_keys"]["root:SHA256:evil"] = {"user": "root", "fingerprint": "SHA256:evil"}
    s["ports"]["tcp/0.0.0.0:4444"] = {"process": "nc"}
    s["suid"]["/var/tmp/.cache/.sh"] = {}

    f = _by(diff_snapshots(BASE, cur))
    assert f[("files", "changed", "/etc/ssh/sshd_config")].severity == "high"
    assert f[("files", "changed", "/etc/ssh/sshd_config")].detail == "alterado: conteúdo"
    assert f[("users", "added", "svc-backup")].severity == "high"
    assert f[("groups", "changed", "sudo")].detail == "novos membros: svc-backup"
    assert f[("ssh_keys", "added", "root:SHA256:evil")].severity == "critical"
    assert f[("ports", "added", "tcp/0.0.0.0:4444")].severity == "high"
    assert f[("suid", "added", "/var/tmp/.cache/.sh")].severity == "critical"


def test_findings_sorted_by_severity():
    cur = _current()
    cur["sections"]["suid"]["/tmp/x"] = {}
    cur["sections"]["ports"] = {}
    sevs = [f.severity for f in diff_snapshots(BASE, cur)]
    assert sevs == ["critical", "medium"]


def test_uid_zero_escalates_to_critical():
    cur = _current()
    cur["sections"]["users"]["toor"] = {"uid": 0, "gid": 0, "home": "/", "shell": "/bin/sh"}
    (finding,) = diff_snapshots(BASE, cur)
    assert finding.severity == "critical"
    assert "UID 0" in finding.detail


def test_host_key_change_is_critical():
    cur = _current()
    cur["host_key"] = "ssh-ed25519 SHA256:bbb"
    (finding,) = diff_snapshots(BASE, cur)
    assert (finding.section, finding.severity) == ("host_key", "critical")


def test_unsupported_section_is_skipped():
    cur = _current()
    cur["sections"]["services"] = {"evil.service": {"description": ""}}
    assert diff_snapshots(BASE, cur) == []
