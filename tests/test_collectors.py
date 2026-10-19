import subprocess

import pytest

from fleetwatch.collectors import build_script, key_fingerprint, parse_output, split_sections
from fleetwatch.config import Policy

ED25519 = "AAAAC3NzaC1lZDI1NTE5AAAAIJkfHSBEq35oAiCBFrMQFbQBK1g/N9w37CDb6AZbIo0M"

SAMPLE = f"""\
@@FW:meta@@
hostname=pdv-01
kernel=6.8.0
os=Debian GNU/Linux 12 (bookworm)
@@FW:files@@
{"a" * 64}\t644:root:root\t/etc/passwd
{"b" * 64}\t440:root:root\t/etc/sudoers
@@FW:users@@
root:x:0:0:root:/root:/bin/bash
auditor:x:1000:1000::/home/auditor:/bin/bash
@@FW:groups@@
root:x:0:
sudo:x:27:auditor,operador
users:x:100:
@@FW:ssh_keys@@
auditor\tssh-ed25519 {ED25519} lab
root\tfrom="10.0.0.1",no-pty ssh-ed25519 {ED25519} admin key
@@FW:ports@@
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=7,fd=3))
tcp   LISTEN 0      128             [::]:22           [::]:*    users:(("sshd",pid=7,fd=4))
tcp   LISTEN 0      4096      127.0.0.11:41231     0.0.0.0:*
udp   UNCONN 0      0      127.0.0.53%lo:53        0.0.0.0:*    users:(("systemd-resolve",pid=1,fd=1))
@@FW:services@@
@@FW:UNSUPPORTED@@
@@FW:suid@@
/usr/bin/passwd
/usr/bin/sudo
@@FW:END@@
"""


@pytest.fixture
def policy():
    p = Policy(files=["/etc/passwd"])
    p.ignore_addresses = ["127.0.0.11"]
    return p


def test_parse_full_output(policy):
    meta, s = parse_output(SAMPLE, policy)
    assert meta["hostname"] == "pdv-01"
    assert s["files"]["/etc/sudoers"] == {
        "sha256": "b" * 64,
        "mode": "440",
        "owner": "root",
        "group": "root",
    }
    assert s["users"]["auditor"]["uid"] == 1000
    assert s["groups"] == {
        "root": {"gid": 0, "members": []},
        "sudo": {"gid": 27, "members": ["auditor", "operador"]},
    }
    assert set(s["ports"]) == {"tcp/0.0.0.0:22", "tcp/:::22", "udp/127.0.0.53:53"}
    assert s["ports"]["tcp/0.0.0.0:22"] == {"process": "sshd"}
    assert s["services"] is None
    assert list(s["suid"]) == ["/usr/bin/passwd", "/usr/bin/sudo"]


def test_ssh_key_options_and_fingerprint(policy):
    _, s = parse_output(SAMPLE, policy)
    fp = key_fingerprint(ED25519)
    root_key = s["ssh_keys"][f"root:{fp}"]
    assert root_key["options"] == 'from="10.0.0.1",no-pty'
    assert root_key["comment"] == "admin key"
    assert fp.startswith("SHA256:") and not fp.endswith("=")


def test_fingerprint_matches_ssh_keygen(tmp_path):
    pub = tmp_path / "k.pub"
    pub.write_text(f"ssh-ed25519 {ED25519} x\n")
    try:
        out = subprocess.run(["ssh-keygen", "-lf", str(pub)], capture_output=True, text=True)
    except FileNotFoundError:
        pytest.skip("ssh-keygen indisponível")
    assert key_fingerprint(ED25519) in out.stdout


def test_incomplete_output_is_rejected():
    with pytest.raises(ValueError):
        split_sections("@@FW:meta@@\nhostname=x\n")


def test_script_runs_locally(policy, tmp_path):
    """O script gerado precisa ser sh válido e terminar com o marcador END."""
    target = tmp_path / "watched.conf"
    target.write_text("x")
    policy.files = [str(tmp_path / "*.conf")]
    policy.enabled = ("files", "users", "suid")
    policy.suid_paths = [str(tmp_path)]
    out = subprocess.run(["sh", "-s"], input=build_script(policy), capture_output=True, text=True)
    _, s = parse_output(out.stdout, policy)
    assert str(target) in s["files"]
    assert "root" in s["users"]
    assert s["suid"] == {}
