import pytest

from fleetwatch.config import ConfigError, expand_address, load_inventory, load_policy


def test_expand_single():
    assert expand_address("10.0.0.5") == ["10.0.0.5"]
    assert expand_address("pdv.local") == ["pdv.local"]


def test_expand_range():
    assert expand_address("172.28.0.11-13") == ["172.28.0.11", "172.28.0.12", "172.28.0.13"]


def test_expand_cidr_excludes_network_and_broadcast():
    assert expand_address("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]


@pytest.mark.parametrize("spec", ["10.0.0.20-10", "10.0.0.1-300", "10.0.0.0/33"])
def test_expand_invalid(spec):
    with pytest.raises(ConfigError):
        expand_address(spec)


def test_inventory_defaults_and_names(tmp_path):
    inv = tmp_path / "inv.yml"
    inv.write_text(
        "defaults: {user: auditor, become: true}\n"
        "hosts:\n"
        "  - {name: pdv, address: 10.0.0.1-2}\n"
        "  - {name: srv, address: 10.0.1.5, user: root, port: 2222}\n"
    )
    hosts = load_inventory(inv)
    assert [h.name for h in hosts] == ["pdv-01", "pdv-02", "srv"]
    assert hosts[0].user == "auditor" and hosts[0].become
    assert hosts[2].user == "root" and hosts[2].port == 2222


def test_inventory_rejects_duplicates(tmp_path):
    inv = tmp_path / "inv.yml"
    inv.write_text("hosts:\n  - {name: a, address: 10.0.0.1}\n  - {name: a, address: 10.0.0.2}\n")
    with pytest.raises(ConfigError, match="duplicados"):
        load_inventory(inv)


@pytest.mark.parametrize("pattern", ["/etc/x; rm -rf /", "/etc/$(id)", "relative/path", "/a b"])
def test_policy_rejects_unsafe_patterns(tmp_path, pattern):
    pol = tmp_path / "pol.yml"
    pol.write_text(f"files: [{pattern!r}]\n")
    with pytest.raises(ConfigError):
        load_policy(pol)


def test_policy_collectors_and_ignore(tmp_path):
    pol = tmp_path / "pol.yml"
    pol.write_text(
        "files: [/etc/passwd, /etc/cron.d/*]\n"
        "collectors: [files, ports]\n"
        "ignore: {ports: [68], addresses: [127.0.0.11]}\n"
    )
    policy = load_policy(pol)
    assert policy.enabled == ("files", "ports")
    assert policy.ignore_ports == ["68"]
