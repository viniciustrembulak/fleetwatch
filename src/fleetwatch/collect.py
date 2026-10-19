"""Conexão SSH e coleta de snapshots em paralelo."""

from __future__ import annotations

import base64
import hashlib
import os
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import paramiko

from fleetwatch.collectors import build_script, parse_output
from fleetwatch.config import Host, Policy


class CollectionError(Exception):
    pass


@dataclass
class CollectResult:
    host: Host
    snapshot: dict[str, Any] | None = None
    error: str | None = None


class _AcceptAndRecord(paramiko.MissingHostKeyPolicy):
    """Aceita a chave do host; a verificação real é feita contra a baseline (TOFU)."""

    def missing_host_key(self, client, hostname, key):  # noqa: D102
        return


def _fingerprint(key: paramiko.PKey) -> str:
    digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
    return f"{key.get_name()} SHA256:{digest}"


def run_remote(host: Host, script: str) -> tuple[str, str]:
    """Executa o script no host. Retorna (stdout, fingerprint da chave do host)."""
    client = paramiko.SSHClient()
    if host.known_hosts:
        client.load_host_keys(os.path.expanduser(host.known_hosts))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(_AcceptAndRecord())

    try:
        client.connect(
            hostname=host.address,
            port=host.port,
            username=host.user,
            key_filename=os.path.expanduser(host.key_file) if host.key_file else None,
            timeout=host.timeout,
            banner_timeout=host.timeout,
            auth_timeout=host.timeout,
            look_for_keys=host.key_file is None,
        )
        host_key = _fingerprint(client.get_transport().get_remote_server_key())

        command = "sudo -n /bin/sh -s" if host.become else "/bin/sh -s"
        stdin, stdout, stderr = client.exec_command(command, timeout=max(host.timeout, 60))
        stdin.write(script)
        stdin.channel.shutdown_write()
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace").strip()
        status = stdout.channel.recv_exit_status()
        if status != 0 and "@@FW:END@@" not in out:
            raise CollectionError(err or f"script remoto saiu com código {status}")
        return out, host_key
    except (paramiko.SSHException, OSError) as exc:
        raise CollectionError(f"{type(exc).__name__}: {exc}") from exc
    finally:
        client.close()


def collect_host(host: Host, policy: Policy, script: str) -> CollectResult:
    try:
        output, host_key = run_remote(host, script)
        meta, sections = parse_output(output, policy)
    except (CollectionError, ValueError) as exc:
        return CollectResult(host, error=str(exc))

    snapshot = {
        "host": host.name,
        "address": host.address,
        "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "meta": meta,
        "host_key": host_key,
        "sections": sections,
    }
    return CollectResult(host, snapshot=snapshot)


def collect_all(
    hosts: Iterable[Host],
    policy: Policy,
    workers: int = 10,
    on_done: Callable[[CollectResult], None] | None = None,
) -> list[CollectResult]:
    script = build_script(policy)
    hosts = list(hosts)
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(collect_host, h, policy, script) for h in hosts]
        results = []
        for fut in futures:
            res = fut.result()
            if on_done:
                on_done(res)
            results.append(res)
    return results
