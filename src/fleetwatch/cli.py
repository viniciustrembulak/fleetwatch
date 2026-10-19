"""Interface de linha de comando."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime

from rich.console import Console

from fleetwatch import __version__
from fleetwatch.collect import CollectResult, collect_all
from fleetwatch.config import ConfigError, Host, load_inventory, load_policy
from fleetwatch.diff import SEVERITIES, Finding, diff_snapshots, severity_rank
from fleetwatch.notify import send_webhook
from fleetwatch.report import HostResult, ScanReport, print_console, write_html, write_json
from fleetwatch.store import load_baseline, save_baseline

EXIT_OK, EXIT_DRIFT, EXIT_ERROR = 0, 1, 2

console = Console(stderr=True)


def _select_hosts(hosts: list[Host], names: list[str] | None) -> list[Host]:
    if not names:
        return hosts
    unknown = set(names) - {h.name for h in hosts}
    if unknown:
        raise ConfigError(f"hosts não encontrados no inventário: {', '.join(sorted(unknown))}")
    return [h for h in hosts if h.name in names]


def _progress(res: CollectResult) -> None:
    if res.error:
        console.print(f"  [magenta]✗[/] {res.host.name} ({res.host.address}): {res.error}")
    else:
        console.print(f"  [green]✓[/] {res.host.name} ({res.host.address})")


def cmd_inventory(args: argparse.Namespace) -> int:
    for h in load_inventory(args.inventory):
        sudo = " sudo" if h.become else ""
        print(f"{h.name}\t{h.user}@{h.address}:{h.port}{sudo}")
    return EXIT_OK


def cmd_baseline(args: argparse.Namespace) -> int:
    hosts = _select_hosts(load_inventory(args.inventory), args.host)
    policy = load_policy(args.policy)
    console.print(f"Coletando baseline de {len(hosts)} host(s)...")
    results = collect_all(hosts, policy, workers=args.workers, on_done=_progress)

    failed = 0
    for res in results:
        if res.snapshot is None:
            failed += 1
            continue
        save_baseline(args.baseline_dir, res.snapshot)
    console.print(
        f"\nBaseline salva para {len(results) - failed} host(s) em {args.baseline_dir}/"
        + (f" · [magenta]{failed} falha(s)[/]" if failed else "")
    )
    return EXIT_ERROR if failed else EXIT_OK


def cmd_scan(args: argparse.Namespace) -> int:
    hosts = _select_hosts(load_inventory(args.inventory), args.host)
    policy = load_policy(args.policy)
    console.print(f"Verificando {len(hosts)} host(s)...")
    results = collect_all(hosts, policy, workers=args.workers, on_done=_progress)
    console.print()

    host_results = []
    for res in results:
        h = res.host
        if res.snapshot is None:
            finding = Finding(h.name, "connectivity", "error", h.address, "high", detail=res.error)
            host_results.append(HostResult(h.name, h.address, "error", [finding], res.error))
            continue
        baseline = load_baseline(args.baseline_dir, h.name)
        if baseline is None:
            host_results.append(
                HostResult(h.name, h.address, "no-baseline", meta=res.snapshot["meta"])
            )
            continue
        findings = diff_snapshots(baseline, res.snapshot)
        host_results.append(
            HostResult(
                h.name,
                h.address,
                "drift" if findings else "ok",
                findings,
                meta=res.snapshot["meta"],
            )
        )

    report = ScanReport(host_results)
    print_console(report, Console())

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    if args.json:
        path = args.json.replace("{ts}", stamp)
        write_json(report, path)
        console.print(f"Relatório JSON: {path}")
    if args.html:
        path = args.html.replace("{ts}", stamp)
        write_html(report, path)
        console.print(f"Relatório HTML: {path}")
    if args.webhook:
        try:
            if send_webhook(args.webhook, report, args.notify_min):
                console.print("Alerta enviado para o webhook.")
        except OSError as exc:
            console.print(f"[magenta]Falha ao enviar webhook: {exc}[/]")

    worst = report.max_severity()
    if worst and severity_rank(worst) >= severity_rank(args.fail_on):
        return EXIT_DRIFT
    if any(h.status == "error" for h in host_results):
        return EXIT_ERROR
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fleetwatch",
        description="Monitor de integridade e desvio de configuração para frotas Linux via SSH.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-i", "--inventory", default="inventory.yml", help="inventário de hosts")
    common.add_argument("-p", "--policy", default="policy.yml", help="política de verificação")
    common.add_argument("-d", "--baseline-dir", default="baselines", help="diretório das baselines")
    common.add_argument("-w", "--workers", type=int, default=10, help="conexões em paralelo")
    common.add_argument("--host", action="append", help="limita a um host (pode repetir)")

    sub = parser.add_subparsers(dest="command", required=True)

    inv = sub.add_parser("inventory", help="lista os hosts do inventário já expandidos")
    inv.add_argument("-i", "--inventory", default="inventory.yml")
    inv.set_defaults(func=cmd_inventory)

    base = sub.add_parser(
        "baseline", parents=[common], help="registra o estado conhecido e confiável"
    )
    base.set_defaults(func=cmd_baseline)

    scan = sub.add_parser("scan", parents=[common], help="compara o estado atual com a baseline")
    scan.add_argument("--json", metavar="ARQ", help="salva relatório JSON ({ts} = data/hora)")
    scan.add_argument("--html", metavar="ARQ", help="salva relatório HTML ({ts} = data/hora)")
    scan.add_argument("--webhook", metavar="URL", help="envia alerta via POST JSON")
    scan.add_argument(
        "--notify-min",
        choices=SEVERITIES,
        default="high",
        help="severidade mínima para notificar (padrão: high)",
    )
    scan.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default="low",
        help="severidade mínima que faz o comando sair com código 1 (padrão: low)",
    )
    scan.set_defaults(func=cmd_scan)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as exc:
        console.print(f"[red]Erro de configuração:[/] {exc}")
        return EXIT_ERROR
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
