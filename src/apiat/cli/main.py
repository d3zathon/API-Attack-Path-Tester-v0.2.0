from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen

from rich.console import Console
from rich.table import Table

from apiat import __version__
from apiat.core.scanner import scan
from apiat.reporting.html_report import write_html
from apiat.reporting.json_report import write_json

console = Console()
PACKAGE_ROOT = Path(__file__).resolve().parents[3]


def _project_root() -> Path:
    """Find a source checkout when lab/demo commands are run from a cloned repo."""
    env_root = __import__("os").environ.get("APIAT_PROJECT_ROOT")
    if env_root:
        root = Path(env_root).expanduser().resolve()
        if (root / "docker-compose.yml").exists():
            return root
    current = Path.cwd().resolve()
    for candidate in (current, *current.parents):
        if (candidate / "docker-compose.yml").exists() and (candidate / "examples").exists():
            return candidate
    if (PACKAGE_ROOT / "docker-compose.yml").exists():
        return PACKAGE_ROOT
    raise RuntimeError("Lab/demo commands must be run from the APIAT repository (or set APIAT_PROJECT_ROOT).")


def _compose_command() -> list[str]:
    if shutil.which("docker"):
        result = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True)
        if result.returncode == 0:
            return ["docker", "compose"]
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    raise RuntimeError("Docker Compose was not found. Install Docker Desktop/Engine + Compose, then retry.")


def _run_compose(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    cmd = _compose_command() + args
    return subprocess.run(cmd, cwd=_project_root(), check=check, text=True)


def _wait_for_lab(url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urlopen(url.rstrip("/") + "/openapi.json", timeout=2) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError(f"Lab did not become ready at {url} within {timeout:.0f}s.")


def _print_result(result, report: str, html_report: str | None = None) -> None:
    table = Table("ID", "Type", "Severity", "Confidence", "Endpoint")
    for finding in result.findings:
        table.add_row(finding.id, finding.kind, finding.severity, finding.confidence, finding.endpoint)
    console.print(table)
    console.print(
        f"[bold]{len(result.findings)} verified findings[/bold] · "
        f"{len(result.attack_paths)} attack paths · {result.requests_sent} requests"
    )
    console.print(f"JSON report: {report}")
    if html_report:
        console.print(f"HTML report: {html_report}")


def _scan(args: argparse.Namespace) -> int:
    report = Path(args.report)
    html_report = Path(args.html) if args.html else None
    try:
        result = scan(args.spec, args.roles, args.base_url, args.seed, args.timeout, not args.insecure)
        write_json(result, str(report))
        if html_report:
            write_html(result, str(html_report))
        _print_result(result, str(report), str(html_report) if html_report else None)
        return 0
    except FileNotFoundError as exc:
        console.print(f"[red]File not found:[/red] {exc.filename}")
        return 2
    except ValueError as exc:
        console.print(f"[red]Invalid input:[/red] {exc}")
        return 2
    except RuntimeError as exc:
        console.print(f"[red]Scan failed:[/red] {exc}")
        return 2


def _lab_start(wait: bool = True) -> int:
    try:
        _run_compose(["up", "-d", "--build", "lab"])
        if wait:
            _wait_for_lab("http://127.0.0.1:8000")
        console.print("[green]Lab is running:[/green] http://127.0.0.1:8000/docs")
        return 0
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        console.print(f"[red]Unable to start lab:[/red] {exc}")
        return 2


def _lab_stop() -> int:
    try:
        _run_compose(["down"])
        console.print("[green]Lab stopped.[/green]")
        return 0
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        console.print(f"[red]Unable to stop lab:[/red] {exc}")
        return 2


def _lab_status() -> int:
    try:
        _run_compose(["ps"])
        return 0
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        console.print(f"[red]Unable to query lab:[/red] {exc}")
        return 2


def _demo(args: argparse.Namespace) -> int:
    if _lab_start() != 0:
        return 2
    report = Path(args.report)
    html_report = Path(args.html)
    try:
        result = scan(
            str(_project_root() / "examples" / "lab-openapi.yaml"),
            str(_project_root() / "examples" / "roles.yaml"),
            "http://127.0.0.1:8000",
            str(_project_root() / "examples" / "seed.yaml"),
            args.timeout,
            True,
        )
        write_json(result, str(report))
        write_html(result, str(html_report))
        console.print("\n[bold green]Demo complete.[/bold green]")
        _print_result(result, str(report), str(html_report))
        return 0
    except Exception as exc:
        console.print(f"[red]Demo failed:[/red] {exc}")
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apiat",
        description="Authorized API Attack-Path & Authorization Tester",
    )
    parser.add_argument("--version", action="version", version=f"apiat {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan", help="Run role-aware authorization tests against an OpenAPI-defined API")
    scan_parser.add_argument("spec", help="Path to OpenAPI JSON/YAML")
    scan_parser.add_argument("--base-url", required=True, help="Authorized target API base URL")
    scan_parser.add_argument("--roles", "--role", dest="roles", required=True, help="Path to roles YAML")
    scan_parser.add_argument("--seed", help="Optional seed/object identifiers YAML")
    scan_parser.add_argument("--report", default="reports/report.json", help="JSON report path")
    scan_parser.add_argument("--html", help="Optional HTML report path")
    scan_parser.add_argument("--timeout", type=float, default=10, help="Per-request timeout in seconds")
    scan_parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")

    lab = sub.add_parser("lab", help="Manage the deliberately vulnerable local lab")
    lab_sub = lab.add_subparsers(dest="lab_command", required=True)
    lab_sub.add_parser("start", help="Build and start the lab")
    lab_sub.add_parser("stop", help="Stop and remove the lab")
    lab_sub.add_parser("status", help="Show lab container status")

    demo = sub.add_parser("demo", help="Start the lab, scan it, and generate both reports")
    demo.add_argument("--report", default="reports/demo.json")
    demo.add_argument("--html", default="reports/demo.html")
    demo.add_argument("--timeout", type=float, default=10)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args)
    if args.command == "lab":
        return {"start": _lab_start, "stop": _lab_stop, "status": _lab_status}[args.lab_command]()
    if args.command == "demo":
        return _demo(args)
    parser.error("unknown command")
    return 2


def legacy_main() -> int:
    console.print("[yellow]Warning:[/yellow] `aapt` is kept only as a compatibility alias. Use `apiat` instead.")
    return main()


if __name__ == "__main__":
    raise SystemExit(main())
