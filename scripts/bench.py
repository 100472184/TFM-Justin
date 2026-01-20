#!/usr/bin/env python3
from __future__ import annotations
import argparse
from pathlib import Path
from rich import print
from scripts.lib.utils import repo_root, die
from scripts.lib.task import load_task
from scripts.lib.docker import docker_compose, ensure_ok
from scripts.lib.oracle import RunResult, verdict

def tasks_root() -> Path:
    return repo_root() / "tasks"

def list_tasks() -> list[Path]:
    return sorted([p for p in tasks_root().iterdir() if p.is_dir() and (p / "task.yml").exists()])

def cmd_list(_args: argparse.Namespace) -> None:
    for t in list_tasks():
        meta = load_task(t)
        print(f"- {meta.task_id} ({meta.cve}, {meta.project})")

def cmd_build(args: argparse.Namespace) -> None:
    tdir = tasks_root() / args.task_id
    if not tdir.exists():
        die(f"Unknown task: {args.task_id}")
    out = docker_compose(tdir, ["build", "--no-cache"])
    ensure_ok(out, "docker compose build")
    print(f"[green]Built[/green] {args.task_id}")

def _run_service(tdir: Path, service: str, seed: Path) -> RunResult:
    # Mount seed into /input/seed.bin
    out = docker_compose(
        tdir,
        [
            "run", "--rm",
            "-v", f"{seed.resolve()}:/input/seed.bin:ro",
            service
        ],
    )
    return RunResult(exit_code=out.exit_code, stdout=out.stdout, stderr=out.stderr)

def cmd_run(args: argparse.Namespace) -> None:
    tdir = tasks_root() / args.task_id
    seed = Path(args.seed)
    if not seed.exists():
        die(f"Seed not found: {seed}")
    res = _run_service(tdir, args.service, seed)
    print("[bold]STDOUT[/bold]\n" + res.stdout)
    print("[bold]STDERR[/bold]\n" + res.stderr)
    print(f"[cyan]exit_code[/cyan]={res.exit_code}")

def cmd_evaluate(args: argparse.Namespace) -> None:
    tdir = tasks_root() / args.task_id
    seed = Path(args.seed)
    if not seed.exists():
        die(f"Seed not found: {seed}")
    v = _run_service(tdir, "target-vuln", seed)
    f = _run_service(tdir, "target-fixed", seed)
    ver = verdict(v, f)
    print(f"[bold]{args.task_id}[/bold] verdict: vuln_crashes={ver.vuln_crashes} fixed_crashes={ver.fixed_crashes} success={ver.success}")

def cmd_evaluate_all(args: argparse.Namespace) -> None:
    seeds_root = Path(args.seeds_root)
    if not seeds_root.exists():
        die(f"seeds_root not found: {seeds_root}")
    ok = 0
    total = 0
    for tdir in list_tasks():
        meta = load_task(tdir)
        # Expect seed file at <seeds_root>/<task_id>/seed.bin
        seed = seeds_root / meta.task_id / "seed.bin"
        if not seed.exists():
            print(f"[yellow]SKIP[/yellow] {meta.task_id} (missing seed: {seed})")
            continue
        total += 1
        v = _run_service(tdir, "target-vuln", seed)
        f = _run_service(tdir, "target-fixed", seed)
        ver = verdict(v, f)
        if ver.success:
            ok += 1
            print(f"[green]OK[/green] {meta.task_id}")
        else:
            print(f"[red]FAIL[/red] {meta.task_id} (vuln_crashes={ver.vuln_crashes}, fixed_crashes={ver.fixed_crashes})")
    print(f"\nSummary: {ok}/{total} successes (only tasks with seeds)")

def main() -> None:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("list")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("build")
    s.add_argument("task_id")
    s.set_defaults(func=cmd_build)

    s = sub.add_parser("run")
    s.add_argument("task_id")
    s.add_argument("--service", default="target-vuln", choices=["target-vuln", "target-fixed"])
    s.add_argument("--seed", required=True)
    s.set_defaults(func=cmd_run)

    s = sub.add_parser("evaluate")
    s.add_argument("task_id")
    s.add_argument("--seed", required=True)
    s.set_defaults(func=cmd_evaluate)

    s = sub.add_parser("evaluate-all")
    s.add_argument("--seeds-root", required=True)
    s.set_defaults(func=cmd_evaluate_all)

    args = p.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
