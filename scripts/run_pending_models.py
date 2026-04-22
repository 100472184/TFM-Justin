#!/usr/bin/env python3
"""Run pending CVE/model/level pipeline combinations safely.

Default mode is dry-run. Use --execute to make changes.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


LEVEL_ITERS = {
    "L3": 15,
    "L2": 30,
    "L1": 45,
    "L0": 50,
}

MODEL_SPECS = {
    "llama3-8b": "ollama/llama3:8b",
    "mistral-7b": "ollama/mistral:7b",
    "qwen2.5-7b": "ollama/qwen2.5:7b",
}

LEVEL_ORDER = ["L3", "L2", "L1", "L0"]
RUN_DIR_RE = re.compile(r"^\s*Run Dir:\s*(.+?)\s*$")
STATE_FILE = ".run_pending_models_state.json"


@dataclass(frozen=True)
class Combo:
    cve: str
    model_alias: str
    level: str
    max_iters: int
    model_spec: str


@dataclass(frozen=True)
class CmdResult:
    returncode: int
    output: str
    timed_out: bool


def log(msg: str) -> None:
    ts = dt.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


def run_cmd(
    args: list[str],
    cwd: Path,
    dry_run: bool,
    capture_output: bool = False,
    timeout_sec: int | None = None,
) -> CmdResult:
    cmd_text = " ".join(args)
    if dry_run:
        log(f"DRY-RUN cmd: {cmd_text}")
        return CmdResult(returncode=0, output="", timed_out=False)

    try:
        if capture_output:
            proc = subprocess.run(
                args,
                cwd=str(cwd),
                text=True,
                capture_output=True,
                check=False,
                timeout=timeout_sec,
            )
            if proc.stdout:
                print(proc.stdout, end="")
            if proc.stderr:
                print(proc.stderr, end="", file=sys.stderr)
            return CmdResult(returncode=proc.returncode, output=f"{proc.stdout}\n{proc.stderr}", timed_out=False)

        proc = subprocess.run(args, cwd=str(cwd), text=True, check=False, timeout=timeout_sec)
        return CmdResult(returncode=proc.returncode, output="", timed_out=False)
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout or ""
        stderr = e.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        if stdout:
            print(stdout, end="")
        if stderr:
            print(stderr, end="", file=sys.stderr)
        return CmdResult(returncode=124, output=f"{stdout}\n{stderr}", timed_out=True)


def require_repo_root(repo_root: Path) -> None:
    required = [
        repo_root / ".git",
        repo_root / "runs",
        repo_root / "agents" / "openhands_llm" / "run.py",
    ]
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        raise RuntimeError(f"No parece la raiz del repo. Faltan rutas: {missing}")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Ejecuta solo combinaciones pendientes CVE+modelo+nivel y normaliza resultados.",
    )
    p.add_argument(
        "--execute",
        action="store_true",
        help="Modo real (por defecto es dry-run).",
    )
    p.add_argument(
        "--cve",
        action="append",
        default=[],
        help="Filtrar por CVE concreta. Repetible.",
    )
    p.add_argument(
        "--model",
        action="append",
        choices=sorted(MODEL_SPECS.keys()),
        default=[],
        help="Filtrar por modelo alias. Repetible.",
    )
    p.add_argument(
        "--level",
        action="append",
        choices=LEVEL_ORDER,
        default=[],
        help="Filtrar por nivel. Repetible.",
    )
    p.add_argument(
        "--no-push",
        action="store_true",
        help="No hacer git push al final.",
    )
    p.add_argument(
        "--commit-message",
        default="chore(runs): add pending CVE model runs",
        help="Mensaje del commit final.",
    )
    p.add_argument(
        "--run-timeout-sec",
        type=int,
        default=3600,
        help="Timeout por run del pipeline en segundos (default: 3600).",
    )
    p.add_argument(
        "--abort-on-timeout",
        action="store_true",
        help="Aborta el batch completo al primer timeout.",
    )
    return p.parse_args()


def safe_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def list_cves(runs_root: Path) -> list[str]:
    out: list[str] = []
    for p in sorted(runs_root.iterdir()):
        if p.is_dir() and p.name.startswith("CVE-"):
            out.append(p.name)
    return out


def read_summary_from_run_dir(run_dir: Path, cve: str) -> dict | None:
    candidates = [run_dir / "summary.json", run_dir / cve / "summary.json"]
    for c in candidates:
        if c.is_file():
            try:
                return json.loads(c.read_text(encoding="utf-8"))
            except Exception:
                return None
    return None


def canonical_dest(runs_root: Path, cve: str, model_alias: str, level: str) -> Path:
    return runs_root / cve / model_alias / f"{level}_{cve}"


def find_existing_level_run(
    runs_root: Path,
    cve: str,
    model_alias: str,
    level: str,
    expected_model: str | None = None,
    expected_max_iters: int | None = None,
) -> tuple[bool, str]:
    model_dir = runs_root / cve / model_alias
    dest = canonical_dest(runs_root, cve, model_alias, level)
    if dest.is_dir():
        return True, f"exists-canonical:{dest.name}"
    if not model_dir.is_dir():
        return False, "model-dir-missing"

    for child in sorted(model_dir.iterdir()):
        if not child.is_dir():
            continue
        summary = read_summary_from_run_dir(child, cve)
        if not summary:
            continue
        if (
            summary.get("task_id") == cve
            and summary.get("level") == level
            and (expected_model is None or summary.get("model") == expected_model)
            and (expected_max_iters is None or summary.get("max_iters") == expected_max_iters)
            and has_min_run_structure(child, summary)
        ):
            return True, f"exists-legacy:{child.name}"
    return False, "pending"


def parse_run_dir_from_output(output: str) -> Path | None:
    found = None
    for line in output.splitlines():
        m = RUN_DIR_RE.match(line)
        if m:
            found = m.group(1).strip()
    if not found:
        return None
    return Path(found)


def has_min_run_structure(run_dir: Path, summary: dict[str, Any]) -> bool:
    """Run valida por estructura minima, independiente del oracle/success."""
    iter_dirs = [p for p in run_dir.iterdir() if p.is_dir() and p.name.startswith("iter_")] if run_dir.is_dir() else []
    total_iters = summary.get("total_iters")
    if not isinstance(total_iters, int) or total_iters < 0:
        return False
    # Compatible con CVEs especiales: una run puede fallar sin crash, pero debe persistir artefactos.
    if total_iters == 0:
        return (run_dir / "summary.json").is_file() or (run_dir / str(summary.get("task_id", "")) / "summary.json").is_file()
    return len(iter_dirs) >= 1


def validate_run_dir(run_dir: Path, cve: str, level: str, expected_model: str | None = None, expected_max_iters: int | None = None) -> tuple[bool, str]:
    summary = read_summary_from_run_dir(run_dir, cve)
    if not summary:
        return False, f"summary-missing-or-invalid:{run_dir}"
    required_keys = {"task_id", "level", "max_iters", "total_iters", "success", "timestamp"}
    missing = [k for k in required_keys if k not in summary]
    if missing:
        return False, f"summary-missing-keys:{missing}"
    if summary.get("task_id") != cve:
        return False, f"summary-task-mismatch:{summary.get('task_id')}"
    if summary.get("level") != level:
        return False, f"summary-level-mismatch:{summary.get('level')}"
    if expected_model and summary.get("model") != expected_model:
        return False, f"summary-model-mismatch:{summary.get('model')}"
    if expected_max_iters is not None and summary.get("max_iters") != expected_max_iters:
        return False, f"summary-max-iters-mismatch:{summary.get('max_iters')}"
    if not has_min_run_structure(run_dir, summary):
        return False, "summary-structure-invalid"
    return True, "ok"


def resolve_new_run_dir(
    repo_root: Path,
    combo: Combo,
    model_dir: Path,
    before_dirs: set[str],
    output: str,
) -> tuple[Path | None, str]:
    parsed = parse_run_dir_from_output(output)
    if parsed:
        run_dir = parsed if parsed.is_absolute() else (repo_root / parsed)
        if run_dir.is_dir():
            if run_dir.name in before_dirs:
                return None, f"parsed-dir-existed-before:{run_dir.name}"
            ok, why = validate_run_dir(
                run_dir,
                combo.cve,
                combo.level,
                expected_model=combo.model_spec,
                expected_max_iters=combo.max_iters,
            )
            if ok:
                return run_dir, "from-output"
            return None, why

    if not model_dir.is_dir():
        return None, "model-dir-missing-post-run"

    after_dirs = {p.name for p in model_dir.iterdir() if p.is_dir()}
    added = sorted(after_dirs - before_dirs)
    candidates: list[Path] = []
    for name in added:
        p = model_dir / name
        ok, _ = validate_run_dir(
            p,
            combo.cve,
            combo.level,
            expected_model=combo.model_spec,
            expected_max_iters=combo.max_iters,
        )
        if ok:
            candidates.append(p)

    if len(candidates) == 1:
        return candidates[0], "from-diff"
    if len(candidates) == 0:
        return None, "no-new-valid-run-dir"
    return None, f"ambiguous-new-run-dirs:{[c.name for c in candidates]}"


def ensure_tools(repo_root: Path, require_docker: bool) -> None:
    required_cmds = [["git", "--version"], ["python", "--version"]]
    if require_docker:
        required_cmds.append(["docker", "--version"])
    for cmd in required_cmds:
        proc = subprocess.run(cmd, cwd=str(repo_root), text=True, capture_output=True, check=False)
        if proc.returncode != 0:
            raise RuntimeError(f"Comando requerido no disponible: {' '.join(cmd)}")
    proc = subprocess.run(
        ["python", "-m", "agents.openhands_llm.run", "--help"],
        cwd=str(repo_root),
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError("No se puede invocar el pipeline: python -m agents.openhands_llm.run --help")


def ensure_repo_state_clean_for_batch(repo_root: Path, execute: bool) -> None:
    proc = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        cwd=str(repo_root),
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0 or proc.stdout.strip() != "true":
        raise RuntimeError("El directorio actual no es un repo git valido.")

    staged = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        cwd=str(repo_root),
        text=True,
        capture_output=True,
        check=False,
    )
    if staged.returncode != 0:
        raise RuntimeError("No se pudo inspeccionar staged changes.")
    staged_lines = [ln.strip() for ln in staged.stdout.splitlines() if ln.strip()]
    if execute and staged_lines:
        raise RuntimeError(
            "Hay cambios staged previos. Abortando por seguridad para evitar commit contaminado.\n"
            f"Staged detectados: {staged_lines[:20]}"
        )


def combo_key(combo: Combo) -> str:
    return f"{combo.cve}|{combo.model_alias}|{combo.level}"


def save_state(state_path: Path, data: dict[str, Any]) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_path.with_suffix(state_path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(state_path)


def update_combo_state(state: dict[str, Any], combo: Combo, status: str, detail: str) -> None:
    state.setdefault("combos", {})
    state["combos"][combo_key(combo)] = {
        "cve": combo.cve,
        "model_alias": combo.model_alias,
        "model_spec": combo.model_spec,
        "level": combo.level,
        "max_iters": combo.max_iters,
        "status": status,
        "detail": detail,
        "updated_at": dt.datetime.now().isoformat(timespec="seconds"),
    }


def task_exists(repo_root: Path, cve: str) -> bool:
    return (repo_root / "tasks" / cve / "task.yml").is_file()


def build_combos(
    runs_root: Path,
    cves_filter: set[str],
    models_filter: set[str],
    levels_filter: set[str],
) -> tuple[list[Combo], list[str]]:
    all_cves = list_cves(runs_root)
    selected_cves = [c for c in all_cves if not cves_filter or c in cves_filter]
    if cves_filter:
        unknown = sorted(cves_filter - set(all_cves))
    else:
        unknown = []

    models = [m for m in sorted(MODEL_SPECS.keys()) if not models_filter or m in models_filter]
    levels = [l for l in LEVEL_ORDER if not levels_filter or l in levels_filter]

    combos: list[Combo] = []
    for cve in selected_cves:
        for model_alias in models:
            for level in levels:
                combos.append(
                    Combo(
                        cve=cve,
                        model_alias=model_alias,
                        level=level,
                        max_iters=LEVEL_ITERS[level],
                        model_spec=MODEL_SPECS[model_alias],
                    )
                )
    return combos, unknown


def main() -> int:
    args = parse_args()
    dry_run = not args.execute
    repo_root = Path.cwd()
    runs_root = repo_root / "runs"

    try:
        require_repo_root(repo_root)
        ensure_tools(repo_root, require_docker=not dry_run)
        ensure_repo_state_clean_for_batch(repo_root, execute=not dry_run)
    except RuntimeError as e:
        log(f"ERROR preflight: {e}")
        return 2

    if args.run_timeout_sec <= 0:
        log("ERROR preflight: --run-timeout-sec debe ser > 0")
        return 2

    cves_filter = set(args.cve)
    models_filter = set(args.model)
    levels_filter = set(args.level)

    combos, unknown_cves = build_combos(runs_root, cves_filter, models_filter, levels_filter)
    if unknown_cves:
        log(f"WARNING CVEs no encontradas en runs/: {unknown_cves}")

    existing: list[tuple[Combo, str]] = []
    pending: list[Combo] = []
    for combo in combos:
        done, reason = find_existing_level_run(
            runs_root,
            combo.cve,
            combo.model_alias,
            combo.level,
            expected_model=combo.model_spec,
            expected_max_iters=combo.max_iters,
        )
        if done:
            existing.append((combo, reason))
        else:
            pending.append(combo)

    log(f"Modo: {'DRY-RUN' if dry_run else 'EJECUCION REAL'}")
    log(f"Total combinaciones inspeccionadas: {len(combos)}")
    log(f"Ya existentes: {len(existing)}")
    log(f"Pendientes a ejecutar: {len(pending)}")

    state_path = runs_root / STATE_FILE
    state: dict[str, Any] = {
        "session_id": dt.datetime.now().strftime("%Y%m%d_%H%M%S"),
        "started_at": dt.datetime.now().isoformat(timespec="seconds"),
        "mode": "dry-run" if dry_run else "execute",
        "args": vars(args),
        "level_iters": LEVEL_ITERS,
        "model_specs": MODEL_SPECS,
        "combos": {},
    }
    for combo, reason in existing:
        update_combo_state(state, combo, "existing", reason)
    for combo in pending:
        update_combo_state(state, combo, "pending", "not-started")
    save_state(state_path, state)

    staged_paths: list[str] = []
    executed_ok: list[Combo] = []
    failed: list[tuple[Combo, str]] = []
    skipped: list[tuple[Combo, str]] = []

    for combo in pending:
        model_dir = runs_root / combo.cve / combo.model_alias
        dest = canonical_dest(runs_root, combo.cve, combo.model_alias, combo.level)
        source_existed_before = False
        log(
            f"Pendiente -> CVE={combo.cve} model={combo.model_alias} "
            f"level={combo.level} max_iters={combo.max_iters}"
        )

        if dry_run:
            log(f"DRY-RUN plan: run + rename -> {dest}")
            cmd = (
                f"python -m agents.openhands_llm.run --task-id {combo.cve} --level {combo.level} "
                f"--max-iters {combo.max_iters} --model {combo.model_spec} "
                f"--kill-running-containers-after-iter"
            )
            log(f"DRY-RUN run-cmd: {cmd}")
            log(f"DRY-RUN mv: <new_run_dir> -> {dest}")
            log(f"DRY-RUN git add: git add -f -- {dest.relative_to(repo_root).as_posix()}")
            update_combo_state(state, combo, "planned", "dry-run")
            save_state(state_path, state)
            continue

        if not task_exists(repo_root, combo.cve):
            msg = f"task-missing: tasks/{combo.cve}/task.yml"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log(f"ERROR {msg}")
            continue

        model_dir.mkdir(parents=True, exist_ok=True)
        before_dirs = {p.name for p in model_dir.iterdir() if p.is_dir()}
        source_existed_before = dest.name in before_dirs

        cmd = [
            "python",
            "-m",
            "agents.openhands_llm.run",
            "--task-id",
            combo.cve,
            "--level",
            combo.level,
            "--max-iters",
            str(combo.max_iters),
            "--model",
            combo.model_spec,
            "--kill-running-containers-after-iter",
        ]
        update_combo_state(state, combo, "running", "launched")
        save_state(state_path, state)
        run_res = run_cmd(cmd, cwd=repo_root, dry_run=False, capture_output=True, timeout_sec=args.run_timeout_sec)
        output = run_res.output
        if run_res.timed_out:
            msg = f"pipeline-timeout:{args.run_timeout_sec}s"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log(f"ERROR {msg}")
            if args.abort_on_timeout:
                log("Abortando batch por --abort-on-timeout")
                break
            continue
        if run_res.returncode == 130:
            msg = "pipeline-interrupted-130"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log("ERROR pipeline devolvio 130 (interrupcion). Abortando batch.")
            break
        if run_res.returncode not in (0, 1):
            msg = f"pipeline-command-exit:{run_res.returncode}"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log(f"ERROR run command rc={run_res.returncode}")
            continue

        run_dir, src_reason = resolve_new_run_dir(repo_root, combo, model_dir, before_dirs, output)
        if not run_dir:
            msg = f"cannot-resolve-run-dir:{src_reason}"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log(f"ERROR no se pudo identificar run dir: {src_reason}")
            continue

        if not safe_relative_to(run_dir, model_dir):
            msg = f"unsafe-source-path:{run_dir}"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log("ERROR fuente fuera del directorio esperado, se aborta esta combinacion")
            continue

        if run_dir.resolve() == dest.resolve() and not source_existed_before:
            rel = dest.relative_to(repo_root).as_posix()
            add_res = run_cmd(["git", "add", "-f", "--", rel], cwd=repo_root, dry_run=False, capture_output=True)
            if add_res.returncode != 0:
                msg = f"git-add-failed:{rel}"
                failed.append((combo, msg))
                update_combo_state(state, combo, "failed", msg)
                save_state(state_path, state)
                log(f"ERROR git add fallo: {rel}")
                continue
            staged_paths.append(rel)
            executed_ok.append(combo)
            update_combo_state(state, combo, "staged", f"source-already-canonical:{rel}")
            save_state(state_path, state)
            log(f"OK source-already-canonical + git add -f {rel}")
            continue

        if dest.exists():
            skipped.append((combo, f"destination-exists:{dest.name}"))
            update_combo_state(state, combo, "skipped", f"destination-exists:{dest.name}")
            save_state(state_path, state)
            log(f"SKIP destino ya existe: {dest}")
            continue

        try:
            shutil.move(str(run_dir), str(dest))
            log(f"OK rename: {run_dir.name} -> {dest.name} ({src_reason})")
        except Exception as e:
            msg = f"rename-failed:{e}"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log(f"ERROR renombrado fallido: {e}")
            continue

        rel = dest.relative_to(repo_root).as_posix()
        add_res = run_cmd(["git", "add", "-f", "--", rel], cwd=repo_root, dry_run=False, capture_output=True)
        if add_res.returncode != 0:
            rollback_detail = "rollback-not-attempted"
            # Rollback best-effort to avoid partial state after move+add failure
            if safe_relative_to(dest, model_dir) and safe_relative_to(run_dir, model_dir) and dest.exists() and not run_dir.exists():
                try:
                    shutil.move(str(dest), str(run_dir))
                    rollback_detail = "rollback-ok"
                except Exception as rb_e:
                    rollback_detail = f"rollback-failed:{rb_e}"
            msg = f"git-add-failed:{rel}:{rollback_detail}"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log(f"ERROR git add fallo: {rel}")
            continue

        staged_paths.append(rel)
        executed_ok.append(combo)
        update_combo_state(state, combo, "staged", rel)
        save_state(state_path, state)
        log(f"OK git add -f {rel}")

    # Final summary (before commit/push)
    print("\n" + "=" * 78)
    print("RESUMEN")
    print("=" * 78)
    print(f"Modo: {'DRY-RUN' if dry_run else 'EJECUCION REAL'}")
    print(f"Inspeccionadas: {len(combos)}")
    print(f"Ya existentes: {len(existing)}")
    print(f"Pendientes: {len(pending)}")
    print(f"Ejecutadas OK: {len(executed_ok)}")
    print(f"Omitidas: {len(skipped)}")
    print(f"Fallidas: {len(failed)}")
    print(f"Staged paths: {len(staged_paths)}")

    if existing:
        print("\nYa existentes (muestra):")
        for combo, reason in existing[:12]:
            print(f"- {combo.cve} {combo.model_alias} {combo.level} [{reason}]")
        if len(existing) > 12:
            print(f"- ... ({len(existing) - 12} mas)")

    if skipped:
        print("\nOmitidas:")
        for combo, reason in skipped:
            print(f"- {combo.cve} {combo.model_alias} {combo.level} [{reason}]")

    if failed:
        print("\nFallidas:")
        for combo, reason in failed:
            print(f"- {combo.cve} {combo.model_alias} {combo.level} [{reason}]")

    if dry_run:
        print("\nComandos finales (dry-run):")
        print(f"- git commit -m \"{args.commit_message}\"")
        if args.no_push:
            print("- git push (omitido por --no-push)")
        else:
            print("- git push")
        print("\nDry-run completado. No se hicieron cambios.")
        state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        state["final_status"] = "dry-run-complete"
        save_state(state_path, state)
        return 0

    # No commit/push on severe errors
    if failed:
        print("\nSe detectaron fallos. Por seguridad NO se hara commit ni push.")
        state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        state["final_status"] = "failed-no-commit"
        save_state(state_path, state)
        return 1

    # Commit and push once at the end
    rc_diff = subprocess.run(
        ["git", "diff", "--cached", "--quiet"],
        cwd=str(repo_root),
        text=True,
        capture_output=True,
        check=False,
    ).returncode
    if rc_diff == 0:
        print("\nNo hay cambios staged. Se omite commit/push.")
        state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        state["final_status"] = "no-staged-changes"
        save_state(state_path, state)
        return 0

    staged_now = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        cwd=str(repo_root),
        text=True,
        capture_output=True,
        check=False,
    )
    if staged_now.returncode != 0:
        print("\nERROR: no se pudo leer staged final. Abortando commit.")
        state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        state["final_status"] = "failed-read-staged"
        save_state(state_path, state)
        return 1
    unexpected = []
    for p in [ln.strip() for ln in staged_now.stdout.splitlines() if ln.strip()]:
        if not p.startswith("runs/"):
            unexpected.append(p)
        if p == f"runs/{STATE_FILE}":
            unexpected.append(p)
    if unexpected:
        print("\nERROR: staged contiene rutas fuera de runs/. Abortando commit por seguridad.")
        print(f"Rutas inesperadas: {unexpected[:20]}")
        state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        state["final_status"] = "failed-contaminated-staged"
        save_state(state_path, state)
        return 1

    commit_res = run_cmd(
        ["git", "commit", "-m", args.commit_message],
        cwd=repo_root,
        dry_run=False,
        capture_output=True,
    )
    if commit_res.returncode != 0:
        print("\nERROR: fallo el commit final. Revisa estado y haz commit manual.")
        state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        state["final_status"] = "failed-commit"
        save_state(state_path, state)
        return 1

    if args.no_push:
        print("\nCommit final hecho. Push omitido por --no-push.")
        state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        state["final_status"] = "commit-only"
        save_state(state_path, state)
        return 0

    push_res = run_cmd(["git", "push"], cwd=repo_root, dry_run=False, capture_output=True)
    if push_res.returncode != 0:
        print("\nERROR: fallo el push final. El commit local quedo hecho.")
        state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        state["final_status"] = "failed-push"
        save_state(state_path, state)
        return 1

    print("\nCommit + push final completados.")
    state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
    state["final_status"] = "success"
    save_state(state_path, state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
