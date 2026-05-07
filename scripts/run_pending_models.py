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
import threading
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
DEFAULT_MAX_STAGE_FILE_MB = 90

# Baseline hardcodeada a partir del estado analizado previamente.
# Se usa para no depender de tener runs sincronizado en Kali.
HARDCODED_EXISTING_COMBOS: set[tuple[str, str, str]] = {
    ("CVE-2014-2525_libyaml", "llama3-8b", "L1"),
    ("CVE-2014-2525_libyaml", "llama3-8b", "L2"),
    ("CVE-2014-2525_libyaml", "llama3-8b", "L3"),
    ("CVE-2014-2525_libyaml", "llama3-8b", "L0"),
    ("CVE-2014-2525_libyaml", "mistral-7b", "L1"),
    ("CVE-2014-2525_libyaml", "mistral-7b", "L2"),
    ("CVE-2014-2525_libyaml", "mistral-7b", "L3"),
    ("CVE-2014-2525_libyaml", "mistral-7b", "L0"),
    ("CVE-2014-2525_libyaml", "qwen2.5-7b", "L1"),
    ("CVE-2014-2525_libyaml", "qwen2.5-7b", "L2"),
    ("CVE-2014-2525_libyaml", "qwen2.5-7b", "L3"),
    # Exclusion deliberada: CVE-2016-5314_libtiff
    # Ver runs/CVE-2016-5314_libtiff/reproduction_analysis.md
    # (repro no fiable en el setup actual; se evita seguir consumiendo runs).
    ("CVE-2016-5314_libtiff", "llama3-8b", "L3"),
    ("CVE-2016-5314_libtiff", "mistral-7b", "L3"),
    ("CVE-2016-5314_libtiff", "qwen2.5-7b", "L3"),
    ("CVE-2016-5314_libtiff", "llama3-8b", "L2"),
    ("CVE-2016-5314_libtiff", "mistral-7b", "L2"),
    ("CVE-2016-5314_libtiff", "qwen2.5-7b", "L2"),
    ("CVE-2016-5314_libtiff", "llama3-8b", "L1"),
    ("CVE-2016-5314_libtiff", "mistral-7b", "L1"),
    ("CVE-2016-5314_libtiff", "qwen2.5-7b", "L1"),
    ("CVE-2016-5314_libtiff", "llama3-8b", "L0"),
    ("CVE-2016-5314_libtiff", "mistral-7b", "L0"),
    ("CVE-2016-5314_libtiff", "qwen2.5-7b", "L0"),
    ("CVE-2016-9827_libming", "llama3-8b", "L3"),
    ("CVE-2016-9827_libming", "mistral-7b", "L3"),
    ("CVE-2016-9827_libming", "qwen2.5-7b", "L3"),
    ("CVE-2016-9827_libming", "llama3-8b", "L2"),
    ("CVE-2016-9827_libming", "mistral-7b", "L2"),
    ("CVE-2016-9827_libming", "qwen2.5-7b", "L2"),
    ("CVE-2021-32292_jsonc", "llama3-8b", "L3"),
    ("CVE-2021-32292_jsonc", "mistral-7b", "L3"),
    ("CVE-2021-32292_jsonc", "qwen2.5-7b", "L3"),
    ("CVE-2021-32292_jsonc", "llama3-8b", "L2"),
    ("CVE-2021-32292_jsonc", "mistral-7b", "L2"),
    ("CVE-2021-32292_jsonc", "qwen2.5-7b", "L2"),
    ("CVE-2022-24724_cmark-gfm", "llama3-8b", "L3"),
    ("CVE-2022-24724_cmark-gfm", "mistral-7b", "L3"),
    ("CVE-2022-24724_cmark-gfm", "qwen2.5-7b", "L3"),
    ("CVE-2022-24724_cmark-gfm", "llama3-8b", "L2"),
    # Exclusion deliberada: cmark-gfm con mistral deriva fuera de dominio (.md)
    ("CVE-2022-24724_cmark-gfm", "mistral-7b", "L2"),
    ("CVE-2022-24724_cmark-gfm", "mistral-7b", "L1"),
    ("CVE-2022-24724_cmark-gfm", "mistral-7b", "L0"),
    # Cuarentena: posible desalineacion seed/harness en L2 para qwen
    ("CVE-2022-24724_cmark-gfm", "qwen2.5-7b", "L2"),
    ("CVE-2022-4899_zstd", "llama3-8b", "L3"),
    # Cuarentena: comportamiento inconsistente en L2 (seed/path semantics)
    ("CVE-2022-4899_zstd", "llama3-8b", "L2"),
    ("CVE-2022-4899_zstd", "mistral-7b", "L2"),
    ("CVE-2022-4899_zstd", "qwen2.5-7b", "L2"),
    ("CVE-2023-29469_libxml2", "llama3-8b", "L3"),
    ("CVE-2023-29469_libxml2", "mistral-7b", "L3"),
    ("CVE-2023-29469_libxml2", "qwen2.5-7b", "L3"),
    ("CVE-2023-39804_gnutar", "llama3-8b", "L3"),
    ("CVE-2023-39804_gnutar", "llama3-8b", "L2"),
    ("CVE-2023-39804_gnutar", "mistral-7b", "L2"),
    ("CVE-2023-39804_gnutar", "qwen2.5-7b", "L2"),
    ("CVE-2023-39804_gnutar", "qwen2.5-7b", "L3"),
    ("CVE-2024-57970_libarchive", "llama3-8b", "L3"),
}


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
            # Stream stdout/stderr in real-time while also capturing them.
            proc = subprocess.Popen(
                args,
                cwd=str(cwd),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
            )
            stdout_chunks: list[str] = []
            stderr_chunks: list[str] = []

            def _pump(pipe, sink: list[str], to_stderr: bool = False) -> None:
                if pipe is None:
                    return
                try:
                    for line in iter(pipe.readline, ""):
                        sink.append(line)
                        if to_stderr:
                            print(line, end="", file=sys.stderr, flush=True)
                        else:
                            print(line, end="", flush=True)
                finally:
                    try:
                        pipe.close()
                    except Exception:
                        pass

            t_out = threading.Thread(target=_pump, args=(proc.stdout, stdout_chunks, False), daemon=True)
            t_err = threading.Thread(target=_pump, args=(proc.stderr, stderr_chunks, True), daemon=True)
            t_out.start()
            t_err.start()

            try:
                proc.wait(timeout=timeout_sec)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
                t_out.join(timeout=2)
                t_err.join(timeout=2)
                return CmdResult(returncode=124, output=f"{''.join(stdout_chunks)}\n{''.join(stderr_chunks)}", timed_out=True)
            except KeyboardInterrupt:
                # On Ctrl+C, terminate child and re-raise to caller.
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
                t_out.join(timeout=2)
                t_err.join(timeout=2)
                raise

            t_out.join(timeout=2)
            t_err.join(timeout=2)
            return CmdResult(
                returncode=proc.returncode if proc.returncode is not None else 1,
                output=f"{''.join(stdout_chunks)}\n{''.join(stderr_chunks)}",
                timed_out=False,
            )

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
    p.add_argument(
        "--max-stage-file-mb",
        type=int,
        default=DEFAULT_MAX_STAGE_FILE_MB,
        help=f"Tamanio maximo por archivo para git add en runs/ (default: {DEFAULT_MAX_STAGE_FILE_MB} MB).",
    )
    return p.parse_args()


def safe_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _chunks(items: list[str], n: int) -> list[list[str]]:
    return [items[i : i + n] for i in range(0, len(items), n)]


def stage_run_files_safely(
    repo_root: Path,
    run_path: Path,
    max_stage_file_mb: int,
    dry_run: bool,
) -> tuple[bool, str, list[str]]:
    if not run_path.exists():
        return False, "run-path-missing", []
    if not safe_relative_to(run_path, repo_root):
        return False, "unsafe-run-path", []

    max_bytes = max_stage_file_mb * 1024 * 1024
    files: list[Path] = []
    if run_path.is_file():
        files = [run_path]
    else:
        files = [p for p in run_path.rglob("*") if p.is_file()]

    if not files:
        return False, "run-path-has-no-files", []

    stageable: list[str] = []
    skipped_large: list[str] = []
    for f in files:
        try:
            size = f.stat().st_size
        except OSError:
            continue
        rel = f.relative_to(repo_root).as_posix()
        if size > max_bytes:
            skipped_large.append(rel)
        else:
            stageable.append(rel)

    if not stageable:
        return False, f"all-files-exceed-limit:{max_stage_file_mb}MB", []

    if skipped_large:
        log(
            f"WARNING se omiten {len(skipped_large)} archivo(s) > {max_stage_file_mb}MB para evitar rechazo en push."
        )
        for p in skipped_large[:6]:
            log(f"  omitiendo: {p}")
        if len(skipped_large) > 6:
            log(f"  ... y {len(skipped_large) - 6} mas")

    if dry_run:
        for chunk in _chunks(stageable, 120):
            log(f"DRY-RUN git add: git add -f -- {' '.join(chunk)}")
        return True, "staged-dry-run", stageable

    for chunk in _chunks(stageable, 120):
        add_res = run_cmd(["git", "add", "-f", "--", *chunk], cwd=repo_root, dry_run=False, capture_output=True)
        if add_res.returncode != 0:
            return False, "git-add-failed", []
    return True, "staged", stageable


def list_cves(runs_root: Path) -> list[str]:
    """Discover CVEs from both runs/ and tasks/ directories.

    On Kali the runs/ tree may not have all CVE dirs yet, so we also
    scan tasks/ to pick up every CVE that has a valid task.yml
    (excluding *_DISCARDED folders).
    """
    cves: set[str] = set()
    tasks_root = runs_root.parent / "tasks"
    # From runs/  (only if the CVE also has a valid task.yml)
    if runs_root.is_dir():
        for p in runs_root.iterdir():
            if p.is_dir() and p.name.startswith("CVE-"):
                if tasks_root.is_dir() and (tasks_root / p.name / "task.yml").is_file():
                    cves.add(p.name)
    if tasks_root.is_dir():
        for p in tasks_root.iterdir():
            if (
                p.is_dir()
                and p.name.startswith("CVE-")
                and "DISCARDED" not in p.name
                and (p / "task.yml").is_file()
            ):
                cves.add(p.name)
    return sorted(cves)


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


def has_partial_run_structure(run_dir: Path) -> bool:
    """
    Best-effort structure check for partially persisted runs when summary is missing/corrupted.
    """
    if not run_dir.is_dir():
        return False
    iter_dirs = [p for p in run_dir.iterdir() if p.is_dir() and p.name.startswith("iter_")]
    if not iter_dirs:
        return False
    for it in iter_dirs:
        if (it / "generate.json").is_file() or (it / "verify.json").is_file() or (it / "analysis.json").is_file():
            return True
    return False


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
            if has_partial_run_structure(run_dir):
                return run_dir, f"from-output-partial:{why}"
            return None, why

    if not model_dir.is_dir():
        return None, "model-dir-missing-post-run"

    after_dirs = {p.name for p in model_dir.iterdir() if p.is_dir()}
    added = sorted(after_dirs - before_dirs)
    candidates: list[Path] = []
    partial_candidates: list[tuple[Path, str]] = []
    for name in added:
        p = model_dir / name
        ok, why = validate_run_dir(
            p,
            combo.cve,
            combo.level,
            expected_model=combo.model_spec,
            expected_max_iters=combo.max_iters,
        )
        if ok:
            candidates.append(p)
            continue
        if has_partial_run_structure(p):
            partial_candidates.append((p, why))

    if len(candidates) == 1:
        return candidates[0], "from-diff"
    if len(candidates) == 0:
        if len(partial_candidates) == 1:
            p, why = partial_candidates[0]
            return p, f"from-diff-partial:{why}"
        if len(partial_candidates) > 1:
            return None, f"ambiguous-partial-run-dirs:{[c[0].name for c in partial_candidates]}"
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


def combo_in_hardcoded_baseline(combo: Combo) -> bool:
    return (combo.cve, combo.model_alias, combo.level) in HARDCODED_EXISTING_COMBOS


def classify_pipeline_failure(output: str) -> str | None:
    """
    Classify known pipeline failures from stdout/stderr text.
    Returns a short failure code or None if not recognized.
    """
    text = (output or "").lower()
    if "failed to solve" in text or "did not complete successfully: exit code" in text:
        return "pipeline-build-failed"
    if "error: build failed" in text or "docker compose build" in text and "failed" in text:
        return "pipeline-build-failed"
    if "images not ready" in text:
        return "pipeline-images-not-ready"
    if "seed file not found" in text:
        return "pipeline-seed-not-found"
    if "oci runtime create failed" in text or "failed to create shim task" in text:
        return "pipeline-container-start-failed"
    if "permission denied: unknown" in text:
        return "pipeline-container-permission-denied"
    return None


def detect_run_anomalies(output: str) -> list[str]:
    """
    Detect suspicious runtime behaviors that should be manually reviewed,
    even when the run produced/staged artifacts.
    """
    text = (output or "").lower()
    anomalies: list[str] = []

    def add(code: str) -> None:
        if code not in anomalies:
            anomalies.append(code)

    # Seed/harness semantic mismatches
    if "seed contains nul byte" in text or "use text argument seeds for this task" in text:
        add("seed-nul-rejected")
    if "seed not found at" in text:
        add("harness-seed-not-found")
    if "target binary not found or not executable" in text:
        add("harness-target-not-executable")

    # Container runtime errors that can still leave partial artifacts
    if "oci runtime create failed" in text or "failed to create shim task" in text:
        add("container-runtime-create-failed")
    if "permission denied: unknown" in text:
        add("container-permission-denied")

    # Keep this focused: transient LLM parse/mutation retries are intentionally ignored.
    return anomalies


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

    # Global priority order: all L3 first, then all L2, then L1, then L0.
    combos: list[Combo] = []
    for level in levels:
        for cve in selected_cves:
            for model_alias in models:
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
            if combo_in_hardcoded_baseline(combo):
                existing.append((combo, "exists-hardcoded-baseline"))
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
    anomalous: list[tuple[Combo, list[str], str]] = []

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
            sys.executable,
            "-u",
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
        try:
            run_res = run_cmd(cmd, cwd=repo_root, dry_run=False, capture_output=True, timeout_sec=args.run_timeout_sec)
        except KeyboardInterrupt:
            msg = "keyboard-interrupt-during-run"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log("Interrupcion manual detectada (Ctrl+C). Abortando batch de forma segura.")
            break
        output = run_res.output
        run_anomalies = detect_run_anomalies(output)
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
            classified = classify_pipeline_failure(output)
            if classified:
                msg = classified
            else:
                msg = f"cannot-resolve-run-dir:{src_reason}"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log(f"ERROR no se pudo identificar run dir: {src_reason}")
            continue

        if "partial" in src_reason:
            if "run-dir-partial" not in run_anomalies:
                run_anomalies.append("run-dir-partial")
            if "summary-missing-or-invalid" in src_reason and "summary-missing-or-invalid" not in run_anomalies:
                run_anomalies.append("summary-missing-or-invalid")

        if not safe_relative_to(run_dir, model_dir):
            msg = f"unsafe-source-path:{run_dir}"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log("ERROR fuente fuera del directorio esperado, se aborta esta combinacion")
            continue

        if run_dir.resolve() == dest.resolve() and not source_existed_before:
            rel = dest.relative_to(repo_root).as_posix()
            ok_stage, stage_reason, staged_rel_files = stage_run_files_safely(
                repo_root=repo_root,
                run_path=dest,
                max_stage_file_mb=args.max_stage_file_mb,
                dry_run=False,
            )
            if not ok_stage:
                msg = f"git-add-failed:{rel}:{stage_reason}"
                failed.append((combo, msg))
                update_combo_state(state, combo, "failed", msg)
                save_state(state_path, state)
                log(f"ERROR git add fallo: {rel}")
                continue
            staged_paths.extend(staged_rel_files)
            executed_ok.append(combo)
            if run_anomalies:
                anomalous.append((combo, run_anomalies, rel))
                update_combo_state(state, combo, "staged-anomalous", f"{rel}|{','.join(run_anomalies)}")
                log(f"WARNING run staged con comportamiento anomalo: {combo.cve} {combo.model_alias} {combo.level} -> {run_anomalies}")
            else:
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
        ok_stage, stage_reason, staged_rel_files = stage_run_files_safely(
            repo_root=repo_root,
            run_path=dest,
            max_stage_file_mb=args.max_stage_file_mb,
            dry_run=False,
        )
        if not ok_stage:
            rollback_detail = "rollback-not-attempted"
            # Rollback best-effort to avoid partial state after move+add failure
            if safe_relative_to(dest, model_dir) and safe_relative_to(run_dir, model_dir) and dest.exists() and not run_dir.exists():
                try:
                    shutil.move(str(dest), str(run_dir))
                    rollback_detail = "rollback-ok"
                except Exception as rb_e:
                    rollback_detail = f"rollback-failed:{rb_e}"
            msg = f"git-add-failed:{rel}:{stage_reason}:{rollback_detail}"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log(f"ERROR git add fallo: {rel}")
            continue

        staged_paths.extend(staged_rel_files)
        executed_ok.append(combo)
        if run_anomalies:
            anomalous.append((combo, run_anomalies, rel))
            update_combo_state(state, combo, "staged-anomalous", f"{rel}|{','.join(run_anomalies)}")
            log(f"WARNING run staged con comportamiento anomalo: {combo.cve} {combo.model_alias} {combo.level} -> {run_anomalies}")
        else:
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
    print(f"Anomalas (staged): {len(anomalous)}")
    print(f"Omitidas: {len(skipped)}")
    print(f"Fallidas: {len(failed)}")
    print(f"Staged paths: {len(staged_paths)}")

    if executed_ok:
        print(f"\nCompletadas y staged ({len(executed_ok)}):")
        for combo in executed_ok:
            dest = canonical_dest(runs_root, combo.cve, combo.model_alias, combo.level)
            rel = dest.relative_to(repo_root).as_posix() if safe_relative_to(dest, repo_root) else str(dest)
            print(f"  ✔ {combo.cve} {combo.model_alias} {combo.level} -> {rel}")

    if existing:
        print(f"\nYa existentes (muestra):")
        for combo, reason in existing[:12]:
            print(f"- {combo.cve} {combo.model_alias} {combo.level} [{reason}]")
        if len(existing) > 12:
            print(f"- ... ({len(existing) - 12} mas)")

    if skipped:
        print("\nOmitidas:")
        for combo, reason in skipped:
            print(f"- {combo.cve} {combo.model_alias} {combo.level} [{reason}]")

    if anomalous:
        print("\nAnomalas (revisar antes de commit):")
        for combo, codes, rel in anomalous:
            print(f"- {combo.cve} {combo.model_alias} {combo.level} [{','.join(codes)}] -> {rel}")

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

    # Ctrl+C outside subprocess or interrupcion general
    if failed and any(reason == "keyboard-interrupt-during-run" for _, reason in failed):
        print("\nEjecucion interrumpida por usuario. NO se hara commit/push automatico.")
        if executed_ok:
            print(f"\n  ℹ {len(executed_ok)} run(s) completada(s) y staged antes de la interrupcion.")
            if anomalous:
                print(f"  WARNING: {len(anomalous)} run(s) staged con comportamiento anomalo: revisar/limpiar antes de commit.")
            print("  Puedes hacer commit manual con:")
            print(f'    git commit -m "{args.commit_message}"')
        else:
            print("\n  No habia runs completadas antes de la interrupcion.")
        state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        state["final_status"] = "interrupted-by-user"
        save_state(state_path, state)
        return 130

    # No commit/push on severe errors
    if failed:
        print("\nSe detectaron fallos. Por seguridad NO se hara commit ni push.")
        state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        state["final_status"] = "failed-no-commit"
        save_state(state_path, state)
        return 1

    # If anomalous runs were staged, force manual review before commit/push.
    if anomalous:
        print("\nSe detectaron runs anomalas ya staged. Se omite commit/push automatico para revision manual.")
        print("Revisa estas rutas y, si procede, retira del stage antes de commitear:")
        print("  git restore --staged <ruta>")
        state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        state["final_status"] = "anomalous-no-auto-commit"
        save_state(state_path, state)
        return 3

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
