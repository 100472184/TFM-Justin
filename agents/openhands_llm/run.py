#!/usr/bin/env python3
"""
Entry point for the OpenHands LLM-based fuzzing pipeline.

This script orchestrates the complete ANALYZE → GENERATE → VERIFY loop using
OpenHands SDK with a local or remote LLM (e.g., LLaMA 3 via Ollama).

Usage:
    python -m agents.openhands_llm.run \
        --task-id CVE-2024-57970_libarchive \
        --level L3 \
        --max-iters 10 \
        --service target-vuln \
        --seed ./private_seeds/CVE-2024-57970_libarchive/seed.bin
"""

import argparse
import os
import sys
from pathlib import Path

from agents.openhands_llm.src.pipeline import run_pipeline
from agents.openhands_llm.src.io_utils import write_text, now_run_id


def main():
    parser = argparse.ArgumentParser(
        description="Run OpenHands LLM-based fuzzing pipeline"
    )
    parser.add_argument(
        "--task-id",
        required=True,
        help="CVE task identifier (e.g., CVE-2024-57970_libarchive)",
    )
    parser.add_argument(
        "--level",
        default="L3",
        choices=["L0", "L1", "L2", "L3"],
        help="Information level for the LLM (default: L3)",
    )
    parser.add_argument(
        "--max-iters",
        type=int,
        default=10,
        help="Maximum number of iterations (default: 10)",
    )
    parser.add_argument(
        "--service",
        default="target-vuln",
        help="Docker service to test (default: target-vuln)",
    )
    parser.add_argument(
        "--seed",
        type=str,
        default=None,
        help="Path to initial seed file (optional)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help=(
            "LLM model identifier (e.g., ollama/qwen2.5:7b, ollama/llama3.1:8b). "
            "Defaults to LLM_MODEL env var or vertex_ai/gemini-2.0-flash-001"
        ),
    )
    parser.add_argument(
        "--kill-running-containers-after-iter",
        action="store_true",
        help=(
            "Kill all running Docker containers after each iteration "
            "(equivalent to docker kill $(docker ps -q)). Disabled by default."
        ),
    )

    args = parser.parse_args()

    # Get repository root (assumes we're in agents/openhands_llm/)
    repo_root = Path(__file__).parent.parent.parent.resolve()

    # Resolve model for display
    effective_model = args.model or os.getenv("LLM_MODEL", "vertex_ai/gemini-2.0-flash-001")

    print(f"{'='*70}")
    print(f"OpenHands LLM-Based Fuzzing Pipeline")
    print(f"{'='*70}")
    print(f"Task ID:      {args.task_id}")
    print(f"Level:        {args.level}")
    print(f"Max Iters:    {args.max_iters}")
    print(f"Service:      {args.service}")
    print(f"Seed:         {args.seed or '(random)'}")
    print(f"Model:        {effective_model}")
    print(f"Kill Docker:  {args.kill_running_containers_after_iter}")
    print(f"Repo Root:    {repo_root}")
    print(f"{'='*70}\n")

    # Run the pipeline (Docker build/check happens inside pipeline)
    try:
        result = run_pipeline(
            repo_root=repo_root,
            task_id=args.task_id,
            level=args.level,
            max_iters=args.max_iters,
            seed_path=args.seed,
            service=args.service,
            model=args.model,
            kill_running_containers_after_iter=args.kill_running_containers_after_iter,
        )

        print(f"\n{'='*70}")
        print(f"Pipeline Finished")
        print(f"{'='*70}")
        print(f"Success:      {result['success']}")
        print(f"Iterations:   {result['iteration']}")
        print(f"Run Dir:      {result.get('run_dir', 'N/A')}")
        
        if result['success']:
            print(f"\n🎉 SUCCESS! Crash detected in iteration {result['iteration']}")
            return 0
        else:
            print(f"\n❌ No crash found after {result['iteration']} iterations")
            return 1

    except KeyboardInterrupt:
        print("\n\n⚠️  Pipeline interrupted by user")
        return 130
    except Exception as e:
        print(f"\n\n❌ Pipeline failed with error:")
        print(f"   {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
