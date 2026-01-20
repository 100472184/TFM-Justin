#!/usr/bin/env python3
"""
OpenHands LLM Pipeline Runner

Usage:
    python -m agents.openhands_llama3.run \\
        --task-id CVE-2023-4863_libwebp \\
        --level L3 \\
        --max-iters 10 \\
        --service target-vuln \\
        --seed path/to/seed.bin
"""

import sys
import argparse
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agents.openhands_llama3.src.pipeline import run_pipeline


def main():
    console = Console()
    
    parser = argparse.ArgumentParser(
        description="Run OpenHands LLM pipeline for CVE analysis and seed generation",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--task-id",
        required=True,
        help="CVE task ID (e.g., CVE-2023-4863_libwebp)"
    )
    
    parser.add_argument(
        "--level",
        default="L3",
        choices=["L0", "L1", "L2", "L3"],
        help="Information level (default: L3)"
    )
    
    parser.add_argument(
        "--max-iters",
        type=int,
        default=10,
        help="Maximum iterations (default: 10)"
    )
    
    parser.add_argument(
        "--service",
        default="target-vuln",
        choices=["target-vuln", "target-fixed"],
        help="Docker service to test (default: target-vuln)"
    )
    
    parser.add_argument(
        "--seed",
        type=Path,
        help="Initial seed file path (optional, will create random if not provided)"
    )
    
    args = parser.parse_args()
    
    # Auto-detect repository root
    repo_root = Path(__file__).parent.parent.parent
    
    # Validate task exists
    task_dir = repo_root / "tasks" / args.task_id
    if not task_dir.exists():
        console.print(f"[red]✗ Task not found:[/red] {args.task_id}", style="bold")
        console.print(f"[yellow]Available tasks in:[/yellow] {repo_root / 'tasks'}")
        sys.exit(1)
    
    # Convert seed path to absolute
    seed_path = args.seed.resolve() if args.seed else None
    
    # Display configuration
    config_table = Table(title="Pipeline Configuration", show_header=False)
    config_table.add_column("Parameter", style="cyan")
    config_table.add_column("Value", style="green")
    
    config_table.add_row("Task ID", args.task_id)
    config_table.add_row("Information Level", args.level)
    config_table.add_row("Max Iterations", str(args.max_iters))
    config_table.add_row("Service", args.service)
    config_table.add_row("Seed", str(seed_path) if seed_path else "[yellow]Random[/yellow]")
    
    console.print(config_table)
    console.print()
    
    # Run pipeline
    try:
        console.print("[bold cyan]Starting OpenHands LLM Pipeline...[/bold cyan]\n")
        
        result = run_pipeline(
            repo_root=repo_root,
            task_id=args.task_id,
            level=args.level,
            max_iters=args.max_iters,
            seed_path=seed_path,
            service=args.service
        )
        
        # Display results
        if result["success"]:
            console.print(Panel.fit(
                f"[bold green]✓ SUCCESS![/bold green]\n"
                f"Triggered vulnerability in iteration {result['iteration']}\n"
                f"Run directory: {result['run_dir']}",
                title="Pipeline Complete",
                border_style="green"
            ))
        else:
            console.print(Panel.fit(
                f"[bold yellow]⚠ No vulnerability triggered[/bold yellow]\n"
                f"Completed {result['iteration']} iterations\n"
                f"Run directory: {result['run_dir']}",
                title="Pipeline Complete",
                border_style="yellow"
            ))
        
        # Summary statistics
        stats_table = Table(title="Run Statistics", show_header=True)
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="magenta")
        
        stats_table.add_row("Total Iterations", str(result["iteration"]))
        stats_table.add_row("Success Signal", "Yes" if result["success"] else "No")
        stats_table.add_row("Run Directory", str(result["run_dir"]))
        
        console.print()
        console.print(stats_table)
        
        # Exit code
        sys.exit(0 if result["success"] else 1)
        
    except KeyboardInterrupt:
        console.print("\n[bold red]Pipeline interrupted by user[/bold red]")
        sys.exit(130)
        
    except Exception as e:
        console.print(f"\n[bold red]Pipeline failed:[/bold red] {e}", style="bold")
        import traceback
        console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
