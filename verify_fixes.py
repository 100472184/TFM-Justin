#!/usr/bin/env python3
"""Quick verification that pipeline fixes are working."""
from pathlib import Path

# Check base.tar exists
base_tar = Path("tasks/CVE-2024-57970_libarchive/seeds/base.tar")
print(f"✓ base.tar exists: {base_tar.exists()}")
print(f"  Size: {base_tar.stat().st_size if base_tar.exists() else 'N/A'} bytes")

# Check old run folder renamed
old_run = Path("runs/(borrar)_20260120_212114_CVE-2024-57970_libarchive")
print(f"\n✓ Old run folder renamed: {old_run.exists()}")

# Check pipeline.py has the fix
pipeline = Path("agents/openhands_llama3/src/pipeline.py")
content = pipeline.read_text(encoding='utf-8')

checks = {
    "seed_path None check": "if seed_path is None:" in content,
    "mutated_seed_itXX filename": 'f"mutated_seed_it{iteration:02d}.bin"' in content,
    "base.tar auto-load": 'base_seed = task_seeds_dir / "base.tar"' in content,
}

print("\n📋 Pipeline fixes:")
for name, passed in checks.items():
    status = "✓" if passed else "✗"
    print(f"  {status} {name}")

if all(checks.values()):
    print("\n✅ All fixes applied successfully!")
    print("\nReady to run:")
    print("  python -m agents.openhands_llama3.run --task-id CVE-2024-57970_libarchive --level L3 --max-iters 10")
else:
    print("\n❌ Some fixes are missing!")
