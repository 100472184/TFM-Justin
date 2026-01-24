from scripts.bench import _run_service
from pathlib import Path

vuln_r = _run_service(Path('tasks/CVE-2024-57970_libarchive'), 'target-vuln', Path('heap_of.tar'))
fixed_r = _run_service(Path('tasks/CVE-2024-57970_libarchive'), 'target-fixed', Path('heap_of.tar'))

print("="*60)
print("VULN RESULT")
print("="*60)
print(f"exit_code: {vuln_r.exit_code}")
print(f"stdout length: {len(vuln_r.stdout)}")
print(f"stderr length: {len(vuln_r.stderr)}")
print(f"has AddressSanitizer: {'AddressSanitizer' in vuln_r.stderr}")
print(f"has AddressSanitizer in stdout: {'AddressSanitizer' in vuln_r.stdout}")
print("\nFirst 500 chars of stderr:")
print(vuln_r.stderr[:500])
print("\nFirst 500 chars of stdout:")
print(vuln_r.stdout[:500])

print("\n" + "="*60)
print("FIXED RESULT")
print("="*60)
print(f"exit_code: {fixed_r.exit_code}")
print(f"stderr length: {len(fixed_r.stderr)}")
print(f"has AddressSanitizer: {'AddressSanitizer' in fixed_r.stderr}")
print("\nFirst 500 chars of stderr:")
print(fixed_r.stderr[:500])

from scripts.lib.oracle import verdict as make_verdict, looks_like_sanitizer_crash
print("\n" + "="*60)
print("ORACLE CHECKS")
print("="*60)
print(f"vuln looks_like_crash: {looks_like_sanitizer_crash(vuln_r)}")
print(f"fixed looks_like_crash: {looks_like_sanitizer_crash(fixed_r)}")
v = make_verdict(vuln_r, fixed_r)
print(f"\nVerdict: vuln_crashes={v.vuln_crashes}, fixed_crashes={v.fixed_crashes}, success={v.success}")
