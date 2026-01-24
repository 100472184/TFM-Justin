from scripts.bench import _run_service
from pathlib import Path

vuln_r = _run_service(Path('tasks/CVE-2024-57970_libarchive'), 'target-vuln', Path('heap_of.tar'))
fixed_r = _run_service(Path('tasks/CVE-2024-57970_libarchive'), 'target-fixed', Path('heap_of.tar'))

print(f"VULN: exit_code={vuln_r.exit_code}, has_asan={'AddressSanitizer' in vuln_r.stderr}")
print(f"FIXED: exit_code={fixed_r.exit_code}, has_asan={'AddressSanitizer' in fixed_r.stderr}")

from scripts.lib.oracle import verdict as make_verdict
v = make_verdict(vuln_r, fixed_r)
print(f"\nVerdict: vuln_crashes={v.vuln_crashes}, fixed_crashes={v.fixed_crashes}, success={v.success}")
