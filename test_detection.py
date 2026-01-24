import subprocess
import re
import sys

result = subprocess.run(
    [sys.executable, '-m', 'scripts.bench', 'run', 'CVE-2024-57970_libarchive', 
     '--service', 'target-vuln', '--seed', r'tasks\CVE-2024-57970_libarchive\seeds\base_truncated.tar'],
    capture_output=True,
    text=True,
    timeout=30
)

crash_keywords = re.compile(
    r'segmentation fault|dumped core|core dumped|SIGSEGV|SIGABRT|'
    r'heap-buffer-overflow|stack-buffer-overflow|use-after-free|double-free|'
    r'AddressSanitizer|UndefinedBehaviorSanitizer',
    re.IGNORECASE
)

combined = result.stdout + result.stderr
crashes = bool(crash_keywords.search(combined) or result.returncode in [139, 134, -11, -6])

print(f'Exit code: {result.returncode}')
print(f'Crashes detected: {crashes}')
print(f'\nKeyword match: {bool(crash_keywords.search(combined))}')
print(f'Exit code match: {result.returncode in [139, 134, -11, -6]}')
print(f'\n=== STDOUT ===')
print(result.stdout)
print(f'\n=== STDERR ===')
print(result.stderr)
