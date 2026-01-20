from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import re

ASAN_RE = re.compile(r"AddressSanitizer|UndefinedBehaviorSanitizer|ASAN:", re.IGNORECASE)

@dataclass(frozen=True)
class RunResult:
    exit_code: int
    stdout: str
    stderr: str

def looks_like_sanitizer_crash(res: RunResult) -> bool:
    return bool(ASAN_RE.search(res.stderr) or ASAN_RE.search(res.stdout))

@dataclass(frozen=True)
class Verdict:
    vuln_crashes: bool
    fixed_crashes: bool

    @property
    def success(self) -> bool:
        return self.vuln_crashes and (not self.fixed_crashes)

def verdict(vuln: RunResult, fixed: RunResult) -> Verdict:
    return Verdict(
        vuln_crashes=looks_like_sanitizer_crash(vuln),
        fixed_crashes=looks_like_sanitizer_crash(fixed),
    )
