# Tasks Audit: Seed/Restriction Consistency (2026-05-08)

## Scope
- Audited every folder under `tasks/` (including `_DISCARDED`).
- Cross-checked `task.yml`, `harness/run.sh`, seed inventory, and pipeline seed-selection behavior.
- Focused on restrictions that can prevent true CVE trigger conditions.

## Global Findings
1. `vertex_ai/*` runs can fail hard when `LLM_BASE_URL`/`OLLAMA_*` leaks into Vertex config (Invalid port error).
2. Text-semantics tasks (`CVE-2022-4899_zstd`, `CVE-2025-49014_jq`) are sensitive to seed extension and NUL handling.
3. Some non-discarded task directories are incomplete (missing `task.yml` / `harness`), causing silent exclusion from automation.
4. `CVE-2016-9827_libming` has no default seed file in `seeds/`; pipeline falls back to synthetic bytes.
5. Prompt mutation catalogue is global and cross-domain, which increases off-format mutations for domain-specific tasks.

## High-Risk Items
- `CVE-2016-9827_libming`
  - HIGH: no default seed found; pipeline fallback is synthetic bytes
- `CVE-2020-15999_freetype_DISCARDED`
  - HIGH: no default seed found; pipeline fallback is synthetic bytes
- `CVE-2022-23852_expat_DISCARDED`
  - HIGH: no default seed found; pipeline fallback is synthetic bytes
- `CVE-2022-23990_expat_DISCARDED`
  - HIGH: no default seed found; pipeline fallback is synthetic bytes
- `CVE-2023-2157_imagemagick`
  - HIGH: non-discarded task missing task.yml (excluded from auto-run)
- `CVE-2023-2157_imagemagick_DISCARDED`
  - HIGH: no default seed found; pipeline fallback is synthetic bytes
- `CVE-2023-4863_libwebp_DISCARDED`
  - HIGH: no default seed found; pipeline fallback is synthetic bytes
- `CVE-2023-50268_jq_DISCARDED`
  - HIGH: no default seed found; pipeline fallback is synthetic bytes
- `CVE-2024-25062_libxml2`
  - HIGH: non-discarded task missing task.yml (excluded from auto-run)
- `CVE-2024-4323_fluentbit`
  - HIGH: non-discarded task missing task.yml (excluded from auto-run)

## Task-by-Task Matrix
| Task | Discarded | task.yml | harness | Default Seed | ARG_FROM_SEED | Harness text-seed | NUL reject | Key issues |
|---|---:|---:|---:|---|---:|---:|---:|---|
| `CVE-2014-2525_libyaml` | false | true | true | `base.yaml` | false | false | false | OK |
| `CVE-2016-5314_libtiff` | false | true | true | `base.tiff` | false | false | false | OK |
| `CVE-2016-9827_libming` | false | true | true | `-` | false | false | false | HIGH: no default seed found; pipeline fallback is synthetic bytes |
| `CVE-2020-15999_freetype_DISCARDED` | true | true | true | `-` | false | false | false | HIGH: no default seed found; pipeline fallback is synthetic bytes |
| `CVE-2021-32292_jsonc` | false | true | true | `base.json` | false | false | false | OK |
| `CVE-2022-23852_expat_DISCARDED` | true | true | true | `-` | false | false | false | HIGH: no default seed found; pipeline fallback is synthetic bytes |
| `CVE-2022-23990_expat_DISCARDED` | true | true | true | `-` | false | false | false | HIGH: no default seed found; pipeline fallback is synthetic bytes |
| `CVE-2022-24724_cmark-gfm` | false | true | true | `base.md` | false | false | false | OK |
| `CVE-2022-4899_zstd` | false | true | true | `base.txt` | true | true | true | MEDIUM: both text and binary base seeds exist; manual --seed base.bin can destabilize semantics |
| `CVE-2023-2157_imagemagick` | false | false | false | `base.tiff` | false | false | false | HIGH: non-discarded task missing task.yml (excluded from auto-run) |
| `CVE-2023-2157_imagemagick_DISCARDED` | true | true | true | `-` | false | false | false | HIGH: no default seed found; pipeline fallback is synthetic bytes |
| `CVE-2023-29469_libxml2` | false | true | false | `seed.xml` | false | false | false | MEDIUM: task.yml exists but harness/run.sh missing in tree |
| `CVE-2023-39804_gnutar` | false | true | true | `base.tar` | false | false | false | OK |
| `CVE-2023-4863_libwebp_DISCARDED` | true | true | true | `-` | false | false | false | HIGH: no default seed found; pipeline fallback is synthetic bytes |
| `CVE-2023-50246_jq_DISCARDED` | true | true | true | `base.json` | false | false | false | OK |
| `CVE-2023-50268_jq_DISCARDED` | true | true | true | `-` | false | false | false | HIGH: no default seed found; pipeline fallback is synthetic bytes |
| `CVE-2023-6228_libtiff_DISCARDED` | true | true | true | `base.tiff` | false | false | false | OK |
| `CVE-2024-25062_libxml2` | false | false | false | `seed_pipeline.xml` | false | false | false | HIGH: non-discarded task missing task.yml (excluded from auto-run) |
| `CVE-2024-4323_fluentbit` | false | false | false | `seed.json` | false | false | false | HIGH: non-discarded task missing task.yml (excluded from auto-run) |
| `CVE-2024-57970_libarchive` | false | true | true | `base.tar` | false | false | false | OK |
| `CVE-2025-26623_exiv2` | false | true | true | `base.jpg` | false | false | false | OK |
| `CVE-2025-49014_jq` | false | true | true | `base.jq` | false | true | true | MEDIUM: both text and binary base seeds exist; manual --seed base.bin can destabilize semantics |

## Notes for Current Incident (CVE-2022-4899_zstd L2 + Gemini)
- Root cause of the shown failure is configuration leakage (`api_base` set to Ollama URL) not seed semantics.
- When this leakage is fixed/unset, L2 behavior depends on mutation quality; `.bin` manual seed tends to allow binary/NUL-heavy proposals.
- For semantic path-argument fuzzing, prefer text-oriented seed invocation or enforce task-local text mutation constraints.

## Recommended Actions
1. Add task-local mutation profiles (text-only ops for ARG_FROM_SEED / jq filter tasks).
2. Keep Vertex/Ollama endpoint separation strict (never apply `api_base` to `vertex_ai/*`).
3. Add explicit default seed for `CVE-2016-9827_libming` in `tasks/.../seeds/`.
4. Mark incomplete non-discarded task dirs as `_DISCARDED` or complete their `task.yml` + harness.
5. Optionally relax/parameterize strict format validators only for tasks where malformed headers are part of trigger path.