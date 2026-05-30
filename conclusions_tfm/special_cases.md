# Casos Especiales del Estudio (Para Tesis/Paper)

## 1) Objetivo de este documento

Este documento recoge solo casos metodologicamente especiales que pueden sesgar la lectura de resultados agregados si no se explican aparte.

## 2) CVE-2024-4323_fluentbit: doble perfil de semilla (24 + 24)

- Este CVE no sigue la matriz simple de 24 runs.
- Se ejecuta con 2 perfiles de semilla:
  - `seed (new op)` -> 24 runs.
  - `seed_crash` -> 24 runs.
- Total del CVE: 48 runs.
- En el informe de resultados ya aparece separado por perfil y con exito 24/24 en ambos perfiles.
- Harness usado en la campana: `target-vuln`.

Fuentes:
- `conclusions_tfm/CVE-2024-4323_fluentbit/RUNS_ANALYSIS_DETAILED_20260521.md`
- `scripts/run_pending_models.py` (`CVE_SEED_PROFILES`)

## 3) CVE-2023-29469_libxml2: dos harness distintos por nivel

- Este CVE no es homogeneo por harness:
  - `L0/L1/L2` usan `target-vuln` (18 runs).
  - `L3` usa `target-vuln-direct` (6 runs).
- En los resultados:
  - `target-vuln`: 0/18 exitos.
  - `target-vuln-direct`: 5/6 exitos.
- Si se reporta solo una tasa global del CVE (5/24), se pierde esta diferencia metodologica clave.

Fuentes:
- `conclusions_tfm/CVE-2023-29469_libxml2/RUNS_ANALYSIS_DETAILED_20260521.md`
- `scripts/run_pending_models.py` (`SERVICE_OVERRIDES_BY_CVE_LEVEL`)
- `docs/PIPELINE_AND_AUTOSCHEDULER_REFERENCE_2026-05-14.md`

## 4) CVE-2024-25062_libxml2: L3 incompleto y pase de cierre de cobertura

- En el informe activo hay 21/24 runs: faltan 3 combinaciones, todas en L3.
- Combinaciones L3 ausentes:
  - `deepseek-v4-pro` + `L3`
  - `gemini-3-flash-preview` + `L3`
  - `glm-5.1` + `L3`
- Hay 3 runs L3 existentes, todas fallidas:
  - `gpt-oss-20b` + `L3`
  - `ministral-3-8b` + `L3`
  - `qwen3-coder-next` + `L3`
- La regla metodologica original excluia L3 cuando no habia `target-vuln-direct`.
- El `compose.yml` de este CVE solo expone `target-vuln`/`target-fixed`, por lo que los 3 L3 ausentes se han marcado como pase explicito de cierre de cobertura contra el harness estandar disponible.
- Los 3 L3 ya cubiertos siguen excluidos de rerun para no duplicar resultados.
- Implicacion: antes del pase de cierre no habia matriz completa de 24 para este CVE; si se incorporan las 3 runs nuevas, deben etiquetarse como completado metodologico contra harness estandar, no como direct-harness L3.

Fuentes:
- `scripts/run_pending_models.py` (`EXCLUDED_COMBOS`)
- `scripts/run_pending_models.py` (`FORCE_PENDING_COMBOS`)
- `conclusions_tfm/CVE-2024-25062_libxml2/RUNS_ANALYSIS_DETAILED_20260521.md`

## 5) CVE-2024-57970_libarchive: oracle marcado como BROKEN

- Existe nota explicita `ORACLE_BROKEN.md`.
- El documento indica que, en ese estado, el oraculo diferencial puede no detectar de forma fiable la vulnerabilidad (especialmente por tratarse de read-overflow).
- El scheduler detecta estas notas y emite warning de politica antes de campanas grandes.

Fuentes:
- `tasks/CVE-2024-57970_libarchive/ORACLE_BROKEN.md`
- `scripts/run_pending_models.py` (scan de `ORACLE_BROKEN.md`)
- `docs/PIPELINE_AND_AUTOSCHEDULER_REFERENCE_2026-05-14.md`

## 6) Reevaluaciones y etiquetado de runs

- Hay sufijos de campana de reevaluacion definidos en scheduler:
  - `CVE-2024-4323_fluentbit` -> `_testing_leakage`
  - `CVE-2021-32292_jsonc` -> `_testing_leakage`
- Esto es importante para no mezclar automaticamente resultados de baseline y retest.

Fuente:
- `scripts/run_pending_models.py` (`RUN_NAME_SUFFIX_BY_CVE`)

## 7) Regla de validez de run y control de anomalias

- Una run se considera valida solo si:
  - `success=true`, o
  - `success=false` pero consumiendo presupuesto completo (`total_iters >= max_iters`).
- Tambien existe normalizacion de falsos positivos de anomalias:
  - `llm-stop-early` se elimina cuando el log indica que fue ignorado por politica o se alcanzaron iteraciones maximas.

Fuentes:
- `scripts/run_pending_models.py` (completion rule y `normalize_run_anomalies`)
- `docs/PIPELINE_AND_AUTOSCHEDULER_REFERENCE_2026-05-14.md`

## 8) Recomendacion de uso en el paper

Incluir un apartado "Casos especiales y amenazas a validez" que cubra al menos:

1. CVEs no comparables 1:1 con matriz 24-run (fluentbit 48 por doble seed).
2. CVEs con cambio de harness por nivel (libxml2 2023-29469).
3. CVEs con exclusiones metodologicas (libxml2 2024-25062).
4. CVEs con oracle no fiable (libarchive ORACLE_BROKEN).
5. Regla formal de validez de run para evitar sobreestimar resultados.
