# Prompt para Agente Revisor del Paper

## Contexto

Estoy cerrando un paper/TFM sobre reproduccion automatizada de CVEs con pipeline OpenHands + LLMs.  
Necesito una revision tecnica profunda del manuscrito para reforzar solidez metodologica y trazabilidad de resultados, **sin inventar datos**.

## Tu tarea

1. Lee las fuentes listadas abajo.
2. Detecta huecos del paper actual (metodo, resultados, amenazas a validez, comparabilidad).
3. Propone texto concreto para mejorar el paper (secciones nuevas o reescrituras), con respaldo explicito en archivos.
4. Si falta evidencia en algun punto, marcalo como "evidencia insuficiente" (no rellenes con supuestos).

## Restricciones

- Prohibido inventar resultados, fechas, cifras o causas.
- Solo usar informacion verificable de los archivos listados.
- Distinguir claramente:
  - hechos observados,
  - interpretaciones,
  - y recomendaciones.

## Focos obligatorios de mejora

1. **Comparabilidad entre CVEs**  
   Explicar por que no todos son 24-run homogeneos.

2. **Casos especiales**  
   Incluir apartado dedicado para:
   - `CVE-2024-4323_fluentbit` (doble perfil seed, 48 runs).
   - `CVE-2023-29469_libxml2` (dos harness por nivel).
   - `CVE-2024-25062_libxml2` (L3 excluido por politica).
   - `CVE-2024-57970_libarchive` (`ORACLE_BROKEN`).

3. **Regla de validez de runs**  
   Dejar explicito criterio de run valida y tratamiento de anomalias (`llm-stop-early`).

4. **Metodologia operativa reproducible**  
   Resumir pipeline, scheduler, niveles L0-L3, mutaciones y oracle diferencial.

5. **Lectura critica de resultados**  
   Proponer como presentar resultados globales sin ocultar subdesgloses (24+24, por harness, etc.).

## Fuentes que debes leer (prioridad alta)

### A) Resumen y conclusiones
- `conclusions_tfm/context.md`
- `conclusions_tfm/models.md`
- `conclusions_tfm/special_cases.md`
- `conclusions_tfm/db.md`

### B) Informes por CVE
- `conclusions_tfm/CVE-2024-4323_fluentbit/RUNS_ANALYSIS_DETAILED_20260521.md`
- `conclusions_tfm/CVE-2023-29469_libxml2/RUNS_ANALYSIS_DETAILED_20260521.md`
- `conclusions_tfm/CVE-2024-25062_libxml2/RUNS_ANALYSIS_DETAILED_20260521.md`
- `conclusions_tfm/CVE-2024-57970_libarchive/RUNS_ANALYSIS_DETAILED_20260521.md`
- `conclusions_tfm/CVE-2021-32292_jsonc/RUNS_ANALYSIS_DETAILED_20260521.md`

### C) Metodo/pipeline/scheduler
- `docs/methodology.md`
- `docs/info_levels.md`
- `docs/PIPELINE_AND_AUTOSCHEDULER_REFERENCE_2026-05-14.md`
- `docs/CAMPAIGN_CONSOLIDATED_ALL_CVES_2026-05-14.md`
- `agents/openhands_llm/openhands_pipeline.md`
- `agents/openhands_llm/src/pipeline.py`
- `agents/openhands_llm/src/openhands_client.py`
- `scripts/run_pending_models.py`
- `scripts/lib/oracle.py`
- `scripts/lib/docker_readiness.py`

### D) Evidencia de casos especiales
- `tasks/CVE-2024-57970_libarchive/ORACLE_BROKEN.md`
- `conclusions_tfm/CVE-2023-29469_libxml2/justification_L2_vs_L3.md`
- `runs_deprecated/CVE-2023-29469_libxml2/gemini-2.0-flash/justification_L2_vs_L3.md` (fuente original, opcional)

### E) Paper a mejorar
- `d:/JustainoTitaino/Descargas/EVALUATING_LARGE_LANGUAGE_MODELS_FOR_AUTOMATED_SOFTWARE_EXPLOIT_GENERATION.pdf`

## Formato de salida que quiero

1. **Lista de gaps del paper** (priorizada por impacto).
2. **Cambios propuestos** (texto o esquema de secciones).
3. **Tabla de claims**: claim -> archivo(s) de evidencia.
4. **Pendientes de evidencia**: puntos que no pueden afirmarse aun.
5. **Version corta lista para integrar** en el paper (1-2 paginas en markdown).
