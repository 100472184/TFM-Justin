# Comparativa de Modelos (Campana TFM)

## 1. Objetivo
Este documento resume el rendimiento de los modelos usados en las campanas de `conclusions_tfm`, con foco en:
- fortalezas observadas,
- debilidades observadas,
- mejor modelo global,
- criterio operativo para elegir modelo segun nivel (L0-L3).

## 2. Base de datos usada
- Fuente principal: los 12 informes `RUNS_ANALYSIS_DETAILED_20260521.md` dentro de `conclusions_tfm/CVE-*/`.
- Modelos evaluados: `gemini-3-flash-preview`, `deepseek-v4-pro`, `glm-5.1`, `qwen3-coder-next`, `gpt-oss-20b`, `ministral-3-8b`.
- Mapeo de aliases y endpoints: `scripts/run_pending_models.py` (`MODEL_SPECS`).
- Cobertura agregada leida desde tablas de ranking por CVE: 72 filas modelo-CVE.

Nota de interpretacion:
- En `CVE-2024-4323_fluentbit` hay doble perfil (`seed (new op)` y `seed_crash`), por eso ese CVE aporta mas runs por modelo.
- En `CVE-2024-25062_libxml2` hay combinaciones `L3` no aplicadas para algunos modelos (aparecen como `N/A` en su matriz).

## 3. Ranking global (todas las campanas agregadas)

| Rank | Modelo | Runs | Exitos | Fracasos | Success Rate | Avg Budget ponderado | Avg Iters ponderado |
|---:|---|---:|---:|---:|---:|---:|---:|
| 1 | `gemini-3-flash-preview` | 51 | 39 | 12 | 76.5% | 30.0% | 11.78 |
| 2 | `deepseek-v4-pro` | 51 | 39 | 12 | 76.5% | 30.7% | 11.92 |
| 3 | `glm-5.1` | 51 | 35 | 16 | 68.6% | 39.8% | 16.65 |
| 4 | `gpt-oss-20b` | 52 | 27 | 25 | 51.9% | 55.5% | 22.23 |
| 5 | `qwen3-coder-next` | 52 | 26 | 26 | 50.0% | 56.9% | 22.73 |
| 6 | `ministral-3-8b` | 52 | 22 | 30 | 42.3% | 65.6% | 25.23 |

Lectura rapida:
- Hay empate en exito global entre `gemini-3-flash-preview` y `deepseek-v4-pro`.
- El desempate por eficiencia (budget e iteraciones) favorece ligeramente a `gemini-3-flash-preview`.

## 4. Rendimiento por nivel (agregado)

| Modelo | L0 | L1 | L2 | L3 |
|---|---:|---:|---:|---:|
| `deepseek-v4-pro` | 69.2% (9/13) | 69.2% (9/13) | 76.9% (10/13) | 91.7% (11/12) |
| `gemini-3-flash-preview` | 61.5% (8/13) | 76.9% (10/13) | 76.9% (10/13) | 91.7% (11/12) |
| `glm-5.1` | 38.5% (5/13) | 69.2% (9/13) | 69.2% (9/13) | 100.0% (12/12) |
| `gpt-oss-20b` | 30.8% (4/13) | 23.1% (3/13) | 76.9% (10/13) | 76.9% (10/13) |
| `ministral-3-8b` | 30.8% (4/13) | 23.1% (3/13) | 46.2% (6/13) | 69.2% (9/13) |
| `qwen3-coder-next` | 23.1% (3/13) | 46.2% (6/13) | 46.2% (6/13) | 84.6% (11/13) |

Patron fuerte del dataset:
- L3 es el nivel con mejor comportamiento para casi todos los modelos.
- L0/L1 concentran mas variabilidad y mas fallos.

## 5. Ganadores por CVE (segun ranking #1 de cada informe)

| Modelo | CVEs donde queda #1 |
|---|---:|
| `gemini-3-flash-preview` | 5 |
| `deepseek-v4-pro` | 5 |
| `glm-5.1` | 1 |
| `gpt-oss-20b` | 1 |
| `qwen3-coder-next` | 0 |
| `ministral-3-8b` | 0 |

Nota:
- El #1 de un CVE no siempre significa mayor facilidad de explotacion global; hay CVEs muy duros donde todos fallan y el ranking se decide por eficiencia relativa.

## 6. Fortalezas y Debilidades por modelo

### `gemini-3-flash-preview`
Fortalezas:
- Mejor eficiencia global del top (menor budget/iteraciones ponderadas entre los dos lideres).
- Muy solido en L1-L3 (>=76.9% agregado).
- Gana 5 CVEs como primer clasificado.

Debilidades:
- Baja en L0 frente a `deepseek-v4-pro` (61.5% vs 69.2%).
- En CVEs especialmente hostiles (ej. `CVE-2024-25062_libxml2`) no logra exito.

### `deepseek-v4-pro`
Fortalezas:
- Empate en mejor tasa de exito global (76.5%).
- Mejor robustez en L0 que `gemini-3-flash-preview`.
- Gana 5 CVEs como primer clasificado.

Debilidades:
- Eficiencia global ligeramente peor que `gemini-3-flash-preview`.
- Mismo techo de dificultad en CVEs muy duros (no rompe ciertos casos sin exito).

### `glm-5.1`
Fortalezas:
- Muy fuerte en L3 (100.0% agregado).
- Tercer mejor modelo global en exito total.
- Puede rendir bien cuando el contexto del nivel alto reduce ambiguedad.

Debilidades:
- Caida marcada en L0 (38.5%).
- Mayor coste medio que los dos lideres.
- Comportamiento mas irregular entre niveles.

### `gpt-oss-20b`
Fortalezas:
- Desempeno aceptable en L2/L3 (76.9% agregado).
- Tiene 1 CVE con primer puesto en ranking.

Debilidades:
- Rendimiento bajo en L0/L1 (30.8% y 23.1%).
- Coste medio alto.
- Menor estabilidad global que el top 3.

### `qwen3-coder-next`
Fortalezas:
- Buen rendimiento en L3 (84.6%).
- Puede converger bien en escenarios de mas contexto.

Debilidades:
- Resultado global medio-bajo (50.0%).
- L0 muy debil (23.1%).
- Sin CVEs liderados como #1 en esta base.

### `ministral-3-8b`
Fortalezas:
- Comportamiento util en parte de L3 (69.2%).
- Puede resolver subconjuntos concretos con bajo presupuesto.

Debilidades:
- Peor tasa global (42.3%).
- L0/L1 especialmente flojos.
- Mayor coste promedio total del grupo.

## 7. Cual es el mejor modelo?

Veredicto global (esta base de resultados):
- `gemini-3-flash-preview` y `deepseek-v4-pro` empatan en exito global.
- Si hay que elegir un unico ganador por equilibrio exito + eficiencia: `gemini-3-flash-preview`.
- Si priorizas robustez en nivel bajo (L0): `deepseek-v4-pro` es una opcion muy fuerte.
- Si priorizas maximo rendimiento en L3: `glm-5.1` destaca claramente.

## 8. Recomendacion practica de uso

Si solo puedes correr un modelo:
- Usa `gemini-3-flash-preview` como baseline principal.

Si puedes correr dos:
- Usa `gemini-3-flash-preview` + `deepseek-v4-pro` para combinar eficiencia y robustez.

Si haces una fase L3 dedicada:
- Anade `glm-5.1` por su fortaleza especifica en L3.

## 9. Nota sobre OpenHands

Si, en este proyecto los modelos se usan combinados con OpenHands.
- OpenHands orquesta el flujo `ANALYZE -> GENERATE -> VERIFY`, la ejecucion en Docker, y el control de artefactos.
- Los LLM no se ejecutan "sueltos"; se integran en ese pipeline con politicas de nivel, guardrails y verificacion diferencial `vuln vs fixed`.

Referencia de implementacion:
- `agents/openhands_llm/run.py`
- `agents/openhands_llm/src/pipeline.py`
- `scripts/run_pending_models.py`

