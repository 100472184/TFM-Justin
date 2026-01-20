# OpenHands LLM Pipeline para TFM-Justin

Pipeline automatizado de análisis y generación de seeds para CVEs usando LLM (LLaMA 3 local u otros modelos).

## 🎯 Objetivo

Implementar un ciclo iterativo **ANALYZE → GENERATE → VERIFY** que usa un LLM para:

1. **ANALYZE**: Analizar el CVE y contexto del task
2. **GENERATE**: Proponer mutaciones de seed basadas en el análisis
3. **VERIFY**: Ejecutar el benchmark y verificar si se gatilló la vulnerabilidad

El LLM actúa como "fuzzing assistant" que propone mutaciones inteligentes en lugar de fuerza bruta.

## 📋 Requisitos

### Python 3.12+ (IMPORTANTE)

OpenHands SDK requiere Python 3.12 o superior. **NO usar el mismo entorno que el repo base**.

```powershell
# Crear entorno separado para OpenHands
python -m venv .venv-oh
.venv-oh\Scripts\activate

# Instalar dependencias
pip install -r requirements-openhands.txt
```

### Ollama + LLaMA 3 (Recomendado para local)

1. Descargar e instalar Ollama: https://ollama.ai/download
2. Abrir terminal y ejecutar:

```powershell
# Descargar modelo LLaMA 3
ollama pull llama3

# Iniciar servidor (puerto 11434 por defecto)
ollama serve
```

3. Verificar que funciona:

```powershell
ollama run llama3 "Hello"
```

### Docker Desktop

Necesario para ejecutar los contenedores de los tasks:

```powershell
# Verificar instalación
docker --version
docker compose version
```

## ⚙️ Configuración

### 1. Copiar archivo de configuración

```powershell
cp agents\openhands_llama3\config\example.env agents\openhands_llama3\.env
```

### 2. Editar `.env` según tu LLM

#### Para LLaMA 3 local (Ollama):

```bash
LLM_MODEL=ollama/llama3
LLM_BASE_URL=http://localhost:11434
LLM_TIMEOUT=120
LLM_NUM_RETRIES=3
```

#### Para OpenAI GPT-4:

```bash
LLM_MODEL=gpt-4o
LLM_API_KEY=sk-...
LLM_BASE_URL=https://api.openai.com/v1
LLM_TIMEOUT=60
LLM_NUM_RETRIES=3
```

#### Para Google Gemini:

```bash
LLM_MODEL=gemini/gemini-1.5-pro
LLM_API_KEY=...
LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta
LLM_TIMEOUT=60
LLM_NUM_RETRIES=3
```

### 3. Construir la imagen Docker del task

```powershell
# Ejemplo: CVE-2023-4863_libwebp
python -m scripts.bench build CVE-2023-4863_libwebp
```

## 🚀 Uso

### Comando básico

```powershell
python -m agents.openhands_llama3.run ^
    --task-id CVE-2023-4863_libwebp ^
    --level L3 ^
    --max-iters 10 ^
    --service target-vuln
```

### Parámetros

- `--task-id`: ID del CVE task (requerido)
  - Ejemplo: `CVE-2023-4863_libwebp`, `CVE-2023-52425_expat`, etc.
  
- `--level`: Nivel de información para el LLM (default: L3)
  - `L0`: Descripción básica del CVE
  - `L1`: + Patch/diff
  - `L2`: + Archivo vulnerable
  - `L3`: + Contexto completo (harness, docs)
  
- `--max-iters`: Máximo de iteraciones (default: 10)
  
- `--service`: Servicio Docker a testear (default: target-vuln)
  - `target-vuln`: Versión vulnerable
  - `target-fixed`: Versión parcheada (sanity check)
  
- `--seed`: Archivo seed inicial (opcional)
  - Si no se provee, se genera uno aleatorio

### Ejemplos

#### 1. Análisis básico con 5 iteraciones

```powershell
python -m agents.openhands_llama3.run ^
    --task-id CVE-2023-4863_libwebp ^
    --level L2 ^
    --max-iters 5
```

#### 2. Usar seed personalizado

```powershell
python -m agents.openhands_llama3.run ^
    --task-id CVE-2024-57970_libarchive ^
    --level L3 ^
    --max-iters 15 ^
    --seed myseeds\archive.tar
```

#### 3. Verificar que el patch funciona (target-fixed)

```powershell
python -m agents.openhands_llama3.run ^
    --task-id CVE-2023-52425_expat ^
    --level L3 ^
    --max-iters 5 ^
    --service target-fixed
```

## 📊 Estructura de salida

Cada ejecución crea un directorio en `runs/`:

```
runs/
└── 20250202_143022_CVE-2023-4863_libwebp/
    └── CVE-2023-4863_libwebp/
        ├── iter_001/
        │   ├── seed.bin          # Seed mutado
        │   ├── command.txt       # Comando ejecutado
        │   ├── analysis.json     # Output de ANALYZE
        │   ├── generate.json     # Output de GENERATE
        │   └── verify.json       # Output de VERIFY
        ├── iter_002/
        │   └── ...
        └── summary.json          # Resumen de la ejecución
```

### Archivo `summary.json`

```json
{
  "task_id": "CVE-2023-4863_libwebp",
  "level": "L3",
  "max_iters": 10,
  "total_iters": 7,
  "success": true,
  "success_iter": 7,
  "run_dir": "runs/20250202_143022_CVE-2023-4863_libwebp/CVE-2023-4863_libwebp",
  "timestamp": "20250202_143022"
}
```

## 🔍 Verificación de resultados

### 1. Ver salida del benchmark

```powershell
type runs\20250202_143022_CVE-2023-4863_libwebp\CVE-2023-4863_libwebp\iter_007\command.txt
```

### 2. Inspeccionar mutaciones propuestas

```powershell
type runs\20250202_143022_CVE-2023-4863_libwebp\CVE-2023-4863_libwebp\iter_007\generate.json
```

Ejemplo:

```json
{
  "mutations": [
    {"op": "overwrite_range", "offset": 12, "hex": "ffffffff"},
    {"op": "flip_bit", "offset": 30, "bit": 7}
  ],
  "rationale": "Corrupting WebP chunk size to trigger overflow"
}
```

### 3. Ver output del sanitizer

Los logs del benchmark están en los archivos `.json` de cada iteración:

```powershell
type runs\...\iter_007\verify.json | jq .stderr
```

## 🐛 Troubleshooting

### Error: "OpenHands SDK not found"

```powershell
# Asegurarse de estar en el entorno correcto
.venv-oh\Scripts\activate
pip install -r requirements-openhands.txt
```

### Error: "Connection refused to Ollama"

```powershell
# Verificar que Ollama está corriendo
ollama serve

# En otra terminal, verificar conectividad
curl http://localhost:11434/api/tags
```

### Error: "Task not found"

```powershell
# Listar tasks disponibles
python -m scripts.bench list

# Verificar que el task_id está bien escrito (case-sensitive)
```

### Error: "Docker service not running"

```powershell
# Construir la imagen primero
python -m scripts.bench build <task_id>

# Verificar que se creó
docker images | findstr <task_id>
```

### El LLM no propone buenas mutaciones

- **Aumentar nivel de información**: `--level L3` da más contexto
- **Aumentar iteraciones**: `--max-iters 20`
- **Probar otro modelo**: GPT-4o o Gemini suelen ser más precisos que LLaMA 3
- **Revisar templates**: Los prompts están en `prompt_templates/`

### Pipeline muy lento

- **Reducir timeout**: `LLM_TIMEOUT=60` en `.env`
- **Usar modelo más rápido**: LLaMA 3 8B en lugar de 70B
- **Reducir iteraciones**: `--max-iters 5`

## 📚 Metodología

Ver [openhands_pipeline.md](openhands_pipeline.md) para detalles técnicos sobre:

- Arquitectura del pipeline
- Formato de prompts Jinja2
- Operaciones de mutación soportadas
- Estrategias de detección de crashes
- Integración con el benchmark

## 🔗 Referencias

- **OpenHands SDK**: https://github.com/All-Hands-AI/OpenHands
- **LiteLLM** (backend de OpenHands): https://docs.litellm.ai/
- **Ollama**: https://ollama.ai/
- **Benchmark TFM-Justin**: Ver README.md principal

## 📄 Licencia

MIT License - Ver archivo LICENSE en el directorio raíz.
