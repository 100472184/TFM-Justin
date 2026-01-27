# Git Workflow en Kali

## Configuración Inicial (Una Sola Vez)

```bash
# Configurar identidad
git config --global user.name "Tu Nombre"
git config --global user.email "100472184@alumnos.uc3m.es"

# Verificar configuración
git config --global --list
```

---

## Workflow Diario

### 1. Ver Cambios

```bash
cd ~/TFM-Justin

# Ver archivos modificados
git status

# Ver diferencias específicas
git diff
git diff path/to/file.py
```

### 2. Agregar Cambios

```bash
# Agregar archivo específico
git add path/to/file.py

# Agregar todos los archivos modificados
git add .

# Agregar solo archivos Python
git add *.py

# Agregar por carpeta
git add agents/
```

### 3. Hacer Commit

```bash
# Commit con mensaje corto
git commit -m "Descripción del cambio"

# Ejemplos:
git commit -m "Fix ASLR detection in pipeline"
git commit -m "Add L2 testing results"
git commit -m "Update compose.yml with sysctls"

# Commit con mensaje más detallado
git commit -m "Fix crash detection" -m "- Changed threshold to 3/5
- Added repro-check with 5 runs
- Updated documentation"
```

### 4. Sincronizar con GitHub

```bash
# Ver si hay cambios remotos (opcional)
git fetch
git status

# Subir cambios a GitHub
git push

# Si es la primera vez en una rama nueva
git push -u origin main
```

### 5. Traer Cambios de Windows

```bash
# Si hiciste cambios en Windows y quieres traerlos a Kali
git pull

# Si hay conflictos, Git te lo dirá
# Resuelve conflictos editando archivos y luego:
git add .
git commit -m "Merge changes from Windows"
```

---

## Workflow Completo (Típico)

```bash
cd ~/TFM-Justin

# 1. Ver qué cambió
git status
git diff

# 2. Agregar cambios
git add .

# 3. Commit
git commit -m "Test L2 with ASLR disabled in Kali"

# 4. Push a GitHub
git push
```

---

## Comandos Útiles

### Ver Historial

```bash
# Últimos commits
git log --oneline -10

# Ver cambios de un commit específico
git show <commit-hash>
```

### Deshacer Cambios

```bash
# Descartar cambios no guardados en un archivo
git checkout -- path/to/file.py

# Descartar TODOS los cambios no guardados
git reset --hard HEAD

# Quitar archivo del staging (antes de commit)
git reset HEAD path/to/file.py
```

### Verificar Conexión

```bash
# Ver repositorio remoto
git remote -v

# Probar conexión SSH
ssh -T git@github.com
# Debe responder: "Hi 100472184! You've successfully authenticated..."
```

---

## Errores Comunes

### Error: "Permission denied (publickey)"

```bash
# Verificar SSH key está cargada
ssh-add ~/.ssh/id_ed25519

# Si no existe, generarla
ssh-keygen -t ed25519 -C "100472184@alumnos.uc3m.es"

# Copiar y agregar a GitHub
cat ~/.ssh/id_ed25519.pub
```

### Error: "Please tell me who you are"

```bash
git config --global user.name "Tu Nombre"
git config --global user.email "100472184@alumnos.uc3m.es"
```

### Conflictos de Merge

```bash
# Cuando git pull da conflicto:
# 1. Edita los archivos (busca <<<<<<, ======, >>>>>>)
# 2. Resuelve manualmente
# 3. Marca como resuelto
git add archivo-con-conflicto.py
git commit -m "Resolve merge conflict"
git push
```

---

## Ignorar Archivos

Si hay archivos que NO quieres subir a GitHub (logs, builds, etc.):

```bash
# Editar .gitignore
nano .gitignore

# Agregar patrones:
*.log
runs/
.venv-oh/
__pycache__/
```

---

## Quick Reference

| Acción | Comando |
|--------|---------|
| Ver estado | `git status` |
| Ver diferencias | `git diff` |
| Agregar todo | `git add .` |
| Commit | `git commit -m "mensaje"` |
| Subir a GitHub | `git push` |
| Traer de GitHub | `git pull` |
| Ver historial | `git log --oneline` |
| Deshacer cambios | `git reset --hard HEAD` |

---

## Workflow Recomendado Después de Testing

```bash
# Después de correr pipeline L2
cd ~/TFM-Justin

# Ver resultados generados
ls -lh runs/

# Agregar solo archivos importantes (no runs/ enteros)
git add agents/
git add tasks/
git add README.md
git add *.py

# Commit con descripción clara
git commit -m "L2 testing with ASLR disabled - 80% reproducibility"

# Push
git push

# Verificar en GitHub que se subió
```

---

**Tip:** Usa `git status` constantemente para saber dónde estás.
