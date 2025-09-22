#!/usr/bin/env bash
# Script de instalación para repo-scan v1.1.1

set -euo pipefail

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*"; }

version="1.1.1"

log "Instalando repo-scan v${version}..."

# Verificar Python
if ! command -v python3 >/dev/null 2>&1; then
    err "Python 3 no está instalado. Instálalo primero."
    exit 1
fi

# Verificar pip
if ! command -v pip3 >/dev/null 2>&1; then
    err "pip3 no está instalado. Instálalo primero."
    exit 1
fi

# Instalar dependencias del sistema (si es posible)
if command -v dnf >/dev/null 2>&1; then
    log "Instalando dependencias del sistema..."
    sudo dnf install -y python3-pip git curl wget || warn "No se pudieron instalar todas las dependencias del sistema"
fi

# Instalar paquete Python
log "Instalando repo-scan..."
pip3 install repo_scan-${version}-py3-none-any.whl

# Verificar instalación
if command -v repo-scan >/dev/null 2>&1; then
    ok "repo-scan instalado correctamente"
    repo-scan --version
else
    err "La instalación falló"
    exit 1
fi

# Instalar herramientas de seguridad (opcional)
log "Para funcionalidad completa, instala las herramientas de seguridad:"
echo "  - Semgrep: pip install semgrep"
echo "  - Gitleaks: curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz | tar -xz -C /usr/local/bin"
echo "  - Trivy: sudo dnf install trivy"
echo "  - Bandit: pip install bandit"
echo "  - Checkov: pip install checkov"

ok "Instalación completada. Ejecuta 'repo-scan --help' para ver las opciones disponibles."
