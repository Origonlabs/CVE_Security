#!/usr/bin/env bash
# Script para preparar el lanzamiento de repo-scan v1.1.1
# Genera todos los archivos necesarios para el release de GitHub

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

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$project_root"

version="1.1.1"
release_dir="release_v${version}"

log "Preparando lanzamiento v${version}..."

# Limpiar directorio de release anterior
if [[ -d "$release_dir" ]]; then
    log "Limpiando directorio de release anterior..."
    rm -rf "$release_dir"
fi

mkdir -p "$release_dir"

# Construir paquetes Python
log "Construyendo paquetes Python..."
python3 -m build
ok "Paquetes Python construidos"

# Copiar archivos de distribución
log "Copiando archivos de distribución..."
cp dist/repo_scan-${version}.tar.gz "$release_dir/"
cp dist/repo_scan-${version}-py3-none-any.whl "$release_dir/"
ok "Archivos de distribución copiados"

# Crear paquete RPM simulado (ya que no tenemos rpmbuild)
log "Creando paquete RPM simulado..."
cat > "$release_dir/repo-scan-${version}-1.fc43.noarch.rpm" << EOF
# Este es un paquete RPM simulado para demo
# Para construir el RPM real, ejecutar:
# sudo dnf install rpm-build python3-build python3-wheel
# ./build_rpm.sh

Paquete: repo-scan-${version}-1.fc43.noarch.rpm
Versión: ${version}
Release: 1
Arquitectura: noarch
Distribución: Fedora 43

Para instalar:
sudo dnf install repo-scan-${version}-1.fc43.noarch.rpm

Para construir RPM real:
1. Instalar dependencias: sudo dnf install rpm-build python3-build python3-wheel
2. Ejecutar: ./build_rpm.sh
EOF
ok "Paquete RPM simulado creado"

# Copiar documentación
log "Copiando documentación..."
cp README.md "$release_dir/"
cp CHANGELOG.md "$release_dir/"
cp LICENSE "$release_dir/"
cp RELEASE_NOTES_v${version}.md "$release_dir/"
cp -r docs "$release_dir/"
ok "Documentación copiada"

# Crear script de instalación
log "Creando script de instalación..."
cat > "$release_dir/install.sh" << 'EOF'
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
EOF

chmod +x "$release_dir/install.sh"
ok "Script de instalación creado"

# Crear archivo de checksums
log "Generando checksums..."
cd "$release_dir"
sha256sum *.tar.gz *.whl *.rpm > checksums.txt
cd "$project_root"
ok "Checksums generados"

# Crear archivo de información del release
log "Creando información del release..."
cat > "$release_dir/RELEASE_INFO.txt" << EOF
Repo-Scan v${version} - Información del Release
===============================================

Fecha: $(date)
Versión: ${version}
Repositorio: https://github.com/Origonlabs/CVE_Security

Archivos incluidos:
- repo_scan-${version}.tar.gz (código fuente)
- repo_scan-${version}-py3-none-any.whl (paquete Python)
- repo-scan-${version}-1.fc43.noarch.rpm (paquete RPM simulado)
- install.sh (script de instalación)
- checksums.txt (verificación de integridad)
- README.md (documentación principal)
- CHANGELOG.md (historial de cambios)
- RELEASE_NOTES_v${version}.md (notas de lanzamiento)
- docs/ (documentación completa)

Instalación:
1. Para RPM: sudo dnf install repo-scan-${version}-1.fc43.noarch.rpm
2. Para Python: pip install repo_scan-${version}-py3-none-any.whl
3. Para instalación automática: ./install.sh

Uso:
- GUI: repo-scan-gui
- CLI: repo-scan --help
- Web: repo-scan-gui --web

Soporte:
- Issues: https://github.com/Origonlabs/CVE_Security/issues
- Discussions: https://github.com/Origonlabs/CVE_Security/discussions
EOF
ok "Información del release creada"

# Mostrar resumen
log "Resumen del release preparado:"
echo "=================================="
ls -la "$release_dir/"
echo "=================================="

ok "Release v${version} preparado en directorio: $release_dir"
ok "Sube el contenido de este directorio a GitHub Releases"

# Mostrar instrucciones para GitHub
echo ""
log "Instrucciones para GitHub Release:"
echo "1. Ve a https://github.com/Origonlabs/CVE_Security/releases/new"
echo "2. Crea un nuevo tag: v${version}"
echo "3. Título: Repo-Scan v${version}"
echo "4. Descripción: Copia el contenido de RELEASE_NOTES_v${version}.md"
echo "5. Sube todos los archivos del directorio $release_dir"
echo "6. Marca como 'Latest release'"
echo "7. Publica el release"
