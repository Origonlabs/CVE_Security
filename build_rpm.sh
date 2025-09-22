#!/bin/bash
# Script para construir RPM de repo-scan

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función para logging
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Variables
PACKAGE_NAME="repo-scan"
VERSION="1.0.0"
RELEASE="1"
ARCH="noarch"
MAINTAINER="Security Team <security@example.com>"
DESCRIPTION="Advanced repository security scanning tool"
LICENSE="MIT"
URL="https://github.com/example/repo-scan"
VENDOR="Security Team"

# Directorios
BUILD_DIR="rpm_build"
SPEC_DIR="$BUILD_DIR/SPECS"
SOURCES_DIR="$BUILD_DIR/SOURCES"
RPMS_DIR="$BUILD_DIR/RPMS"
SRPMS_DIR="$BUILD_DIR/SRPMS"
BUILDROOT_DIR="$BUILD_DIR/BUILDROOT"

log_info "Iniciando construcción de RPM para $PACKAGE_NAME-$VERSION"

# Crear directorios de construcción
log_info "Creando directorios de construcción..."
mkdir -p "$SPEC_DIR" "$SOURCES_DIR" "$RPMS_DIR" "$SRPMS_DIR" "$BUILDROOT_DIR"

# Crear tarball del código fuente
log_info "Creando tarball del código fuente..."
tar -czf "$SOURCES_DIR/$PACKAGE_NAME-$VERSION.tar.gz" \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='build' \
    --exclude='dist' \
    --exclude='*.egg-info' \
    --exclude='rpm_build' \
    --exclude='.pytest_cache' \
    --exclude='*.log' \
    .

# Crear spec file
log_info "Creando spec file..."
cat > "$SPEC_DIR/$PACKAGE_NAME.spec" << EOF
Name: $PACKAGE_NAME
Version: $VERSION
Release: $RELEASE%{?dist}
Summary: $DESCRIPTION
License: $LICENSE
URL: $URL
Source0: %{name}-%{version}.tar.gz
BuildArch: $ARCH
Vendor: $VENDOR
Packager: $MAINTAINER

Requires: python3 >= 3.8
Requires: python3-pip
Requires: git
Requires: docker >= 1.0 || podman >= 1.0
Requires: gitleaks
Requires: semgrep
Requires: trivy
Requires: bandit
Requires: checkov

BuildRequires: python3-devel
BuildRequires: python3-setuptools
BuildRequires: python3-wheel
BuildRequires: python3-build

%description
$DESCRIPTION

This package provides a comprehensive security scanning tool for software repositories.
It includes multiple security scanners (SAST, SCA, Secret Detection, IaC Security)
with advanced risk scoring, reporting capabilities, and both CLI and GUI interfaces.

Features:
- Multiple security scanners (Semgrep, Gitleaks, Trivy, Bandit, Checkov)
- Advanced risk scoring and prioritization
- Multiple report formats (JSON, HTML, JUnit)
- GUI and CLI interfaces
- CI/CD integration
- Plugin system
- Real-time notifications

%prep
%setup -q

%build
# Build Python package
python3 -m build --wheel --outdir dist

%install
# Install Python package
python3 -m pip install --no-deps --root %{buildroot} --prefix /usr dist/*.whl

# Create directories
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/etc/repo-scan
mkdir -p %{buildroot}/var/lib/repo-scan
mkdir -p %{buildroot}/var/log/repo-scan
mkdir -p %{buildroot}/var/cache/repo-scan
mkdir -p %{buildroot}/usr/share/applications
mkdir -p %{buildroot}/usr/share/doc/repo-scan
mkdir -p %{buildroot}/usr/share/man/man1

# Install configuration files
install -m 644 packaging/config.yaml %{buildroot}/etc/repo-scan/config.yaml

# Install desktop file
install -m 644 packaging/repo-scan-gui.desktop %{buildroot}/usr/share/applications/

# Install documentation
install -m 644 README.md %{buildroot}/usr/share/doc/repo-scan/
install -m 644 CHANGELOG.md %{buildroot}/usr/share/doc/repo-scan/

# Install man page if exists
if [ -f packaging/repo-scan.1 ]; then
    install -m 644 packaging/repo-scan.1 %{buildroot}/usr/share/man/man1/
    gzip %{buildroot}/usr/share/man/man1/repo-scan.1
fi

# Install systemd service
if [ -f packaging/repo-scan.service ]; then
    mkdir -p %{buildroot}/usr/lib/systemd/system
    install -m 644 packaging/repo-scan.service %{buildroot}/usr/lib/systemd/system/
fi

# Install shell completions
if [ -f packaging/repo-scan.bash ]; then
    mkdir -p %{buildroot}/usr/share/bash-completion/completions
    install -m 644 packaging/repo-scan.bash %{buildroot}/usr/share/bash-completion/completions/repo-scan
fi

if [ -f packaging/_repo-scan ]; then
    mkdir -p %{buildroot}/usr/share/zsh/site-functions
    install -m 644 packaging/_repo-scan %{buildroot}/usr/share/zsh/site-functions/_repo-scan
fi

%files
%license LICENSE
%doc README.md CHANGELOG.md
%{_bindir}/repo-scan
%{_bindir}/repo-scan-gui
%{python3_sitelib}/repo_scan
%{python3_sitelib}/repo_scan-*.dist-info
%config(noreplace) %{_sysconfdir}/repo-scan/config.yaml
%{_datadir}/applications/repo-scan-gui.desktop
%{_datadir}/doc/repo-scan/README.md
%{_datadir}/doc/repo-scan/CHANGELOG.md
%dir %{_localstatedir}/lib/repo-scan
%dir %{_localstatedir}/log/repo-scan
%dir %{_localstatedir}/cache/repo-scan

%if 0%{?fedora} >= 18
%{_mandir}/man1/repo-scan.1*
%{_datadir}/bash-completion/completions/repo-scan
%{_datadir}/zsh/site-functions/_repo-scan
%{_unitdir}/repo-scan.service
%endif

%post
# Update desktop database
if [ -x /usr/bin/update-desktop-database ]; then
    /usr/bin/update-desktop-database %{_datadir}/applications >/dev/null 2>&1 || :
fi

# Update systemd
if [ -x /usr/bin/systemctl ]; then
    /usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :
fi

%postun
# Update desktop database
if [ -x /usr/bin/update-desktop-database ]; then
    /usr/bin/update-desktop-database %{_datadir}/applications >/dev/null 2>&1 || :
fi

# Update systemd
if [ -x /usr/bin/systemctl ]; then
    /usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :
fi

%changelog
* $(date '+%a %b %d %Y') $MAINTAINER - $VERSION-$RELEASE
- Initial package
- Advanced repository security scanning tool
- Includes GUI and CLI interfaces
- Multiple security scanners support
EOF

# Crear archivo LICENSE si no existe
if [ ! -f LICENSE ]; then
    log_info "Creando archivo LICENSE..."
    cat > LICENSE << EOF
MIT License

Copyright (c) 2024 Security Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
EOF
fi

# Intentar construir el RPM usando rpmbuild si está disponible
if command -v rpmbuild &> /dev/null; then
    log_info "Usando rpmbuild para construir el RPM..."
    rpmbuild --define "_topdir $(pwd)/$BUILD_DIR" -ba "$SPEC_DIR/$PACKAGE_NAME.spec"
    
    if [ $? -eq 0 ]; then
        log_success "RPM construido exitosamente!"
        log_info "Archivos generados:"
        find "$RPMS_DIR" -name "*.rpm" -exec ls -la {} \;
        find "$SRPMS_DIR" -name "*.rpm" -exec ls -la {} \;
    else
        log_error "Error al construir el RPM con rpmbuild"
        exit 1
    fi
else
    log_warning "rpmbuild no está disponible, creando RPM manualmente..."
    
    # Crear estructura del RPM manualmente
    RPM_DIR="$BUILDROOT_DIR/$PACKAGE_NAME-$VERSION-$RELEASE.$ARCH"
    mkdir -p "$RPM_DIR"
    
    # Instalar archivos
    log_info "Instalando archivos en el RPM..."
    
    # Instalar Python package
    python3 -m pip install --no-deps --root "$RPM_DIR" --prefix /usr dist/*.whl
    
    # Crear directorios necesarios
    mkdir -p "$RPM_DIR/usr/bin"
    mkdir -p "$RPM_DIR/etc/repo-scan"
    mkdir -p "$RPM_DIR/var/lib/repo-scan"
    mkdir -p "$RPM_DIR/var/log/repo-scan"
    mkdir -p "$RPM_DIR/var/cache/repo-scan"
    mkdir -p "$RPM_DIR/usr/share/applications"
    mkdir -p "$RPM_DIR/usr/share/doc/repo-scan"
    
    # Instalar archivos de configuración
    if [ -f packaging/config.yaml ]; then
        cp packaging/config.yaml "$RPM_DIR/etc/repo-scan/"
    fi
    
    # Instalar desktop file
    if [ -f packaging/repo-scan-gui.desktop ]; then
        cp packaging/repo-scan-gui.desktop "$RPM_DIR/usr/share/applications/"
    fi
    
    # Instalar documentación
    cp README.md "$RPM_DIR/usr/share/doc/repo-scan/"
    cp CHANGELOG.md "$RPM_DIR/usr/share/doc/repo-scan/"
    cp LICENSE "$RPM_DIR/usr/share/doc/repo-scan/"
    
    # Crear script de instalación
    log_info "Creando script de instalación..."
    cat > install_repo_scan.sh << 'EOF'
#!/bin/bash
# Script de instalación para repo-scan

set -e

echo "Instalando repo-scan..."

# Verificar que se ejecute como root
if [ "$EUID" -ne 0 ]; then
    echo "Por favor ejecuta este script como root (sudo)"
    exit 1
fi

# Crear directorios
mkdir -p /var/lib/repo-scan
mkdir -p /var/log/repo-scan
mkdir -p /var/cache/repo-scan
mkdir -p /etc/repo-scan

# Instalar archivos
if [ -d "rpm_build/BUILDROOT/repo-scan-1.0.0-1.noarch" ]; then
    cp -r rpm_build/BUILDROOT/repo-scan-1.0.0-1.noarch/* /
else
    echo "Error: No se encontró el directorio de instalación"
    exit 1
fi

# Configurar permisos
chown -R root:root /usr/lib/python3.*/site-packages/repo_scan*
chmod +x /usr/bin/repo-scan
chmod +x /usr/bin/repo-scan-gui

# Actualizar base de datos de aplicaciones
if command -v update-desktop-database &> /dev/null; then
    update-desktop-database /usr/share/applications
fi

# Actualizar systemd si existe el servicio
if [ -f /usr/lib/systemd/system/repo-scan.service ]; then
    systemctl daemon-reload
fi

echo "¡repo-scan instalado exitosamente!"
echo ""
echo "Comandos disponibles:"
echo "  repo-scan --help          # CLI help"
echo "  repo-scan-gui             # GUI de escritorio"
echo "  repo-scan-gui --web       # Interfaz web"
echo ""
echo "Configuración: /etc/repo-scan/config.yaml"
echo "Logs: /var/log/repo-scan/"
echo "Datos: /var/lib/repo-scan/"
EOF
    
    chmod +x install_repo_scan.sh
    
    log_success "Estructura del RPM creada manualmente!"
    log_info "Para instalar, ejecuta: sudo ./install_repo_scan.sh"
fi

log_success "Construcción completada!"
log_info "Archivos generados en: $BUILD_DIR/"
