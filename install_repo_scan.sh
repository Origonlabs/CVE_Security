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
