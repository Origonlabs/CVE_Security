# Proceso de Release 1.1.x

Este documento describe cómo generar los artefactos de distribución (wheel, sdist y RPM)
y cómo realizar las validaciones previas al anuncio público.

## 1. Prerrequisitos

- Fedora 38 o superior con los paquetes `python3`, `python3-build`, `rpm-build` y `dnf-plugins-core`.
- Herramientas auxiliares: `semgrep`, `bandit`, `checkov`, `gitleaks` y `trivy` (recomendado).
- Árbol de trabajo limpio (`git status` sin ficheros pendientes).

## 2. Validaciones previas

```bash
make lint
make test
python -m repo_scan serve --host 127.0.0.1 --port 8000 --reload  # smoke test API
repo-scan-gui --web --port 8080                                 # smoke test UI
```

## 3. Generar artefactos Python

```bash
python -m build
ls dist/
# -> repo-scan-1.1.0.tar.gz (sdist)
# -> repo_scan-1.1.0-py3-none-any.whl (wheel)
```

## 4. Construir el RPM oficial

```bash
./build_rpm.sh
ls dist/ | grep repo-scan-1.1.0
# repo-scan-1.1.0-1.<dist>.noarch.rpm
# repo-scan-1.1.0-1.src.rpm
```

El script `build_rpm.sh` lee la versión desde `pyproject.toml`, ejecuta `python -m build`
y luego invoca `rpmbuild` apuntando a `packaging/repo-scan.spec`.

## 5. Verificación post build

```bash
rpm -qlp dist/repo-scan-1.1.0-1*.noarch.rpm | less
rpmlint dist/repo-scan-1.1.0-1*.rpm || true  # ignorar advertencias menores
```

Instalación de prueba en limpio:

```bash
sudo dnf install dist/repo-scan-1.1.0-1*.noarch.rpm
repo-scan --help
systemctl status repo-scan.service
```

## 6. Publicación

1. Crear etiqueta git `v1.1.0` y subir a origen.
2. Adjuntar `dist/repo-scan-1.1.0.tar.gz`, `.whl`, `.rpm` y `.src.rpm` en la release de GitHub.
3. Actualizar documentación externa y anunciar la disponibilidad del paquete.

¡Release listo!
