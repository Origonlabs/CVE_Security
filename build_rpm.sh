#!/usr/bin/env bash
# Build RPMs for repo-scan using the canonical spec file.
# The script reads the version from pyproject.toml, builds the Python artifacts
# and invokes rpmbuild pointing at packaging/repo-scan.spec.

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

if ! command -v rpmbuild >/dev/null 2>&1; then
    err "rpmbuild command not found. Install rpm-build (dnf install rpm-build)."
    exit 1
fi

version="$(python3 -c "import tomllib;print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])")"
release="1"
log "Detected version ${version} (release ${release})."

if ! python3 -c "import build" >/dev/null 2>&1; then
    err "Python module 'build' is missing. Install it with 'sudo dnf install python3-build'."
    exit 1
fi

if ! python3 -c "import wheel" >/dev/null 2>&1; then
    err "Python module 'wheel' is missing. Install it with 'sudo dnf install python3-wheel'."
    exit 1
fi

build_dir="${project_root}/rpm_build"
spec_file="${project_root}/packaging/repo-scan.spec"
dist_dir="${project_root}/dist"

log "Cleaning previous artifacts..."
rm -rf "$build_dir"
mkdir -p "$build_dir"

log "Building Python distributions (sdist + wheel)..."
python3 -m build > /tmp/repo-scan-build.log
ok "Python artifacts generated in dist/."

expected_tar="${dist_dir}/repo-scan-${version}.tar.gz"
if [[ ! -f "$expected_tar" ]]; then
    err "Source tarball ${expected_tar} not found."
    exit 1
fi

log "Invoking rpmbuild..."
rpmbuild \
    --define "_topdir ${build_dir}" \
    --define "_sourcedir ${dist_dir}" \
    --define "_srcrpmdir ${dist_dir}" \
    --define "_rpmdir ${dist_dir}" \
    --define "_builddir ${build_dir}/BUILD" \
    --define "_specdir ${project_root}/packaging" \
    -ba "$spec_file"

ok "RPM build completed."

log "Generated RPMs:"
find "${dist_dir}" -name "repo-scan-${version}-${release}*.rpm" -print || warn "No RPM files produced."
