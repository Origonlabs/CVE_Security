#!/bin/bash
# Repo-Scan Installation Script for Fedora
# This script installs repo-scan and its dependencies

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO_SCAN_VERSION="$(python3 -c "import tomllib;print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])")"
INSTALL_DIR="/opt/repo-scan"
CONFIG_DIR="/etc/repo-scan"
DATA_DIR="/var/lib/repo-scan"
LOG_DIR="/var/log/repo-scan"
CACHE_DIR="/var/cache/repo-scan"
SERVICE_USER="repo-scan"

# Functions
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

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_fedora() {
    if ! command -v dnf &> /dev/null; then
        log_error "This script is designed for Fedora. Please use the appropriate package manager for your distribution."
        exit 1
    fi
}

install_dependencies() {
    log_info "Installing system dependencies..."
    
    # Update package database
    dnf update -y
    
    # Install Python and development tools
    dnf install -y \
        python3 \
        python3-devel \
        python3-pip \
        python3-setuptools \
        python3-wheel \
        python3-build \
        git \
        curl \
        wget \
        unzip \
        tar \
        gzip
    
    # Install security scanning tools
    log_info "Installing security scanning tools..."
    
    # Install Semgrep
    if ! command -v semgrep &> /dev/null; then
        log_info "Installing Semgrep..."
        python3 -m pip install semgrep
    else
        log_success "Semgrep already installed"
    fi
    
    # Install Gitleaks
    if ! command -v gitleaks &> /dev/null; then
        log_info "Installing Gitleaks..."
        # Download and install Gitleaks
        GITLEAKS_VERSION="8.18.0"
        wget -O /tmp/gitleaks.tar.gz "https://github.com/zricethezav/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
        tar -xzf /tmp/gitleaks.tar.gz -C /tmp
        mv /tmp/gitleaks /usr/local/bin/
        chmod +x /usr/local/bin/gitleaks
        rm /tmp/gitleaks.tar.gz
    else
        log_success "Gitleaks already installed"
    fi
    
    # Install Trivy
    if ! command -v trivy &> /dev/null; then
        log_info "Installing Trivy..."
        TRIVY_VERSION="0.45.1"
        TRIVY_ARCHIVE="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
        curl -sSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${TRIVY_ARCHIVE}" -o /tmp/${TRIVY_ARCHIVE}
        tar -xzf /tmp/${TRIVY_ARCHIVE} -C /tmp
        install -m 0755 /tmp/trivy /usr/local/bin/trivy
        rm -f /tmp/${TRIVY_ARCHIVE} /tmp/trivy
    else
        log_success "Trivy already installed"
    fi
    
    # Install Bandit
    if ! command -v bandit &> /dev/null; then
        log_info "Installing Bandit..."
        python3 -m pip install bandit
    else
        log_success "Bandit already installed"
    fi
    
    # Install Checkov
    if ! command -v checkov &> /dev/null; then
        log_info "Installing Checkov..."
        python3 -m pip install checkov
    else
        log_success "Checkov already installed"
    fi
    
    # Install Docker (optional, for container scanning)
    if ! command -v docker &> /dev/null; then
        log_info "Installing Docker..."
        dnf install -y docker
        systemctl enable docker
        systemctl start docker
    else
        log_success "Docker already installed"
    fi
}

create_directories() {
    log_info "Creating directories..."
    
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$CACHE_DIR"
    mkdir -p "/var/tmp/repo-scan"
}

create_user() {
    log_info "Creating system user..."
    
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$DATA_DIR" -c "Repo-Scan Service User" "$SERVICE_USER"
        log_success "Created user: $SERVICE_USER"
    else
        log_success "User already exists: $SERVICE_USER"
    fi
}

install_repo_scan() {
    log_info "Installing repo-scan..."
    
    # Install Python dependencies
    python3 -m pip install --upgrade pip
    
    # Install repo-scan package
    if [[ -f "dist/repo_scan-${REPO_SCAN_VERSION}-py3-none-any.whl" ]]; then
        python3 -m pip install "dist/repo_scan-${REPO_SCAN_VERSION}-py3-none-any.whl"
    else
        log_error "repo-scan wheel not found. Please build the package first."
        exit 1
    fi
    
    log_success "repo-scan installed successfully"
}

install_config_files() {
    log_info "Installing configuration files..."
    
    # Copy configuration files
    cp packaging/config.yaml "$CONFIG_DIR/"
    cp packaging/repo-scan.service /etc/systemd/system/
    
    # Set permissions
    chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR" "$LOG_DIR" "$CACHE_DIR"
    chmod 755 "$CONFIG_DIR"
    chmod 644 "$CONFIG_DIR/config.yaml"
    chmod 644 /etc/systemd/system/repo-scan.service
}

install_completions() {
    log_info "Installing shell completions..."
    
    # Install bash completion
    mkdir -p /usr/share/bash-completion/completions
    cp packaging/repo-scan.bash-completion /usr/share/bash-completion/completions/repo-scan
    
    # Install zsh completion
    mkdir -p /usr/share/zsh/site-functions
    cp packaging/_repo-scan /usr/share/zsh/site-functions/_repo-scan
    
    log_success "Shell completions installed"
}

install_man_page() {
    log_info "Installing man page..."
    
    mkdir -p /usr/share/man/man1
    cp packaging/repo-scan.1 /usr/share/man/man1/
    gzip /usr/share/man/man1/repo-scan.1
    
    log_success "Man page installed"
}

install_desktop_file() {
    log_info "Installing desktop file..."
    
    # Install desktop file for GUI
    mkdir -p /usr/share/applications
    cp packaging/repo-scan-gui.desktop /usr/share/applications/
    
    # Update desktop database
    if command -v update-desktop-database &> /dev/null; then
        update-desktop-database /usr/share/applications
    fi
    
    log_success "Desktop file installed"
}

setup_systemd() {
    log_info "Setting up systemd service..."
    
    systemctl daemon-reload
    systemctl enable repo-scan.service
    
    log_success "Systemd service configured"
}

verify_installation() {
    log_info "Verifying installation..."
    
    # Check if repo-scan command is available
    if command -v repo-scan &> /dev/null; then
        log_success "repo-scan command is available"
        repo-scan --version
    else
        log_error "repo-scan command not found"
        exit 1
    fi
    
    # Check if service is configured
    if systemctl is-enabled repo-scan.service &> /dev/null; then
        log_success "repo-scan service is enabled"
    else
        log_warning "repo-scan service is not enabled"
    fi
    
    # Check if all scanners are available
    log_info "Checking scanner availability..."
    
    scanners=("semgrep" "gitleaks" "trivy" "bandit" "checkov")
    for scanner in "${scanners[@]}"; do
        if command -v "$scanner" &> /dev/null; then
            log_success "$scanner is available"
        else
            log_warning "$scanner is not available"
        fi
    done
    
    # Check GUI availability
    if command -v repo-scan-gui &> /dev/null; then
        log_success "GUI launcher is available"
    else
        log_warning "GUI launcher not found"
    fi
}

show_next_steps() {
    log_success "Installation completed successfully!"
    echo
    echo "Next steps:"
    echo "1. Start the service: systemctl start repo-scan"
    echo "2. Check service status: systemctl status repo-scan"
    echo "3. View logs: journalctl -u repo-scan -f"
    echo "4. Configure repo-scan: edit $CONFIG_DIR/config.yaml"
    echo "5. Test the installation: repo-scan --help"
    echo
    echo "GUI Options:"
    echo "• Desktop GUI: repo-scan-gui"
    echo "• Web Interface: repo-scan-gui --web"
    echo "• Web Interface (custom port): repo-scan-gui --web --port 8080"
    echo
    echo "API will be available at: http://localhost:8000"
    echo "Documentation: https://github.com/example/repo-scan"
}

main() {
    log_info "Starting repo-scan installation..."
    
    check_root
    check_fedora
    
    install_dependencies
    create_directories
    create_user
    install_repo_scan
    install_config_files
    install_completions
    install_man_page
    install_desktop_file
    setup_systemd
    verify_installation
    show_next_steps
}

# Run main function
main "$@"
