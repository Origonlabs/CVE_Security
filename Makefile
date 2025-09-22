# Makefile for repo-scan project

.PHONY: help install install-dev test lint format clean build package install-rpm run serve

# Default target
help:
	@echo "Available targets:"
	@echo "  install      - Install repo-scan package"
	@echo "  install-dev  - Install in development mode with dev dependencies"
	@echo "  test         - Run tests"
	@echo "  lint         - Run linting checks"
	@echo "  format       - Format code with black and isort"
	@echo "  clean        - Clean build artifacts"
	@echo "  build        - Build package"
	@echo "  package      - Create RPM package"
	@echo "  install-rpm  - Install RPM package"
	@echo "  run          - Run repo-scan CLI"
	@echo "  serve        - Start API server"

# Installation targets
install:
	pip install .

install-dev:
	pip install -e ".[dev]"
	pre-commit install

# Testing
test:
	pytest tests/ -v --cov=repo_scan --cov-report=html --cov-report=term-missing

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

# Code quality
lint:
	flake8 src/ tests/
	mypy src/
	black --check src/ tests/
	isort --check-only src/ tests/

format:
	black src/ tests/
	isort src/ tests/

# Build and packaging
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build: clean
	python -m build

package: build
	@echo "Creating RPM package..."
	rpmbuild -ba packaging/repo-scan.spec \
		--define "_sourcedir $(PWD)/dist" \
		--define "_builddir $(PWD)/build" \
		--define "_rpmdir $(PWD)/dist"

install-rpm:
	sudo dnf install dist/repo-scan-1.0.0-1.fc38.noarch.rpm

# Development
run:
	python -m repo_scan

serve:
	python -m repo_scan serve --host 0.0.0.0 --port 8000

# Docker targets
docker-build:
	docker build -t repo-scan:latest .

docker-run:
	docker run -it --rm -v $(PWD):/workspace repo-scan:latest

# Documentation
docs:
	@echo "Generating documentation..."
	# Add documentation generation commands here

# Security scanning
security-scan:
	@echo "Running security scan on the project..."
	bandit -r src/
	safety check
	semgrep --config=auto src/

# Dependencies
install-deps:
	@echo "Installing system dependencies..."
	sudo dnf install -y python3 python3-pip python3-devel git curl wget
	pip install semgrep bandit checkov

# Quick setup for development
setup-dev: install-deps install-dev
	@echo "Development environment setup complete!"

# CI/CD helpers
ci-test: lint test
	@echo "CI tests passed!"

ci-package: clean build package
	@echo "Package created successfully!"

# Release helpers
release-check:
	@echo "Checking release requirements..."
	@python -c "import repo_scan; print(f'Version: {repo_scan.__version__}')"
	@git status --porcelain | grep -q . && echo "Working directory not clean!" || echo "Working directory clean"

release: release-check clean build package
	@echo "Release package ready!"

# Utility targets
check-scanners:
	@echo "Checking scanner availability..."
	@which semgrep && echo "✓ Semgrep available" || echo "✗ Semgrep not found"
	@which gitleaks && echo "✓ Gitleaks available" || echo "✗ Gitleaks not found"
	@which trivy && echo "✓ Trivy available" || echo "✗ Trivy not found"
	@which bandit && echo "✓ Bandit available" || echo "✗ Bandit not found"
	@which checkov && echo "✓ Checkov available" || echo "✗ Checkov not found"

demo:
	@echo "Running demo scan..."
	python -m repo_scan --path . --format all --output ./demo-reports

# Help for specific targets
help-install:
	@echo "Installation options:"
	@echo "  make install      - Install from PyPI or local package"
	@echo "  make install-dev  - Install in development mode"
	@echo "  make install-rpm  - Install from RPM package"

help-test:
	@echo "Testing options:"
	@echo "  make test         - Run all tests with coverage"
	@echo "  make test-unit    - Run unit tests only"
	@echo "  make test-integration - Run integration tests only"

help-build:
	@echo "Build options:"
	@echo "  make build        - Build Python package"
	@echo "  make package      - Create RPM package"
	@echo "  make clean        - Clean build artifacts"
