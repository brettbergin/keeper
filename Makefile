.PHONY: help install install-dev sync sync-dev add add-dev remove update update-pkg venv tree clean lint format type-check test test-cov run run-prod db-init db-migrate db-upgrade docker-build docker-run docker-stop all-checks

# Default target
help:
	@echo "Keeper - Secret Management Application"
	@echo ""
	@echo "Available targets:"
	@echo "  install      Install production dependencies"
	@echo "  install-dev  Install all dependencies (including dev)"
	@echo "  sync         Sync dependencies from pyproject.toml"
	@echo "  sync-dev     Sync all dependencies (including dev)"
	@echo "  add          Add a new dependency (usage: make add pkg=<package>)"
	@echo "  add-dev      Add a dev dependency (usage: make add-dev pkg=<package>)"
	@echo "  remove       Remove a dependency (usage: make remove pkg=<package>)"
	@echo "  update       Update all dependencies"
	@echo "  update-pkg   Update specific package (usage: make update-pkg pkg=<package>)"
	@echo "  tree         Show dependency tree"
	@echo "  venv         Create virtual environment with uv"
	@echo "  clean        Clean up cache files and build artifacts"
	@echo "  lint         Run ruff linter"
	@echo "  format       Format code with black and isort"
	@echo "  type-check   Run mypy type checker"
	@echo "  test         Run pytest"
	@echo "  test-cov     Run pytest with coverage report"
	@echo "  run          Run development server"
	@echo "  run-prod     Run production server with gunicorn"
	@echo "  db-init      Initialize the database"
	@echo "  populate-demo Populate database with demo users and secrets"
	@echo "  db-reset-demo Reset database and populate with demo data"
	@echo "  clean-db     Clean database files"
	@echo "  db-migrate   Create database migration"
	@echo "  db-upgrade   Apply database migrations"
	@echo "  docker-build Build Docker image"
	@echo "  docker-run   Run Docker container"
	@echo "  docker-stop  Stop Docker container"
	@echo "  all-checks   Run all quality checks (lint, format, type-check, test)"

# Installation targets
install:
	uv sync

install-dev:
	uv sync --dev

# Sync dependencies (uv-specific)
sync:
	uv sync

sync-dev:
	uv sync --dev

# Add a new dependency
add:
	@if [ -z "$(pkg)" ]; then echo "Usage: make add pkg=<package>"; exit 1; fi
	uv add $(pkg)

# Add a development dependency
add-dev:
	@if [ -z "$(pkg)" ]; then echo "Usage: make add-dev pkg=<package>"; exit 1; fi
	uv add --dev $(pkg)

# Remove a dependency
remove:
	@if [ -z "$(pkg)" ]; then echo "Usage: make remove pkg=<package>"; exit 1; fi
	uv remove $(pkg)

# Update dependencies
update:
	uv sync --upgrade

# Update a specific package
update-pkg:
	@if [ -z "$(pkg)" ]; then echo "Usage: make update-pkg pkg=<package>"; exit 1; fi
	uv add $(pkg) --upgrade

# Create virtual environment with uv
venv:
	uv venv

# Show dependency tree
tree:
	uv tree

# Cleanup
clean:
	rm -rf __pycache__/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

# Code quality targets
lint:
	uv run ruff check keeper/ tests/

lint-fix:
	uv run ruff check --fix keeper/ tests/

format:
	uv run black keeper/ tests/
	uv run isort keeper/ tests/

format-check:
	uv run black --check keeper/ tests/
	uv run isort --check-only keeper/ tests/

type-check:
	uv run mypy keeper/

# Testing targets
test:
	uv run pytest tests/ -v

test-cov:
	uv run pytest tests/ --cov=keeper --cov-report=html --cov-report=term-missing

test-unit:
	uv run pytest tests/ -m "unit" -v

test-integration:
	uv run pytest tests/ -m "integration" -v

# Development server
run:
	uv run python -m keeper.cli run --debug

run-prod:
	uv run gunicorn -c gunicorn.conf.py wsgi:app

# Database operations
db-init:
	uv run python -m keeper.cli init-db

# Demo data population
populate-demo:
	uv run python scripts/populate_demo_data.py

# Reset database and populate with demo data
db-reset-demo: clean-db populate-demo
	@echo "Database reset and populated with demo data!"

# Clean database
clean-db:
	rm -rf instance/
	@echo "Database cleaned!"

# Docker operations
docker-build:
	docker build -t keeper:latest .

docker-run:
	docker run -d --name keeper-app -p 8000:8000 keeper:latest

docker-stop:
	docker stop keeper-app && docker rm keeper-app

docker-logs:
	docker logs -f keeper-app

# Quality assurance - run all checks
all-checks: lint-fix format-check type-check test

# Development workflow
dev-setup: sync-dev db-init
	@echo "Development environment setup complete!"

# Pre-commit checks
pre-commit: format lint type-check test
	@echo "All pre-commit checks passed!"

# Security checks (optional)
security-check:
	uv pip install pip-audit
	pip-audit

# Documentation (if using sphinx)
docs:
	@echo "Documentation generation not yet implemented"

# Backup database
backup-db:
	cp keeper.db keeper.db.backup.$(shell date +%Y%m%d_%H%M%S)

# Show project info
info:
	@echo "Project: Keeper"
	@echo "Version: $(shell uv run python -c 'from keeper import __version__; print(__version__)' 2>/dev/null || echo 'Unknown')"
	@echo "Python: $(shell uv run python --version)"
	@echo "UV: $(shell uv --version 2>/dev/null || echo 'Not installed')"
	@echo "Dependencies:"
	@uv pip list | grep -E "(Flask|SQLAlchemy|boto3|hvac|pydantic)" 2>/dev/null || echo "No dependencies found"