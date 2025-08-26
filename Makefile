# Code Hygiene Agent - Development Makefile

.PHONY: help install install-dev test lint format type-check security build clean docker-build docker-run docker-test serve analyze

# Default target
help: ## Show this help message
	@echo "Code Hygiene Agent - Development Commands"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Installation
install: ## Install the package in production mode
	pip install -e .

install-dev: ## Install development dependencies
	pip install -r requirements-dev.txt
	pip install -e .
	pre-commit install

install-tools: ## Install external analysis tools
	pip install pip-audit safety vulture bandit semgrep

# Development
format: ## Format code with black and ruff
	black src/ tests/
	ruff format src/ tests/

lint: ## Run linting with ruff
	ruff check src/ tests/

type-check: ## Run type checking with mypy
	mypy src/code_hygiene_agent/

# Testing
test: ## Run unit tests
	pytest tests/unit/ -v

test-integration: ## Run integration tests
	pytest tests/integration/ -v

test-all: ## Run all tests with coverage
	pytest -v --cov=src/code_hygiene_agent --cov-report=term-missing --cov-report=html

test-fast: ## Run fast tests only (exclude slow tests)
	pytest -v -m "not slow"

# Security
security: ## Run security checks
	safety check
	bandit -r src/
	pip-audit

# Quality
quality: lint type-check security ## Run all quality checks

# Build
build: ## Build package distributions
	python -m build

clean: ## Clean build artifacts
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf .pytest_cache/
	rm -rf .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

# Docker
docker-build: ## Build Docker image
	docker build -t code-hygiene-agent:latest .

docker-build-dev: ## Build development Docker image
	docker build --target development -t code-hygiene-agent:dev .

docker-run: ## Run Docker container
	docker-compose up code-hygiene-agent

docker-dev: ## Run development Docker container
	docker-compose --profile dev up code-hygiene-dev

docker-test: ## Run tests in Docker
	docker-compose --profile test run --rm test

# Application
serve: ## Start the MCP server
	code-hygiene-agent serve

analyze: ## Analyze current directory (requires PROJECT_PATH env var or default to .)
	code-hygiene-agent analyze ${PROJECT_PATH:-.}

check: ## Check availability of external tools  
	code-hygiene-agent check

info: ## Show analyzer information
	code-hygiene-agent info

# Documentation
docs: ## Generate documentation (placeholder)
	@echo "Documentation generation not implemented yet"

# Release
release-test: build ## Test package release
	twine check dist/*

release: build ## Release to PyPI (requires TWINE_* env vars)
	twine upload dist/*

# CI/CD simulation
ci: quality test-all security ## Run all CI checks locally

# Development setup
setup-dev: install-dev install-tools ## Complete development setup
	@echo "Development environment setup complete!"
	@echo "Don't forget to copy .env.example to .env and configure your settings"

# Sample project for testing
create-sample: ## Create a sample project for testing
	mkdir -p sample-project/src
	echo "requests==2.25.0\nflask==1.1.0" > sample-project/requirements.txt
	echo "import os\nimport unused_module\n\ndef used_func():\n    return os.getcwd()\n\ndef unused_func():\n    pass" > sample-project/src/main.py
	@echo "Sample project created in ./sample-project/"

# Environment
env-check: ## Check environment configuration
	@echo "Checking environment configuration..."
	@python -c "from code_hygiene_agent.config.settings import settings; print('✅ Configuration loaded successfully')" || echo "❌ Configuration error"

# Utilities
logs: ## Show recent logs (if running with Docker)
	docker-compose logs -f code-hygiene-agent

restart: ## Restart services
	docker-compose restart

down: ## Stop all services
	docker-compose down

# Pre-commit hooks
pre-commit: format lint type-check test-fast ## Run pre-commit checks

# Version info
version: ## Show version information
	@python -c "from code_hygiene_agent import __version__; print(f'Code Hygiene Agent v{__version__}')"