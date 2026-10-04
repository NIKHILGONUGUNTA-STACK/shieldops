.DEFAULT_GOAL := help

.PHONY: help setup start stop status logs validate

help:
	@echo "Aegis local development commands"
	@echo "  make setup    Create config/dev.env from its example"
	@echo "  make start    Start dependencies and synthetic business services"
	@echo "  make stop     Stop the development stack"
	@echo "  make status   Show development stack status"
	@echo "  make logs     Follow development stack logs"
	@echo "  make validate Validate the Docker Compose configuration"

setup:
	pwsh -File scripts/setup-dev.ps1

start:
	pwsh -File scripts/start-dev.ps1

stop:
	pwsh -File scripts/stop-dev.ps1

status:
	pwsh -File scripts/status-dev.ps1

logs:
	pwsh -File scripts/logs-dev.ps1

validate:
	pwsh -File scripts/validate-dev.ps1
