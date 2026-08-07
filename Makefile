.PHONY: install test lint run help clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install all dependencies
	uv sync

test: ## Run the test suite
	uv run pytest

test-v: ## Run tests with verbose output
	uv run pytest -v

run: ## Run the application (interactive menu)
	uv run python main.py

connect: ## Connect to RDP server (set HOST=host[:port], USER=, PASS= and optionally SECURITY=, WIDTH=, HEIGHT=, NOCERT=1)
	$(eval _HOST := $(firstword $(subst :, ,$(HOST))))
	$(eval _PORT := $(or $(word 2,$(subst :, ,$(HOST))),3389))
	uv run arrdipi connect \
		--host "$(_HOST)" \
		--port $(_PORT) \
		--user "$(USER)" \
		--password "$(PASS)" \
		$(if $(SECURITY),--security $(SECURITY),) \
		$(if $(WIDTH),--width $(WIDTH),) \
		$(if $(HEIGHT),--height $(HEIGHT),) \
		$(if $(NOCERT),--no-verify-cert,) \
		--clipboard-sync \
		--debug

menu: ## Open the interactive terminal menu
	uv run arrdipi menu

cli-help: ## Show CLI connect help
	uv run arrdipi connect --help

clean: ## Remove build artifacts and caches
	rm -rf dist/ build/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true

check: ## Verify the package imports correctly
	uv run python -c "import arrdipi; print(arrdipi.__name__)"
