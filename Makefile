CONTAINER_RUNTIME ?= podman
PROFILE ?= all
COMPOSE = $(CONTAINER_RUNTIME) compose -f deploy/compose.yaml --profile $(PROFILE)

export BAE6_CONTAINER_RUNTIME = $(CONTAINER_RUNTIME)

.PHONY: install format lint typecheck test model-test migrate integration demo up down

install:
	pnpm install --frozen-lockfile
	uv sync --frozen

format:
	pnpm format
	uv run ruff format .

lint:
	pnpm lint
	uv run ruff check .

typecheck:
	pnpm typecheck

test:
	pnpm test
	uv run pytest

model-test:
	pnpm --filter @bae6/authz-scripts test

migrate:
	pnpm --filter @bae6/authz-api migrate

integration:
	BAE6_API_URL=http://localhost:8080 OPENFGA_API_URL=http://localhost:8180 pnpm --filter @bae6/authz-api test:integration
	BAE6_API_URL=http://localhost:8080 OPENFGA_API_URL=http://localhost:8180 pnpm --filter @bae6/authz test:integration

demo:
	node --test e2e/integration/demo.test.mjs e2e/integration/workers.test.mjs e2e/integration/console.test.mjs

up:
	$(COMPOSE) up --build -d --wait

down:
	$(COMPOSE) down
