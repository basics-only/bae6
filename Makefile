CONTAINER_RUNTIME ?= podman
PROFILE ?= all
COMPOSE = $(CONTAINER_RUNTIME) compose -f deploy/compose.yaml --profile $(PROFILE)

export BAE6_CONTAINER_RUNTIME = $(CONTAINER_RUNTIME)

.PHONY: install format lint typecheck test db-test model-test migrate integration demo up down

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

# Each package's database-backed tests get a fresh database, apart from the ones the running services use.
DB_TESTS = services/authz/api:authz_test:test \
	services/authz/api/tests/security:authz_security_test:test:security \
	services/ai/gateway:ai_test:test services/ai/agent-worker:agents_test:test \
	services/ai/eval-worker:evals_test:test \
	packages/context/data-postgres:data_test:test packages/context/embed-pgvector:embed_test:test
DB_ADMIN_URL = postgres://postgres:$${POSTGRES_ADMIN_PASSWORD:-dev-only-admin}@127.0.0.1:5432

db-test:
	@set -e; for entry in $(DB_TESTS); do \
	  dir=$${entry%%:*}; rest=$${entry#*:}; db=$${rest%%:*}; script=$${rest#*:}; \
	  $(COMPOSE) exec -T postgres psql -U postgres -q -c "DROP DATABASE IF EXISTS $$db WITH (FORCE)" -c "CREATE DATABASE $$db"; \
	  BAE6_DATABASE_URL=$(DB_ADMIN_URL)/$$db BAE6_EMBED_DATABASE_URL=$(DB_ADMIN_URL)/$$db \
	    OPENFGA_API_URL=http://127.0.0.1:8180 pnpm -C $$dir run $$script; \
	done

up:
	$(COMPOSE) up --build -d --wait

down:
	$(COMPOSE) down
