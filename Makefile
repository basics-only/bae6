CONTAINER_RUNTIME ?= podman
PROFILE ?= all
COMPOSE = $(CONTAINER_RUNTIME) compose -f deploy/compose.yaml --profile $(PROFILE)

export BAE6_CONTAINER_RUNTIME = $(CONTAINER_RUNTIME)

.PHONY: install format lint typecheck test db-test model-test migrate integration demo up down tenant seed

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

demo: seed
	node --test e2e/integration/demo.test.mjs e2e/integration/workers.test.mjs e2e/integration/console.test.mjs e2e/integration/orgs.test.mjs

ORGS_OVERRIDE = e2e/orgs/compose.generated.json

# Each package's database-backed tests get a fresh database, apart from the ones the running services use.
DB_TESTS = services/authn/api:authn_test:test \
	services/authz/api:authz_test:test \
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

TENANT_ENV = deploy/.env

up:
	$(COMPOSE) up -d --wait postgres
	$(COMPOSE) exec -T postgres sh /docker-entrypoint-initdb.d/init.sh
	grep -qs '^BAE6_TENANT_STORE_ID=' $(TENANT_ENV) || $(MAKE) tenant
	$(COMPOSE) config --format json | node e2e/orgs/compose.mjs > $(ORGS_OVERRIDE)
	$(COMPOSE) -f deploy/compose/authz-tenant.yaml -f $(ORGS_OVERRIDE) up --build -d --wait
	if [ "$(PROFILE)" = all ]; then $(MAKE) seed; fi

# Once per stack: the acme tenant's OpenFGA store, whose ids authz and authn read from deploy/.env.
tenant:
	$(COMPOSE) up -d openfga
	for i in $$(seq 30); do curl -sf http://127.0.0.1:8180/healthz >/dev/null && break; sleep 1; done
	OPENFGA_API_URL=http://127.0.0.1:8180 pnpm --silent --filter @bae6/authz-scripts model bootstrap-tenant --organization acme > $(TENANT_ENV).tenant
	cat $(TENANT_ENV).tenant >> $(TENANT_ENV)
	rm $(TENANT_ENV).tenant

seed:
	node e2e/seed.mjs

down:
	$(COMPOSE) down
