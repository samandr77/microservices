.PHONY: up down

pg_dsn := "postgres://postgres:dev@localhost:15432/postgres?sslmode=disable"

# App start and down
up:
	docker compose -f ../docker/docker-compose.yml up --remove-orphans -d pg

# To show running containers associated with this project
ps:
	docker compose -f ../docker/docker-compose.yml ps

down:
	docker compose -f ../docker/docker-compose.yml down

up-docker:
	docker compose -f ../docker/docker-compose.yml up --force-recreate --remove-orphans -d --build


# Migrations
migrate-new:
	goose -dir ./migrations create $(name) sql && goose -dir ./migrations fix

migrate-up:
	goose -dir ./migrations postgres ${pg_dsn} up

migrate-down:
	goose -dir ./migrations postgres ${pg_dsn} down

migrate-drop:
	goose -dir ./migrations postgres ${pg_dsn} drop
	
# Linter
lint:
	golangci-lint run

# Tests
test: test-down
	@docker run --rm --name test-payment-pg -p 15432:5432 -e POSTGRES_PASSWORD=dev -d postgres:16.3-alpine
	@sleep 2
	@goose -timeout 10s -dir ./migrations postgres ${pg_dsn} up
	@TEST_POSTGRES_DSN=${pg_dsn} go test -race ./...

test-down:
	@if [ -z "$(docker ps -q -f name=test-payment-pg)" ]; then docker rm -f test-payment-pg; fi


# Generation
gen:
	go generate ./...
	swag init -g internal/api/handler.go
	rm -r internal/api/gen
	go run github.com/go-swagger/go-swagger/cmd/swagger@latest generate client models -f ./docs/swagger.json -c ./internal/api/gen -m ./internal/api/gen/models
