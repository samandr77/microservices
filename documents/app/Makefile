.PHONY: up down

pg_dsn := "user=postgres dbname=postgres password=dev host=localhost port=15436 sslmode=disable"

# App start and down
up:
	docker compose -f ../docker/docker-compose.yml up --remove-orphans -d pg

down:
	docker compose -f ../docker/docker-compose.yml down

up-docker:
	docker compose -f ../docker/docker-compose.yml up --force-recreate --remove-orphans -d --build


# Migrations
migrate-new:
	@goose -dir ./migrations create $(name) sql

migrate-up:
	@goose -dir ./migrations postgres ${pg_dsn} up

migrate-down:
	@goose -dir ./migrations postgres ${pg_dsn} down

migrate-drop:
	@goose -dir ./migrations postgres ${pg_dsn} drop
	
# Linter
lint:
	@golangci-lint run -v ./...

# Tests
test:
	docker rm -f test-russ-documents
	docker run --rm --name test-russ-documents -e POSTGRES_PASSWORD=dev -p 15489:5432 -d postgres:16.3-alpine
	sleep 3
	goose -dir ./migrations postgres "user=postgres dbname=postgres password=dev host=localhost port=15489 sslmode=disable" up
	TEST_POSTGRES_DSN=postgres://postgres:dev@localhost:15489/postgres?sslmode=disable go test -v -race ./...


# Generation
gen:
	go generate ./...
	swag init -g ./internal/api/handler.go
