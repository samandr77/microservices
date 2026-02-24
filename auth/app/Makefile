.PHONY: up down

pg_dsn := "user=postgres dbname=postgres password=dev host=localhost port=15432 sslmode=disable"

# App start and down
up:
	docker compose -f ../docker/docker-compose.yml up --remove-orphans -d pg

down:
	docker compose -f ../docker/docker-compose.yml down

up-docker:
	docker compose -f ../docker/docker-compose.yml up --force-recreate --remove-orphans -d --build

# Migrations
migrate-new:
	goose -dir ./migrations create $(name) sql

migrate-up:
	goose -dir ./migrations postgres ${pg_dsn} up

migrate-down:
	goose -dir ./migrations postgres ${pg_dsn} down 1

migrate-drop:
	goose -dir ./migrations postgres ${pg_dsn} reset

# Tests
test: up migrate-up
	go test -v -race ./...

test-integration: up migrate-up
	docker exec auth-pg psql -U postgres -d postgres -c "TRUNCATE verification_codes CASCADE;" || true
	go test -tags=integration -v ./internal/repository/... -run TestCodeRepositoryTestSuite

test-all: up migrate-up
	docker exec auth-pg psql -U postgres -d postgres -c "TRUNCATE verification_codes, attempts, token CASCADE;" || true
	go test -tags=integration -v -p 1 -parallel 1 -count=1 ./internal/repository/...

# Linter
lint:
	@golangci-lint run -c ./.golangci.yml

# Generation
gen:
	swag init -g ./internal/api/handler.go

# === TLS / mTLS generation ===
tls-dir := ../certs
ca-key := $(tls-dir)/ca.key
ca-cert := $(tls-dir)/ca.crt
server-key := $(tls-dir)/server.key
server-csr := $(tls-dir)/server.csr
server-cert := $(tls-dir)/server.crt
client-key := $(tls-dir)/client.key
client-csr := $(tls-dir)/client.csr
client-cert := $(tls-dir)/client.crt

# 1. Generate CA
tls-ca:
	mkdir -p $(tls-dir)
	openssl genrsa -out $(ca-key) 4096
	openssl req -x509 -new -nodes -key $(ca-key) -sha256 -days 3650 -out $(ca-cert) -subj "/C=RU/ST=Moscow/L=Moscow/O=Blago/OU=Dev/CN=BlagoRootCA"

# 2. Generate Server cert signed by CA
tls-server:
	openssl genrsa -out $(server-key) 2048
	openssl req -new -key $(server-key) -out $(server-csr) -subj "/C=RU/ST=Moscow/L=Moscow/O=Blago/OU=Dev/CN=localhost"
	openssl x509 -req -in $(server-csr) -CA $(ca-cert) -CAkey $(ca-key) -CAcreateserial -out $(server-cert) -days 825 -sha256

# 3. Generate Client cert signed by CA
tls-client:
	openssl genrsa -out $(client-key) 2048
	openssl req -new -key $(client-key) -out $(client-csr) -subj "/C=RU/ST=Moscow/L=Moscow/O=Blago/OU=Dev/CN=client"
	openssl x509 -req -in $(client-csr) -CA $(ca-cert) -CAkey $(ca-key) -CAcreateserial -out $(client-cert) -days 825 -sha256

# Clean certs
clean-tls:
	rm -rf $(tls-dir)/*.key $(tls-dir)/*.crt $(tls-dir)/*.csr $(tls-dir)/*.srl

