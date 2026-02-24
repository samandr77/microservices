.PHONY: up down up-docker lint test gen tls-ca tls-server tls-client clean-tls run-mtls run-no-mtls

# App start and down
up:
	@docker compose -f ../docker/docker-compose.yml up --remove-orphans -d pg

down:
	@docker compose -f ../docker/docker-compose.yml down

up-docker:
	@docker compose -f ../docker/docker-compose.yml up --force-recreate --remove-orphans -d --build

# Linter
lint:
	@golangci-lint run -c ./.golangci.yml

# Tests
test:
	@go test -v -race ./...

# Swagger docs
gen:
	@swag init -g ./internal/api/handler.go

# === TLS / mTLS generation ===
tls-dir := ./certs
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
	openssl req -x509 -new -nodes -key $(ca-key) -sha256 -days 3650 -out $(ca-cert) -subj "/C=RU/ST=Moscow/L=Moscow/O=MyOrg/OU=Dev/CN=MyRootCA"

# 2. Generate Server cert signed by CA
tls-server:
	openssl genrsa -out $(server-key) 2048
	openssl req -new -key $(server-key) -out $(server-csr) -subj "/C=RU/ST=Moscow/L=Moscow/O=MyOrg/OU=Dev/CN=localhost"
	openssl x509 -req -in $(server-csr) -CA $(ca-cert) -CAkey $(ca-key) -CAcreateserial -out $(server-cert) -days 825 -sha256

# 3. Generate Client cert signed by CA
tls-client:
	openssl genrsa -out $(client-key) 2048
	openssl req -new -key $(client-key) -out $(client-csr) -subj "/C=RU/ST=Moscow/L=Moscow/O=MyOrg/OU=Dev/CN=client"
	openssl x509 -req -in $(client-csr) -CA $(ca-cert) -CAkey $(ca-key) -CAcreateserial -out $(client-cert) -days 825 -sha256

# Clean certs
clean-tls:
	rm -rf $(tls-dir)/*.key $(tls-dir)/*.crt $(tls-dir)/*.csr $(tls-dir)/*.srl
