# build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY ../app ./
RUN go mod download
RUN go build -o notification ./cmd/

# runtime stage
FROM alpine:latest

WORKDIR /app

# переменные окружения (будут задаваться через compose или .env)
ENV HTTP_PORT=8082

# SMTP
ENV MAILER_HOST=""
ENV MAILER_PORT=587
ENV MAILER_ENCRYPTION="tls"
ENV MAILER_FROM=""
ENV MAILER_FROM_NAME=""
ENV MAILER_LOGIN=""
ENV MAILER_PASSWORD=""

# TLS / mTLS
ENV TLS_SERVER_CERT="/app/certs/server.crt"
ENV TLS_SERVER_KEY="/app/certs/server.key"
ENV TLS_CA_CERT="/app/certs/ca.crt"

# копируем бинарь
COPY --from=builder /app/notification .

# копируем сертификаты (ожидаем, что ./certs смонтирован томом)
RUN mkdir -p /app/certs

EXPOSE 8082

CMD ["./notification"]
