FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY ../app/go.mod ../app/go.sum ./
RUN go mod download

COPY app ./
RUN go build -o ./auth ./cmd/

FROM alpine:latest

WORKDIR /app
COPY --from=builder /app/auth .

EXPOSE 8081
ENTRYPOINT [ "/app/auth" ]
