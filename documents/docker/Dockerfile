FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY ../app/go.* ./
RUN go mod download

COPY ../app ./
RUN go build -o ./documents ./cmd/

FROM alpine:latest

WORKDIR /app
COPY --from=builder /app/documents .

EXPOSE 8080
ENTRYPOINT [ "/app/documents" ]
