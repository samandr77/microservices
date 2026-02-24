FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY ../app/go.* ./
RUN go mod download

COPY ../app ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./payment ./cmd/

FROM alpine:latest

RUN apk add --no-cache ca-certificates && \
    update-ca-certificates

COPY ./docker/certificates/*.crt /usr/local/share/ca-certificates/
RUN update-ca-certificates

WORKDIR /app
COPY --from=builder /app/payment .

EXPOSE 8080
ENTRYPOINT [ "/app/payment" ]
