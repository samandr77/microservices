# Запуск (production)

1. Перейти в директорию приложения: `cd ./app`
2. Подготовить конфиг: `cp ../docker-example.env ../.env`
3. Сгенерировать TLS: `make tls-ca tls-server tls-client`
4. Запустить контейнеры: `docker compose -f docker/docker-compose.yml up --remove-orphans -d --build`
5. Проверка health endpoint: `curl -k https://0.0.0.0:8080/api/health`
