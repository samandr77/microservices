### Запуск прилодения:

1. Перейти в папку app `cd ./app`
2. Создать config `cp ../docker-example.env ../.env`
3. Выполнить команду `docker-compose -f ../docker/docker-compose.yml up --remove-orphans -d --build`
4. Для проверки выполнить команду `curl http://localhost:8080/api/health`
