## Переменные окружения

| Переменная                  | Описание                                                                                                                                                      |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `HTTP_PORT`                 | Порт, на котором приложение будет слушать входящие HTTP-запросы (по умолчанию: `8080`).                                                                       |
| `POSTGRES_DSN`              | Строка подключения (DSN) к базе данных PostgreSQL. Формат: `postgres://username:password@host:port/database?sslmode=disable`                                  |
| `POSTGRES_MAX_CONNS`        | Максимальное количество подключений к базе данных PostgreSQL (по умолчанию: `50`).                                                                            |
| `CLIENTS_SERVICE_URL`       | URL сервиса клиентов.                                                                                                                                         |
| `CAMPAIGNS_SERVICE_URL`     | URL сервиса кампаний                                                                                                                                          |
| `RO_BACK_SERVICE_URL`       | URL сервиса RO Back                                                                                                                                           |
| `ONE_C_SERVICE_URL`         | URL сервиса OneC, включая логин и пароль для аутентификации (например, `https://<login>:<password>@1c-russ.services.net.buroburo.tech/Acc_DEV_MSB_24/hs/RD`). |
| `ONE_C_VERIFICATION_PERIOD` | Период проверки для сервиса OneC (по умолчанию: `1h`).                                                                                                        |
