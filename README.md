# auth-proxy

Прокси-шлюз с авторизацией по JWT (куки) и проверкой ролей на маршрутах.
Один бинарник поднимает два HTTP-слушателя:

- **гейт** (`server.port`, по умолчанию 5000) — проксирует трафик после проверки access/refresh-кук и роли;
- **auth-сервис** (`auth.port`, по умолчанию 6000) — `/login`, `/refresh`, `/logout`, `/user/me`.

## Быстрый старт локально

```bash
cp internal/config/example.config.yaml config.yaml
cp internal/config/example.env .env
# прописать свои JWT-секреты в .env и секреты пользователей в config.yaml
go run ./cmd/proxy
```

Конфиг = `YAML_CONFIG_PATH` (по умолчанию `./config.yaml`) + переменные окружения + дефолты.
**Приоритет: YAML перекрывает ENV.** Пароли пользователей в `config.yaml` указываются
в открытом виде и хешируются при старте.

## Docker

### Сборка и публикация образа

Публичный адрес — Docker Hub. Проект собирается двумя стадиями, рантайм —
`alpine:3.21` с `curl` и `ca-certificates` (полезно для диагностики изнутри
и для проверки живости). Локальные секреты (`config.yaml`, `.env`) в образ
не попадают — их исключает `.dockerignore`.

### Локально: docker compose

```bash
docker compose up -d --build
```

Конфиг монтируется из `./config.yaml` в `/etc/auth-proxy/config.yaml` (read-only), порты гейта и
auth-сервиса публикуются как 5000/6000.

### Docker Swarm

```bash
docker stack deploy -c docker-stack.yml auth-proxy
```

Файл конфига (`./config.yaml`) раздаётся на все ноды как **docker config** и монтируется
в `/etc/auth-proxy/config.yaml`. После правки конфига:

```bash
docker config rm auth_proxy_config
docker stack deploy -c docker-stack.yml auth-proxy
```

### Что обязательно настроить в проде

| Настройка | Почему |
|---|---|
| `ENV=production` | включает `Secure` у кук — браузер сохранит их только по HTTPS |
| `GATEWAY_BASE_URL`, `AUTH_BASE_URL` | внешние адреса (домены), а не `localhost` — редиректы после логина |
| HTTPS перед обоими портами | терминация TLS (nginx/traefik/swarm ingress), иначе `Secure`-куки не сохранятся |
| свои `JWT_ACCESS_SECRET`/`JWT_REFRESH_SECRET` (≥32 символа) | в `config.yaml` или ENV; держать в секрете |
| `JWT_COOKIE_DOMAIN` (напр. `.example.com`) | когда гейт и auth-сервис на разных поддоменах: кука должна жить на общем домене, иначе её не увидит второй поддомен |

### Проверка живости

`HEALTHCHECK` встроен в `Dockerfile` и `docker-stack.yml` и делает
`curl -f http://127.0.0.1:5000/healthz`. `/healthz` отдаёт
`{"status":"ok","version":"..."}` на гейте и `{"status":"ok"}` на
auth-сервисе. Чтобы Swarm также проверял auth-порт, добавьте проверку вручную
или держите `8081` за ingress с внешним пробингом.
