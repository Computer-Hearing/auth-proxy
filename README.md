# auth-proxy

Прокси-шлюз с авторизацией и проверкой ролей на маршрутах.
Один бинарник поднимает два HTTP-слушателя:

- **gateway-сервис** (`gateway.port`, по умолчанию 5000) — проксирует трафик после проверки доступа;
- **auth-сервис** (`auth.port`, по умолчанию 6000) — `/login`, `/refresh`, `/logout`, `/user/me`, `/` (профиль).

Для каждого маршрута (`gateway.routes[]`) задаётся `auth_method`: `jwt` (куки, по умолчанию),
`basic` (Login/Password из `Authorization: Basic`, например, для CLI MLflow), `jwt2basic`
(принимаем JWT-куки, бэкенду подставляем `Authorization: Basic`) или `none`
(маршрут открыт). Роль для `jwt`/`jwt2basic`/`basic` проверяется через `required_roles`.
Подробности полей — в `internal/config/README.md`.

### Маршрутизация по host

Поле `host` позволяет создавать маршруты с одинаковым `prefix`, но разными доменами
(virtual hosting). Поддерживается точное совпадение и wildcard одного уровня (`*.example.com`).
Если `host` не указан, маршрут подходит под любой host.

Сначала выбирается домен, потом путь: **точный host > wildcard host > маршрут без host**,
и только среди маршрутов этого уровня — самый специфичный `prefix`. Маршруты без `host`
работают как общий fallback: они срабатывают, если у домена нет своего подходящего маршрута.
Порядок маршрутов в конфиге важен только при полной ничьей.

```yaml
gateway:
  routes:
    - prefix: "/api"
      host: "api.example.com"
      target: "http://api_service:8085"

    - prefix: "/api"
      host: "*.example.com"
      target: "http://wildcard_service:8086"

    - prefix: "/api"
      target: "http://default_api:8080"
```

| Запрос `Host` | Маршрут |
|---|---|
| `api.example.com` | api_service (точный) |
| `grafana.example.com` | wildcard_service (wildcard) |
| `a.b.example.com` | default_api (wildcard не матчит два уровня) |
| `other.com` | default_api |

Домен главнее длины префикса: если есть `/**` с `host: grafana.example.com` и общий
`/api/admin` без host, запрос `grafana.example.com/api/admin` уйдёт в маршрут grafana.

## Быстрый старт локально

```bash
cp internal/config/example.config.yaml config.yaml
cp internal/config/example.env .env
# прописать свои JWT-секреты (session.jwt) и пользователей (access.users) в config.yaml
go run ./cmd/auth-proxy
```

Конфиг = `YAML_CONFIG_PATH` (по умолчанию `./config.yaml`) + переменные окружения + дефолты.
**Приоритет: YAML перекрывает ENV.** Пароли пользователей в `config.yaml` указываются
в открытом виде и хешируются при старте.
По сути можно пользоваться только yaml-конфигурацией.
## Docker

### Локально: docker compose

```bash
docker compose up -d --build
```

Конфиг монтируется из `./config.yaml` в `/etc/auth-proxy/config.yaml` (read-only), порты gateway-сервиса и
auth-сервиса публикуются как 5000/6000.

Файл конфига (`./config.yaml`) раздаётся на все ноды как **docker config** и монтируется
в `/etc/auth-proxy/config.yaml`.

### Что обязательно настроить в реальной среде
| Настройка | Почему |
|---|---|
| `ENV=production` | включает `Secure` у кук — браузер сохранит их только по HTTPS |
| `GATEWAY_BASE_URL`, `AUTH_BASE_URL` | внешние адреса (домены), а не `localhost` — редиректы после логина |
| HTTPS перед обоими портами | терминация TLS (nginx/traefik/swarm ingress), иначе `Secure`-куки не сохранятся |
| свои `SESSION_ACCESS_SECRET`/`SESSION_REFRESH_SECRET` (≥32 символа) | в `config.yaml` (`session.jwt`) или ENV; держать в секрете |
| `SESSION_COOKIE_DOMAIN` (напр. `.example.com`) | когда гейт и auth-сервис на разных поддоменах: кука должна жить на общем домене, иначе её не увидит второй поддомен |
| `AUTH_ALLOW_ORIGINS` (напр. `https://app.example.com`) | CORS для auth-сервиса: точные origin фронтендов, обращающихся к `/user/me` через `fetch`. Пусто = `*` без кук |

### Проверка живости

`HEALTHCHECK` встроен в `Dockerfile` и `docker-stack.yml` и делает
`curl -f http://127.0.0.1:5000/healthz`. `/healthz` отдаёт
`{"status":"ok","version":"..."}` на гейте и `{"status":"ok"}` на
auth-сервисе.
