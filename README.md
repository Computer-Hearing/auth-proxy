# auth-proxy

Роутер и авторизатор за Authentik. Своей аутентификации в прокси нет: Caddy
делает `forward_auth` в Authentik и передаёт доверенные заголовки
`X-authentik-username`, `X-authentik-email`, `X-authentik-groups`. Прокси решает,
к какому сервису отправить запрос и пускать ли пользователя по группам.

Один бинарник поднимает два HTTP-слушателя:

- **gateway** (`server.port`, по умолчанию `5000`) — маршруты и проксирование;
- **admin** (`admin.port`, по умолчанию `7000`) — статика `/_admin` и JSON API `/config`.

## Конфиги

Два файла:

| Файл | Что внутри | Как меняется |
|---|---|---|
| `gateway.yaml` | порты, таймауты, заголовок секрета Authentik, путь к `routes.yaml` | вручную + рестарт |
| `routes.yaml` | `roles` и `routes` | через админку, без рестарта |

`gateway.yaml` читается из `YAML_CONFIG_PATH` (по умолчанию `/etc/auth-proxy/gateway.yaml`).
Путь к `routes.yaml` задаётся полем `routes_file` (или `ROUTES_FILE`).
Отсутствие любого из файлов — ошибка запуска.

Примеры: `internal/config/example.gateway.yaml`, `internal/config/example.routes.yaml`,
`internal/config/example.env`. Подробно — `internal/config/README.md`.

## Авторизация по группам

Роли в `routes.yaml` идут **по убыванию полномочий**: `roles[0]` — самая высокая.
Маршрут проверяет `required_groups`:

- `required_groups` пусто — маршрут открыт (Authentik уже отработал на ingress);
- иначе нужен `X-authentik-username` и группа из списка;
- работает «лесенка»: роль выше покрывает требования ниже. Если маршруту нужен
  `admin`, то `superadmin` тоже пройдёт;
- группы, которых нет в `roles`, игнорируются с `warn` в лог.

`X-authentik-groups` парсится как `foo|bar|baz` (формат Authentik).

## Маршрутизация по host

Поле `host` позволяет держать одинаковый `prefix` на разных доменах.
Поддерживается точное совпадение и wildcard одного уровня (`*.example.com`).
Без `host` маршрут подходит под любой домен.

Сначала выбирается домен, потом путь: **точный host > wildcard host > без host**,
и только среди них — самый специфичный `prefix`. Маршруты без `host` — общий fallback.

```yaml
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

Host для выбора маршрута берётся из `X-Forwarded-Host` (его ставит ingress),
fallback — `Host` запроса.

## Админка

- `GET /_admin/` — встроенная HTML+JS-страница (редактор JSON).
- `GET /config` — текущие `roles` и `routes` в JSON.
- `PUT /config` — полная замена `roles` + `routes`:
  1. валидация (роли, дубликаты `prefix|host`, паттерны, зарезервированные пути);
  2. проверка, что вызывающий не отбирает доступ у себя;
  3. атомарная запись `routes.yaml` (tmp + rename);
  4. пересборка движка и подмена снапшота без рестарта.

`/_admin` и `/config` зарезервированы: маршруты не могут их занять.
Оба слушателя пускают к админке только пользователя с `roles[0]`:
нет `X-authentik-username` → `401`, роль ниже → `403`.
Admin-порт наружу не публикуется: gateway проксирует на него после проверки.

## Caddy `on_demand_tls`

Чтобы Caddy выпускал сертификаты только для доменов, которые есть в маршрутах,
используйте `ask`-ручку admin-листенера:

```caddyfile
{
    on_demand_tls {
        ask http://auth-proxy:7000/internal/allowed-domain
    }
}

https:// {
    tls {
        on_demand
    }
    reverse_proxy auth-proxy:5000
}
```

`GET /internal/allowed-domain?domain=<host>`:

- `200` — домен есть среди **точных** `host` маршрутов;
- `404` — нет (wildcard-маршруты и маршруты без `host` разрешения не дают);
- `400` — параметр `domain` отсутствует/пустой;
- `405` — метод не `GET`.

Ручка публичная (Caddy не присылает заголовки Authentik) и живёт только на
admin-порту. Наружу порт не публикуйте: Caddy должен обращаться к
`auth-proxy:7000` внутри docker-сети.

## Быстрый старт локально

```bash
cp internal/config/example.gateway.yaml gateway.yaml
cp internal/config/example.routes.yaml routes.yaml
cp internal/config/example.env .env
go run ./cmd/auth-proxy
```

Проверка:

```bash
curl -H 'X-authentik-username: root' \
     -H 'X-authentik-groups: superadmin' \
     http://localhost:7000/config
```

Без заголовков будет `401` — это ожидаемо.

## Docker

```bash
docker compose up -d --build
```

`gateway.yaml` и `routes.yaml` лежат в `./data` и монтируются в `/etc/auth-proxy`:
каталог должен быть доступен на запись (атомарный rename не работает с
single-file bind mount). Публикуется только `5000`; admin-порт `7000` доступен
только внутри docker-сети (`expose`) — Caddy и gateway обращаются к нему напрямую.

## Отложено / TODO

- проверка `X-Proxy-Secret` (сейчас заголовок читается, но не сверяется);
- CORS (сейчас не реализован);
- ограничение `/_admin` конкретным доменом админки;
- права non-root пользователя на каталог с `routes.yaml`.

## Healthcheck

`/healthz` на gateway отдаёт `{"status":"ok","version":"..."}`.
На admin-порту healthz нет.
