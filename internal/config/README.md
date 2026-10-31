# Конфигурация auth-proxy

Конфиг состоит из двух файлов:

1. **`gateway.yaml`** — статика (порты, таймауты, Authentik, путь к routes).
   Источники: ENV (с дефолтами) → `.env` → YAML. YAML перекрывает ENV.
2. **`routes.yaml`** — динамика (роли + маршруты). Читается по пути `routes_file`
   и переписывается админкой.

Путь к `gateway.yaml` — `YAML_CONFIG_PATH` (по умолчанию `/etc/auth-proxy/gateway.yaml`).
Отсутствие любого файла — ошибка запуска.

Примеры: `example.gateway.yaml`, `example.routes.yaml`, `example.env`.

---

## `gateway.yaml`

```yaml
log_level: info
shutdown_timeout: 10s

server:
  port: 5000
  read_timeout: 5s
  write_timeout: 10s

admin:
  port: 7000
  read_timeout: 5s
  write_timeout: 10s

authentik:
  secret_header: "X-Proxy-Secret"
  secret: ""

routes_file: "/etc/auth-proxy/routes.yaml"
```

| Поле | ENV | По умолчанию | Описание |
|---|---|---|---|
| `log_level` | `LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |
| `shutdown_timeout` | `SHUTDOWN_TIMEOUT` | `10s` | таймаут graceful shutdown (≥ 1s) |
| `server.port` | `SERVER_PORT` | `5000` | основной слушатель |
| `server.read_timeout` | `SERVER_READ_TIMEOUT` | `5s` | |
| `server.write_timeout` | `SERVER_WRITE_TIMEOUT` | `10s` | |
| `admin.port` | `ADMIN_PORT` | `7000` | админка (статика + API) |
| `admin.read_timeout` | `ADMIN_READ_TIMEOUT` | `5s` | |
| `admin.write_timeout` | `ADMIN_WRITE_TIMEOUT` | `10s` | |
| `authentik.secret_header` | `AUTHENTIK_SECRET_HEADER` | `X-Proxy-Secret` | имя заголовка секрета |
| `authentik.secret` | `AUTHENTIK_SECRET` | — | значение секрета (пока не проверяется) |
| `routes_file` | `ROUTES_FILE` | `/etc/auth-proxy/routes.yaml` | путь к динамике |

---

## `routes.yaml`

```yaml
roles:
  - "superadmin"
  - "admin"
  - "user"

routes:
  - prefix: "/api"
    target: "http://api_service:8085"
    required_groups: ["admin"]

  - prefix: "/"
    host: "app.example.com"
    target: "http://app:8080"

  - prefix: "/static/**"
    target: "http://static_service:8084"
    strip_first_prefix: true

  - prefix: "/inference"
    target: "http://login_service:8084/login"
    redirect: true
    strip_first_prefix: true
```

### `roles`

- минимум одна роль, все непустые и уникальные;
- порядок — **по убыванию полномочий**: `roles[0]` самая высокая;
- `roles[0]` даёт доступ к админке;
- группа пользователя выше по списку покрывает требования ниже («лесенка»).

### `routes[]`

| Поле | Тип | Обязательное | Описание |
|---|---|---|---|
| `host` | string | нет | точный домен или `*.example.com` (один уровень). Пусто — любой домен |
| `prefix` | string | да | путь; `*` — один сегмент, `**` — любое число |
| `target` | string | да | URL, куда проксировать/редиректить |
| `redirect` | bool | нет | `true` — 302 на `target` + путь вместо проксирования |
| `strip_first_prefix` | bool | нет | убрать первый сегмент пути |
| `required_groups` | []string | нет | группы из `roles`; пусто — маршрут открыт |

Правила:

- `prefix` должен начинаться с `/`;
- дубликаты `prefix + "|" + host` запрещены;
- `required_groups` должны существовать в `roles`;
- `prefix` не должен пересекаться с зарезервированными `/_admin` и `/config`;
- пустой список `routes` разрешён — тогда все запросы получают `404`.

### Поведение `strip_first_prefix`

- `/inference/api/v1` → бэкенд получает `/inference/api/v1`;
- при `strip_first_prefix: true` → `/api/v1`.

### Поведение `redirect`

`redirect: true` — вместо проксирования отдаётся `302` на `target` + путь запроса
(с учётом `strip_first_prefix`).

---

## Авторизация

Заголовки Authentik (forward_auth):

| Заголовок | Использование |
|---|---|
| `X-authentik-username` | признак залогиненного пользователя |
| `X-authentik-email` | читается в context (для логов/будущего) |
| `X-authentik-groups` | группы через `|`, например `admin|user` |
| `X-Proxy-Secret` | читается в context; проверка — TODO |

Если `required_groups` задан:

- нет `X-authentik-username` → `401`;
- группы пользователя не проходят проверку → `403`;
- группы, которых нет в `roles`, игнорируются и логируются с `warn`;
- роль выше по списку проходит (например, `superadmin` для `required_groups: ["admin"]`).

Если `required_groups` пуст — проверки группы нет (запрос всё равно проходит
через Authentik на ingress).

---

## Admin API

Все запросы требуют `roles[0]` в `X-authentik-groups`.

| Метод | Путь | Описание |
|---|---|---|
| `GET` | `/config` | `{"roles": [...], "routes": [...]}` |
| `PUT` | `/config` | полная замена; тело — тот же JSON |
| `GET` | `/_admin/` | HTML+JS-редактор |

`PUT`:

1. декодирует JSON (`unknown fields` запрещены);
2. валидирует роли и маршруты;
3. проверяет, что вызывающий сохраняет `roles[0]` (нельзя отобрать доступ у себя);
4. собирает новый движок;
5. атомарно пишет `routes.yaml` (tmp + rename);
6. подменяет снапшот в памяти.

Ошибка записи → `500`, конфиг в памяти не меняется.

---

## Порядок загрузки

1. ENV (дефолты из тегов) → `.env` → `gateway.yaml`.
2. Валидация `gateway.yaml`.
3. Чтение и валидация `routes.yaml`.
4. Сборка движка маршрутов.
5. Запуск gateway и admin.

Изменения `gateway.yaml` применяются только после рестарта.
Изменения `routes.yaml` через API применяются сразу.
