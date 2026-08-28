# Конфигурация auth-proxy

Конфиг собирается из трёх источников в следующем порядке (**каждый следующий перекрывает предыдущий**):

1. **ENV-переменные** — парсятся библиотекой `caarlos0/env/v11`, со значениями по умолчанию из тегов `envDefault`.
2. **`.env` файл** — если есть в рабочей директории, загружается через `godotenv`. Уже заданные переменные окружения он **не перезаписывает**.
3. **YAML-файл** — путь берётся из `YAML_CONFIG_PATH` (по умолчанию `config.yaml`). Явно указанные в YAML значения перекрывают ENV.

После загрузки конфиг проходит валидацию (`go-playground/validator`, проверка маршрутов, проверка blacklist). При ошибке загрузки/валидации `config.Load()` возвращает ошибку.

Готовая в разработке копия: `internal/config/example.env` и `internal/config/example.config.yaml`.

---

## ENV-переменные

Загружаются до YAML, поэтому YAML имеет приоритет.

| Переменная                    | По умолчанию    | Обязательная | Описание |
|-------------------------------|-----------------|--------------|----------|
| `YAML_CONFIG_PATH`            | `config.yaml`   | —            | Путь к YAML-конфигу |
| `SERVER_PORT`                 | `5000`          | —            | Порт сервера (1–65535) |
| `SERVER_READ_TIMEOUT`         | `5s`            | —            | Read timeout сервера (>= 1s) |
| `SERVER_WRITE_TIMEOUT`        | `10s`           | —            | Write timeout сервера (>= 1s) |
| `SERVER_SHUTDOWN_TIMEOUT`     | `10s`           | —            | Таймаут graceful shutdown (>= 1s) |
| `JWT_ACCESS_COOKIE_KEY`       | `access_token`  | —            | Имя cookie access-токена |
| `JWT_REFRESH_COOKE_KEY`       | `refresh_token` | —            | Имя cookie refresh-токена (так в теге) |
| `JWT_ACCESS_SECRET`           | —               | да           | Секрет access-токена (>= 32 симв.) |
| `JWT_REFRESH_SECRET`          | —               | да           | Секрет refresh-токена (>= 32 симв.) |
| `JWT_ACCESS_TTL`              | `15m`           | —            | TTL access-токена (>= 1m) |
| `JWT_REFRESH_TTL`             | `24h`           | —            | TTL refresh-токена (>= 1m, > access TTL) |
| `BCRYPT_COST`                 | `12`            | —            | Стоимость bcrypt (4–31) |
| `ROLES`                       | `user,admin,superadmin` | —   | Роли через запятую (>= 3, все не пустые) |

### Пример `.env`

```env
YAML_CONFIG_PATH="./config.yaml"

JWT_ACCESS_COOKIE_KEY=access_token
JWT_REFRESH_COOKIE_KEY=refresh_token
JWT_ACCESS_SECRET=supersecret-access-key-32-chars-min
JWT_REFRESH_SECRET=supersecret-refresh-key-32-chars-min
JWT_ACCESS_TTL=15m
JWT_REFRESH_TTL=24h

SERVER_PORT=5000
SERVER_READ_TIMEOUT=5s
SERVER_WRITE_TIMEOUT=10s

BCRYPT_COST=12

ROLES=user,admin,superadmin
```

---

## YAML-конфиг

```yaml
server:
  port: 5000
  read_timeout: 5s
  write_timeout: 10s
  shutdown_timeout: 10s

jwt:
  access_cookie_key: access_token
  refresh_cookie_key: refresh_token
  access_secret: "суперсекретный-access-секрет-min-32-символа---"
  refresh_secret: "супер-секретный-refresh-секрет-min-32-символа--"
  access_ttl: 15m
  refresh_ttl: 24h

bcrypt:
  cost: 12

roles:
  - "user"
  - "admin"
  - "superadmin"

routes:
  - prefix: "/api/users"
    target: "http://users_service:8081"
    skip_auth: false

blacklist:
  - "10.0.0.0/8"
```

### Блоки

- **`server`** — порт и таймауты HTTP-сервера.
- **`jwt`** — названия cookie и секреты для access/refresh токенов, их TTL.
- **`bcrypt`** — стоимость хеширования паролей.
- **`roles`** — общий список ролей по возрастанию полномочий (слева направо: самая низкая → самая высокая). Используется для «лесенки» ролей в маршрутах.
- **`blacklist`** — список IP-адресов или CIDR-подсетей, которым доступ закрыт (403).
- **`routes`** — маршруты шлюза (см. ниже). **Минимум один маршрут обязателен.**

### Маршрут (`routes[]`)

| Поле                   | Тип    | Описание |
|------------------------|--------|----------|
| `prefix`               | string | Путь, который перехватывает шлюз (matched по самому длинному совпадению). Обязателен, префиксы не должны дублироваться. |
| `target`               | string | Куда проксировать/редиректить (валидный URL). Обязателен. |
| `skip_auth`            | bool   | `true` — пропустить проверку токена и ролей. |
| `redirect`             | bool   | `true` — вместо проксирования вернуть 302 на `target` + путь запроса. |
| `strip_first_prefix`   | bool   | `true` — убрать первый сегмент пути запроса: `/inference/api/v1` → `/api/v1`. |
| `required_roles`       | []string | Минимальная роль для доступа. Автоматически расширяется на все роли «выше» из `roles`. |

#### Как работает `prefix` + `strip_first_prefix`

- Запрос `/inference/api/v1` перехватывается маршрутом с `prefix: "/inference"`.
- По умолчанию полный путь идёт к `target`: бэкенд получает `/inference/api/v1` (или редирект идёт на `target + /inference/api/v1`).
- При `strip_first_prefix: true` первый сегмент убирается: на бэкенд/в редирект уходит `/api/v1`.

#### Как работает `redirect`

`redirect: true` — маршрут не проксирует, а отвечает HTTP 302 (`Location: target + путь запроса`). Полезно, например, для перенаправления неавторизованных пользователей на страницу логина. `target` при этом указывает на абсолютный URL (домен контейнера + порт), чтобы редирект не перехватил сам auth-proxy.

#### Как работает «лесенка» ролей (`required_roles`)

Роли в `roles` идут по возрастанию полномочий. Если маршруту задан `required_roles` (и `skip_auth: false`):

- доступ получают как указанная роль, так и все роли, стоящие в `roles` **правее** (выше по полномочиям);
- если у маршрута ролей нет — открыт для **всех** ролей;
- если `skip_auth: true` — `required_roles` игнорируются.

Пример:

```yaml
roles: ["user", "admin", "superadmin"]

routes:
  - prefix: "/api/users/delete"
    target: "http://users_service:8081"
    skip_auth: false
    required_roles: ["admin"]   # доступно admin и superadmin

  - prefix: "/api/reports"
    target: "http://reports_service:8082"
    skip_auth: false             # ролей нет -> доступно всем ролям

  - prefix: "/"
    target: "http://login:8084/login"
    skip_auth: true
    redirect: true
    strip_first_prefix: true
```

---

## Порядок приоритета и валидация

1. Парсинг ENV (с дефолтами) → парсинг `.env` → загрузка YAML.
2. Валидация `validate.Struct(cfg)` — обязательные секреты, диапазоны, типы.
3. `validateRoutes` — уникальность префиксов, валидность `required_roles`, построение «лесенки» ролей.
4. `validateBlacklist` — каждый элемент должен быть валидным IP или CIDR.

Частые ошибки при запуске:

- отсутствует/недоступен `config.yaml` или в нём нет ни одного маршрута;
- `JWT_ACCESS_SECRET` / `JWT_REFRESH_SECRET` короче 32 символов;
- неуникальный `prefix` или неизвестная роль в `required_roles`;
- `refresh_ttl` не больше `access_ttl`;
- кривой IP/CIDR в `blacklist`.