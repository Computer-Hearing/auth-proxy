# ---------- Стадия сборки: компилируем статичный бинарь ----------
FROM golang:1.26-alpine AS build
WORKDIR /app

# Версия прошивается в бинарь: docker build --build-arg VERSION=v1.0.0
ARG VERSION=dev

# Сначала зависимости - слой кешируется, пока go.mod/go.sum не менялись
COPY go.mod go.sum ./
RUN go mod download

# Секреты (config.yaml, .env) в образ не попадают - их исключает .dockerignore.
# Конфиг монтируется при запуске.
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /auth-proxy ./cmd/proxy

FROM alpine:3.21

RUN apk add --no-cache curl ca-certificates

COPY --from=build /auth-proxy /usr/local/bin/auth-proxy

# Не root, со своим /etc/passwd
RUN addgroup -S app && adduser -S -G app app
USER app

EXPOSE 5000 8081

WORKDIR /app
ENTRYPOINT ["auth-proxy"]