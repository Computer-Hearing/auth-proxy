FROM golang:1.27-alpine AS build
WORKDIR /app

# Версия прошивается в бинарь: docker build --build-arg VERSION=v1.0.0
ARG VERSION=dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /auth-proxy ./cmd/auth-proxy

FROM alpine:3.21

RUN apk add --no-cache curl ca-certificates

COPY --from=build /auth-proxy /usr/local/bin/auth-proxy

RUN addgroup -S app && adduser -S -G app app
USER app

# 5000 - gateway, 7000 - admin (наружу не публикуется)
EXPOSE 5000 7000

WORKDIR /app
ENTRYPOINT ["auth-proxy"]
