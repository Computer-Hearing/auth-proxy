FROM golang:1.26-alpine AS build
WORKDIR /app

# Версия прошивается в бинарь: docker build --build-arg VERSION=v1.0.0
ARG VERSION=dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /auth-proxy ./cmd/proxy

FROM alpine:3.21

RUN apk add --no-cache curl ca-certificates

COPY --from=build /auth-proxy /usr/local/bin/auth-proxy

RUN addgroup -S app && adduser -S -G app app
USER app

EXPOSE 5000 6000

WORKDIR /app
ENTRYPOINT ["auth-proxy"]