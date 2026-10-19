package gateway

import (
	"auth-proxy/internal/config"
	"auth-proxy/internal/middleware"
	"auth-proxy/internal/reverseproxy"
	"auth-proxy/internal/ruleengine"
	"auth-proxy/internal/tokens"
	"auth-proxy/internal/users"
	"auth-proxy/pkg/apierror"
	"auth-proxy/pkg/httpx"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
)

// Options - зависимости гейта.
type Options struct {
	Logger *slog.Logger
	Routes []config.RouteConfig
	Cookie config.CookieConfig
	// AuthURL - внешний адрес auth-сервиса, туда редиректим на /login и /refresh
	AuthURL string
	Tokens  *tokens.Service
	Users   *users.Storage

	AppVersion string
}

var (
	ErrOptionsIsNil = errors.New("options is nil")
	ErrTokensIsNil  = errors.New("tokens service is nil")
	ErrUsersIsNil   = errors.New("users storage is nil")
)

// Gateway - http-слушатель, который проксирует трафик по маршрутам
// после проверки токенов и ролей.
type Gateway struct {
	logger  *slog.Logger
	engine  *ruleengine.Engine
	cookie  config.CookieConfig
	authURL string
	tokens  *tokens.Service
	users   *users.Storage

	appVersion string
}

func New(opts *Options) (*Gateway, error) {
	if opts == nil {
		return nil, ErrOptionsIsNil
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Tokens == nil {
		return nil, ErrTokensIsNil
	}
	if opts.Users == nil {
		return nil, ErrUsersIsNil
	}

	logger := opts.Logger
	engine, err := ruleengine.New(opts.Routes, func(route config.RouteConfig) (http.Handler, error) {
		return reverseproxy.New(route, logger)
	})
	if err != nil {
		return nil, fmt.Errorf("build routes: %w", err)
	}

	return &Gateway{
		logger:     logger,
		engine:     engine,
		cookie:     opts.Cookie,
		authURL:    opts.AuthURL,
		tokens:     opts.Tokens,
		users:      opts.Users,
		appVersion: opts.AppVersion,
	}, nil
}

// Handler собирает mux гейта
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", httpx.Healthz(g.appVersion))
	mux.Handle("/", g)
	return middleware.Chain(mux, middleware.Recover, middleware.RequestID, middleware.Log)
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// путь, по которому определяется маршрут
	path := r.URL.Path

	// маршрут выбирается один раз: по нему и проверяем доступ, и проксируем
	rule, ok := g.engine.Match(r.Host, path)
	if !ok {
		g.logger.Debug("Route not found", slog.String("path", path), slog.String("remote", r.RemoteAddr))
		apierror.HandleAPIError(w, g.logger, apierror.ErrPathNotFound)
		return
	}

	// вернули false - ответ (редирект/401/403) уже записан в w
	if !g.authorizeRoute(w, r, &rule.Route) {
		return
	}

	// Проксируем запрос на целевой сервис
	g.logger.Debug("proxying", slog.String("path", path))
	rule.Upstream.ServeHTTP(w, r)
}
