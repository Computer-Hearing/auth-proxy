package handlers

import (
	"auth-proxy/internal/config"
	"auth-proxy/internal/modules/routes"
	"auth-proxy/pkg"
	"auth-proxy/pkg/apierror"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
)

type Options struct {
	Logger *slog.Logger
	Config *config.Config
}

var (
	ErrOptionsIsNil = errors.New("options is nil")
	ErrConfigIsNil  = errors.New("config is nil")
)

type AuthProxy struct {
	cfg    *config.Config
	logger *slog.Logger
	proxy  *routes.RoutesProxy
}

func NewHandlers(opts *Options) (*AuthProxy, error) {
	if opts == nil {
		return nil, ErrOptionsIsNil
	}
	if opts.Config == nil {
		return nil, ErrConfigIsNil
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	cfg, logger := opts.Config, opts.Logger
	proxy, err := routes.NewRoutesProxy(cfg)
	if err != nil {
		return nil, fmt.Errorf("new routes proxy: %w", err)
	}
	return &AuthProxy{cfg: cfg, logger: logger, proxy: proxy}, nil
}

func (h *AuthProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// путь который сравниваться будет и определяться куда перенаправить
	proxyPath := r.URL.Path

	// Берем отпечатки устройства
	fingerprints := pkg.GetFingerprint(r)

	// смотрим в блеклист
	if h.cfg.IsIPBlacklisted(fingerprints.IP) {
		apierror.HandleAPIError(w, h.logger, apierror.ErrBlacklistedIP)
		return
	}
	// смотрим есть ли этот маршрут в нашем конфиге
	route := h.cfg.GetRouteByPrefix(proxyPath)
	if route == nil {
		apierror.HandleAPIError(w, h.logger, apierror.ErrPathNotFound)
		return
	}

	// если нужна аутентификация/авторизация
	if !route.SkipAuth {
		// TODO: проверка токена (jwt из куки) и ролей пользователя
		return
	}

	// Проксируем запрос на целевой сервис
	h.proxy.ServeHTTP(w, r)
}
