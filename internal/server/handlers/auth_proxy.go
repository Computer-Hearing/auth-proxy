package handlers

import (
	"auth-proxy/internal/config"
	"auth-proxy/pkg"
	"auth-proxy/pkg/apierror"
	"log/slog"
	"net/http"
)

type AuthProxy struct {
	cfg    *config.Config
	logger *slog.Logger
}

func NewHandlers(cfg *config.Config, logger *slog.Logger) *AuthProxy {
	return &AuthProxy{cfg: cfg, logger: logger}
}

func (h *AuthProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// путь который сравниваться будет и определяться куда перенаправить
	proxyPath := r.URL.Path

	// Берем отпечатки устройства
	fingerprints := pkg.GetFingerprint(r)
	// сначала смотрим в блеклист

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
	// если нужна аутентификация/авторизация путю
	if !route.SkipAuth {

	}

	// TODO: только тестово
	type Response struct {
		Prefix      string                `json:"prefix"`
		Target      string                `json:"target"`
		Fingerprint pkg.DeviceFingerprint `json:"fingerprint"`
	}

	pkg.SendJSON(h.logger, w, Response{
		Prefix:      route.Prefix,
		Target:      route.Target,
		Fingerprint: fingerprints,
	}, http.StatusOK)
	//TODO: закончить прокси
}
