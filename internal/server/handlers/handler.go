package handlers

import (
	"auth-proxy/internal/config"
	"auth-proxy/internal/modules/routes"
	"auth-proxy/internal/modules/tokens"
	"auth-proxy/pkg"
	"auth-proxy/pkg/apierror"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"

	"github.com/golang-jwt/jwt/v5"
)

type Options struct {
	Logger *slog.Logger
	Config *config.Config
	JWT    *tokens.JWTModule
}

var (
	ErrOptionsIsNil = errors.New("options is nil")
	ErrConfigIsNil  = errors.New("config is nil")
	ErrJWTIsNil     = errors.New("jwt module is nil")
)

type AuthProxy struct {
	cfg    *config.Config
	logger *slog.Logger
	proxy  *routes.RoutesProxy
	jwt    *tokens.JWTModule
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
	if opts.JWT == nil {
		return nil, ErrJWTIsNil
	}
	cfg, logger := opts.Config, opts.Logger
	proxy, err := routes.NewRoutesProxy(cfg)
	if err != nil {
		return nil, fmt.Errorf("new routes proxy: %w", err)
	}
	return &AuthProxy{cfg: cfg, logger: logger, proxy: proxy, jwt: opts.JWT}, nil
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

	// маршрут требует аутентификации и авторизации;
	// вернули false - ответ (редирект/403) уже записан в w
	if !route.SkipAuth && !h.authorize(w, r, route) {
		return
	}

	// Проксируем запрос на целевой сервис
	h.proxy.ServeHTTP(w, r)
}

// authorize проверяет access/refresh куки и роль пользователя.
//
// Возвращает true, если можно проксировать запрос дальше.
// При false ответ (редирект на /login или /refresh, либо 403) уже записан в w.
//
// Ветка принятия решения:
//
//	кук нет совем                              -> /login
//	access нет, refresh есть                   -> /refresh
//	access валиден                             -> проверка роли
//	access истёк + refresh есть                -> /refresh
//	access истёк, refresh нет                  -> /login
//	access невалиден (подпись/alg)             -> /login (признак подмены, не истечения)
func (h *AuthProxy) authorize(w http.ResponseWriter, r *http.Request, route *config.RouteConfig) bool {
	access, _ := r.Cookie(h.cfg.JWT.AccessCookieKey)
	refresh, _ := r.Cookie(h.cfg.JWT.RefreshCookieKey)

	// access куки нет: если есть refresh - просим обновить токен, иначе - логин
	if access == nil {
		if refresh != nil {
			h.redirectToAuth(w, r, "refresh")
			return false
		}
		h.redirectToAuth(w, r, "login")
		return false
	}

	// access есть - пробуем распарсить
	claims, err := h.jwt.ValidateAccessToken(access.Value)

	// валидный токен - проверяем роль и пропускаем
	if err == nil {
		return h.checkRole(w, r, route, claims)
	}

	// Истёкший токен - это нормальная ситуация: пробуем освежить через refresh.
	// А вот невалидная подпись (jwt.ErrTokenSignatureInvalid и прочие, кроме
	// expire) - признак подмены токена, обновлять такой не из чего и незачем.
	if !errors.Is(err, jwt.ErrTokenExpired) {
		h.redirectToAuth(w, r, "login")
		return false
	}

	// access истёк: если есть refresh - на /refresh, иначе - на логин
	if refresh != nil {
		h.redirectToAuth(w, r, "refresh")
		return false
	}
	h.redirectToAuth(w, r, "login")
	return false
}

// checkRole - роль из токена должна входить в RequiredRoles маршрута.
// Ошибка роли - это 403, а НЕ редирект на /login: иначе после повторного
// логина та же роль снова вернёт 403 и получится бесконечный цикл.
func (h *AuthProxy) checkRole(w http.ResponseWriter, _ *http.Request, route *config.RouteConfig, claims *tokens.Claims) bool {
	if slices.Contains(route.RequiredRoles, claims.Role) {
		return true
	}
	apierror.HandleAPIError(w, h.logger, apierror.ErrForbidden)
	return false
}

// redirectToAuth редиректит пользователя на страницу auth-сервиса (/login
// или /refresh) и передаёт в query исходный путь (next), чтобы после входа
// вернуть его на то же место.
func (h *AuthProxy) redirectToAuth(w http.ResponseWriter, r *http.Request, page string) {
	next := pkg.SafeNext(r.URL.RequestURI())
	redirectURL := h.cfg.Auth.BaseURL + "/" + page + "?next=" + url.QueryEscape(next)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}
