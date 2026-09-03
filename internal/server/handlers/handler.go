package handlers

import (
	"auth-proxy/internal/config"
	"auth-proxy/internal/middleware"
	"auth-proxy/internal/modules/routes"
	"auth-proxy/internal/modules/tokens"
	"auth-proxy/internal/modules/users"
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
	Users  users.UserStorage

	AppVersion string
}

var (
	ErrOptionsIsNil = errors.New("options is nil")
	ErrConfigIsNil  = errors.New("config is nil")
	ErrJWTIsNil     = errors.New("jwt module is nil")
	ErrUsersIsNil   = errors.New("users storage is nil")
)

type AuthProxy struct {
	cfg    *config.Config
	logger *slog.Logger
	proxy  *routes.RoutesProxy
	jwt    *tokens.JWTModule
	users  users.UserStorage

	appVersion string
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
	if opts.Users == (users.UserStorage{}) {
		return nil, ErrUsersIsNil
	}
	cfg, logger := opts.Config, opts.Logger
	proxy, err := routes.NewRoutesProxy(cfg)
	if err != nil {
		return nil, fmt.Errorf("new routes proxy: %w", err)
	}
	return &AuthProxy{cfg: cfg, logger: logger, proxy: proxy, jwt: opts.JWT, users: opts.Users, appVersion: opts.AppVersion}, nil
}

func (h *AuthProxy) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","version":%q}`+"\n", h.appVersion)
	})
	mux.Handle("/", h)
	return middleware.Chain(mux, middleware.Recover, middleware.RequestID, middleware.Log)
}

func (h *AuthProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// путь который сравниваться будет и определяться куда перенаправить
	proxyPath := r.URL.Path

	// Берем отпечатки устройства
	fingerprints := pkg.GetFingerprint(r)

	// смотрим в блеклист
	if h.cfg.IsIPBlacklisted(fingerprints.IP) {
		h.logger.Debug("IP blacklisted", slog.String("ip", fingerprints.IP))
		apierror.HandleAPIError(w, h.logger, apierror.ErrBlacklistedIP)
		return
	}
	// смотрим есть ли этот маршрут в нашем конфиге
	route := h.cfg.GetRouteByPrefix(proxyPath)
	if route == nil {
		h.logger.Debug("Route not found", slog.String("path", proxyPath), slog.String("ip", fingerprints.IP))
		apierror.HandleAPIError(w, h.logger, apierror.ErrPathNotFound)
		return
	}

	// маршрут требует аутентификации и авторизации по своему методу;
	// вернули false - ответ (редирект/401/403) уже записан в w
	switch route.AuthMethod {
	case config.AuthNone:
		// маршрут открыт, проверок нет
	case config.AuthBasic:
		// basic авторизация
		if !h.authorizeBasic(w, r, route) {
			return
		}
	default:
		// по умолчанию - jwt
		if !h.authorize(w, r, route) {
			return
		}
	}

	// Проксируем запрос на целевой сервис
	h.logger.Debug("proxying", slog.String("path", proxyPath))
	h.proxy.ServeHTTP(w, r)
}

// authorizeBasic проверяет login/password из Basic-заголовка по кешу пользователей.
// Пароль должен совпадать с учёткой из конфига, а роль пользователя - входить
// в RequiredRoles маршрута (как и для jwt-маршрутов).
//
// Возвращает true, если можно проксировать запрос дальше.
// При неверных/отсутствующих кредах шлём 401 + WWW-Authenticate: Basic,
// чтобы клиент/браузер показал диалог входа.
func (h *AuthProxy) authorizeBasic(w http.ResponseWriter, r *http.Request, route *config.RouteConfig) bool {
	username, password, ok := r.BasicAuth()
	if !ok {
		h.requireBasicAuth(w, r, username)
		return false
	}

	user, authOK := h.users.Authenticate(r.Context(), username, password)
	if !authOK {
		h.logger.Debug("basic auth failed", slog.String("username", username))
		h.requireBasicAuth(w, r, username)
		return false
	}

	// роль пользователя должна подходить под minimum ролей маршрута
	if !slices.Contains(route.RequiredRoles, user.Role) {
		h.logger.Debug("basic auth role denied", slog.String("username", username), slog.String("role", user.Role))
		apierror.HandleAPIError(w, h.logger, apierror.ErrForbidden)
		return false
	}

	h.logger.Debug("basic auth ok", slog.String("username", username))
	return true
}

// requireBasicAuth отвечает 401 + WWW-Authenticate: Basic realm="AUTH-PROXY".
// Заголовок WWW-Authenticate обязателен, иначе браузер не покажет диалог логина.
func (h *AuthProxy) requireBasicAuth(w http.ResponseWriter, r *http.Request, username string) {
	h.logger.Debug("basic auth required", slog.String("path", r.URL.Path), slog.String("username", username))
	w.Header().Set("WWW-Authenticate", `Basic realm="AUTH-PROXY"`)
	apierror.HandleAPIError(w, h.logger, apierror.ErrUnauthorized)
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
			h.logger.Debug("access cookie is empty", slog.String("redirect", "refresh"))
			return false
		}
		h.redirectToAuth(w, r, "login")
		h.logger.Debug("access and refresh cookies are empty", slog.String("redirect", "login"))
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
		h.logger.Debug("access cookie error", slog.String("redirect", "login"))
		return false
	}

	// access истёк: если есть refresh - на /refresh, иначе - на логин
	if refresh != nil {
		h.redirectToAuth(w, r, "refresh")
		h.logger.Debug("access cookie expired", slog.String("redirect", "refresh"))
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
