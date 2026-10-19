package gateway

import (
	"auth-proxy/internal/config"
	"auth-proxy/internal/tokens"
	"auth-proxy/pkg/apierror"
	"errors"
	"log/slog"
	"net/http"
	"slices"

	"github.com/golang-jwt/jwt/v5"
)

// authorizeRoute проверяет доступ по auth_method маршрута.
// Возвращает true, если можно проксировать запрос дальше;
// при false ответ (редирект/401/403) уже записан в w.
func (g *Gateway) authorizeRoute(w http.ResponseWriter, r *http.Request, route *config.RouteConfig) bool {
	switch route.AuthMethod {
	case config.AuthNone:
		// маршрут открыт, проверок нет
		return true
	case config.AuthBasic:
		// basic авторизация
		return g.authorizeBasic(w, r, route)
	case config.AuthJWTBasic:
		// jwt + подстановка Basic-заголовка в таргет
		claims, ok := g.authorizeJWT(w, r, route)
		if !ok {
			return false
		}
		user, found := g.users.GetByUsername(r.Context(), claims.Username)
		if !found || user.BasicAuth == "" {
			g.logger.Error("jwt2basic: user has no BasicAuth configured",
				slog.String("username", claims.Username), slog.String("path", r.URL.Path))
			apierror.HandleAPIError(w, g.logger, apierror.ErrForbidden)
			return false
		}
		r.Header.Set("Authorization", user.BasicAuth)
		return true
	default:
		// по умолчанию - jwt
		_, ok := g.authorizeJWT(w, r, route)
		return ok
	}
}

// authorizeBasic проверяет login/password из Basic-заголовка по кешу пользователей.
// Пароль должен совпадать с учёткой из конфига, а роль пользователя - входить
// в RequiredRoles маршрута (как и для jwt-маршрутов).
//
// Возвращает true, если можно проксировать запрос дальше.
// При неверных/отсутствующих кредах шлём 401 + WWW-Authenticate: Basic,
// чтобы клиент/браузер показал диалог входа.
func (g *Gateway) authorizeBasic(w http.ResponseWriter, r *http.Request, route *config.RouteConfig) bool {
	username, password, ok := r.BasicAuth()
	if !ok {
		g.requireBasicAuth(w, r, username)
		return false
	}

	user, authOK := g.users.Authenticate(r.Context(), username, password)
	if !authOK {
		g.logger.Debug("basic auth failed", slog.String("username", username))
		g.requireBasicAuth(w, r, username)
		return false
	}

	// роль пользователя должна подходить под minimum ролей маршрута
	if !slices.Contains(route.RequiredRoles, user.Role) {
		g.logger.Debug("basic auth role denied", slog.String("username", username), slog.String("role", user.Role))
		g.denyAccess(w, r, user.Role)
		return false
	}

	g.logger.Debug("basic auth ok", slog.String("username", username))
	return true
}

// authorizeJWT проверяет access/refresh куки и роль пользователя.
//
// Возвращает claims и true, если можно проксировать запрос дальше.
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
func (g *Gateway) authorizeJWT(w http.ResponseWriter, r *http.Request, route *config.RouteConfig) (*tokens.Claims, bool) {
	access, _ := r.Cookie(g.cookie.AccessName)
	refresh, _ := r.Cookie(g.cookie.RefreshName)

	// access куки нет: если есть refresh - просим обновить токен, иначе - логин
	if access == nil {
		if refresh != nil {
			g.redirectToAuth(w, r, "refresh")
			g.logger.Debug("access cookie is empty", slog.String("redirect", "refresh"))
			return nil, false
		}
		g.redirectToAuth(w, r, "login")
		g.logger.Debug("access and refresh cookies are empty", slog.String("redirect", "login"))
		return nil, false
	}

	// access есть - пробуем распарсить
	claims, err := g.tokens.ValidateAccessToken(access.Value)

	// валидный токен - проверяем роль и пропускаем
	if err == nil {
		return g.checkRole(w, r, route, claims)
	}

	// Истёкший токен - это нормальная ситуация: пробуем освежить через refresh.
	if !errors.Is(err, jwt.ErrTokenExpired) {
		g.redirectToAuth(w, r, "login")
		g.logger.Debug("access cookie error", slog.String("redirect", "login"))
		return nil, false
	}

	// access истёк: если есть refresh - на /refresh, иначе - на логин
	if refresh != nil {
		g.redirectToAuth(w, r, "refresh")
		g.logger.Debug("access cookie expired", slog.String("redirect", "refresh"))
		return nil, false
	}
	g.redirectToAuth(w, r, "login")
	return nil, false
}

// checkRole - роль из токена должна входить в RequiredRoles маршрута.
// Ошибка роли - это 403, а НЕ редирект на /login: иначе после повторного
// логина та же роль снова вернёт 403 и получится бесконечный цикл.
func (g *Gateway) checkRole(w http.ResponseWriter, r *http.Request, route *config.RouteConfig, claims *tokens.Claims) (*tokens.Claims, bool) {
	if slices.Contains(route.RequiredRoles, claims.Role) {
		return claims, true
	}
	g.denyAccess(w, r, claims.Role)
	return nil, false
}
