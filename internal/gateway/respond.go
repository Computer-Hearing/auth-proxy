package gateway

import (
	"auth-proxy/pkg/apierror"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// requireBasicAuth отвечает 401 + WWW-Authenticate: Basic realm="AUTH-PROXY".
// Заголовок WWW-Authenticate обязателен, иначе браузер не покажет диалог логина.
func (g *Gateway) requireBasicAuth(w http.ResponseWriter, r *http.Request, username string) {
	g.logger.Debug("basic auth required", slog.String("path", r.URL.Path), slog.String("username", username))
	w.Header().Set("WWW-Authenticate", `Basic realm="AUTH-PROXY"`)
	apierror.HandleAPIError(w, g.logger, apierror.ErrUnauthorized)
}

// denyAccess - 403 при недостаточной роли. Браузеру (Accept: text/html)
// редиректим на профиль auth-сервиса с error=forbidden, чтобы пользователь
// мог разлогиниться на главной странице. API/скриптам отвечаем JSON.
func (g *Gateway) denyAccess(w http.ResponseWriter, r *http.Request, role string) {
	if isHTMLAccept(r) {
		redirectURL := g.authURL + "/?error=forbidden&role=" + url.QueryEscape(role)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}
	apierror.HandleAPIError(w, g.logger, apierror.ErrForbidden)
}

// isHTMLAccept - запрос «из браузера» (Accept содержит text/html).
// Обычный curl/API шлёт */* или application/json - для них всё остаётся JSON.
func isHTMLAccept(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// redirectToAuth редиректит пользователя на страницу auth-сервиса (/login
// или /refresh) и передаёт в query исходный адрес (next) целиком, со схемой
// и host, чтобы после входа вернуть его на тот же домен и то же место.
// Проверяет next уже auth-сервис (httpx.SafeNext).
func (g *Gateway) redirectToAuth(w http.ResponseWriter, r *http.Request, page string) {
	redirectURL := g.authURL + "/" + page + "?next=" + url.QueryEscape(requestURL(r))
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// requestURL - исходный адрес запроса так, как его видел браузер.
// За TLS-терминацией (Caddy/nginx) схему берём из X-Forwarded-Proto.
func requestURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		// может прийти списком через цепочку прокси: "https, http"
		proto, _, _ = strings.Cut(proto, ",")
		if proto = strings.ToLower(strings.TrimSpace(proto)); proto == "http" || proto == "https" {
			scheme = proto
		}
	}
	return scheme + "://" + r.Host + r.URL.RequestURI()
}
