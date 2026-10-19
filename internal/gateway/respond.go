package gateway

import (
	"auth-proxy/pkg/apierror"
	"auth-proxy/pkg/httpx"
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
// мог разлогиниться на главной странице. API/скриптам отвечаем JSON как раньше.
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
// или /refresh) и передаёт в query исходный путь (next), чтобы после входа
// вернуть его на то же место.
func (g *Gateway) redirectToAuth(w http.ResponseWriter, r *http.Request, page string) {
	next := httpx.SafeNext(r.URL.RequestURI())
	redirectURL := g.authURL + "/" + page + "?next=" + url.QueryEscape(next)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}
