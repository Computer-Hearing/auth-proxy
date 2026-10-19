package reverseproxy

import (
	"auth-proxy/internal/config"
	"auth-proxy/pkg/httpx"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const redirectStatus = http.StatusFound

// New строит обработчик одного маршрута: реверс-прокси на target или,
// при route.Redirect, 302 на target + путь запроса. Маршрут уже выбран
// (ruleengine), здесь только отправка запроса.
// logger - куда писать транспортные ошибки прокси (502);
func New(route config.RouteConfig, logger *slog.Logger) (http.Handler, error) {
	if logger == nil {
		logger = slog.Default()
	}

	target, err := url.Parse(route.Target)
	if err != nil {
		return nil, err
	}

	if route.Redirect {
		return &redirectHandler{target: target, stripFirst: route.StripFirstPrefix}, nil
	}
	return newProxy(target, route.StripFirstPrefix, logger), nil
}

// newProxy создает реверс-прокси к целевому сервису.
// stripFirst - если true, из пути запроса убирается первый сегмент
// (например, /inference/api/v1 -> /api/v1).
func newProxy(target *url.URL, stripFirst bool, logger *slog.Logger) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)

			if stripFirst {
				pr.Out.URL.Path = StripFirstPath(pr.In.URL.Path)
				pr.Out.URL.RawPath = ""
			}
		},
		// ErrorHandler логирует причину транспортной ошибки (недоступный таргет,
		// EOF, таймаут и т.п.) и отвечает 502. Без него ReverseProxy глушит ошибку
		// дефолтным http.Error, а причина теряется (классический случай - молчаливый
		// 502 на бэкенд, который не поднялся).
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("reverse proxy: target service unreachable",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("target", target.String()),
				slog.String("request_id", r.Header.Get("X-Request-ID")),
				slog.String("error", err.Error()),
			)
			httpx.SendError(logger, w, errors.New("target service unreachable"), http.StatusBadGateway)
		},
	}
}

// redirectHandler отдает 302 на target + путь запроса (при stripFirst - без первого сегмента)
type redirectHandler struct {
	target     *url.URL
	stripFirst bool
}

func (h *redirectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if h.stripFirst {
		path = StripFirstPath(path)
	}

	location := *h.target
	location.Path = joinPaths(location.Path, path)
	location.RawPath = ""
	http.Redirect(w, r, location.String(), redirectStatus)
}

// StripFirstPath убирает первый сегмент пути: /inference/api/v1 -> /api/v1, /inference -> /
func StripFirstPath(path string) string {
	p := strings.TrimPrefix(path, "/")
	idx := strings.IndexByte(p, '/')
	if idx == -1 {
		return "/"
	}
	return "/" + p[idx+1:]
}

// joinPaths склеивает путь target и подпуть запроса с одним слешем
func joinPaths(base, sub string) string {
	if base == "" {
		return sub
	}
	return strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(sub, "/")
}
