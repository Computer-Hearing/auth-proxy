package pkg

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

func SendJSON(logger *slog.Logger, w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		logger.Error("failed to encode json", "error", err.Error())
	}
}

func SendError(logger *slog.Logger, w http.ResponseWriter, err error, statusCode int) {
	SendJSON(logger, w, jsonError{Error: err.Error()}, statusCode)
}

type jsonError struct {
	Error string `json:"error"`
}

// NewReverseProxy создает реверс-прокси к целевому сервису.
// stripFirstPrefix - если true, из пути запроса убирается первый сегмент
// (например, /inference/api/v1 -> /api/v1). logger - куда писать
// транспортные ошибки прокси; если nil, используется slog.Default().
func NewReverseProxy(targetURL string, stripFirstPrefix bool, logger *slog.Logger) (*httputil.ReverseProxy, error) {
	if logger == nil {
		logger = slog.Default()
	}

	target, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)

			if stripFirstPrefix {
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
				slog.String("target", targetURL),
				slog.String("request_id", r.Header.Get("X-Request-ID")),
				slog.String("error", err.Error()),
			)
			SendJSON(logger, w, jsonError{Error: "target service unreachable"}, http.StatusBadGateway)
		},
	}
	return proxy, nil
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
