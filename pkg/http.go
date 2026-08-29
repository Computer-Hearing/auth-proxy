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
// (например, /inference/api/v1 -> /api/v1).
func NewReverseProxy(targetURL string, stripFirstPrefix bool) (*httputil.ReverseProxy, error) {
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
