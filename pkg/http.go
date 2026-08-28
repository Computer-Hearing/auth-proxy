package pkg

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
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

// NewReverseProxy создает реверс-прокси к целевому сервису
func NewReverseProxy(targetURL string) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	return proxy, nil
}
