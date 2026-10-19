package httpx

import (
	"log/slog"
	"net/http"
)

type healthStatus struct {
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
}

// Healthz - обработчик проверки живости: {"status":"ok"} и, если задана, версия.
func Healthz(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		SendJSON(slog.Default(), w, healthStatus{Status: "ok", Version: version}, http.StatusOK)
	}
}
