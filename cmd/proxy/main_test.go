package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newGatewayHandler: /healthz отдаёт 200 с версией, а остальные пути
// уходят в прокси-хендлер
func TestNewGatewayHandler_Healthz(t *testing.T) {
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot) // сюда /healthz попадать не должен
	})
	h := newGatewayHandlerWithHealthz(proxy, "1.2.3")

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"version":"1.2.3"`) {
		t.Errorf("body: got %q, want version 1.2.3", rec.Body.String())
	}
}

func TestNewGatewayHandler_NonHealthzPathGoesToProxy(t *testing.T) {
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	h := newGatewayHandlerWithHealthz(proxy, "dev")

	req := httptest.NewRequest(http.MethodPost, "/some/path", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected proxy to handle path, got %d", rec.Code)
	}
}
