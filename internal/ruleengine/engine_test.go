package ruleengine

import (
	"auth-proxy/internal/config"
	"errors"
	"net/http"
	"testing"
)

// stubBuilder - обработчик не нужен, проверяем только выбор маршрута
func stubBuilder(config.RouteConfig) (http.Handler, error) {
	return http.NotFoundHandler(), nil
}

func mustEngine(t *testing.T, routes []config.RouteConfig) *Engine {
	t.Helper()
	e, err := New(routes, stubBuilder)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// matchCase: want - Target выбранного маршрута, "" = маршрут не найден
type matchCase struct {
	host, path, want string
}

func checkMatches(t *testing.T, e *Engine, cases []matchCase) {
	t.Helper()
	for _, tc := range cases {
		rule, ok := e.Match(tc.host, tc.path)
		switch {
		case tc.want == "" && ok:
			t.Errorf("host %q path %q: got %s, want no match", tc.host, tc.path, rule.Route.Target)
		case tc.want != "" && !ok:
			t.Errorf("host %q path %q: got no match, want %s", tc.host, tc.path, tc.want)
		case ok && rule.Route.Target != tc.want:
			t.Errorf("host %q path %q: got %s, want %s", tc.host, tc.path, rule.Route.Target, tc.want)
		}
	}
}

func TestMatch_Wildcard(t *testing.T) {
	e := mustEngine(t, []config.RouteConfig{
		{Prefix: "/api/*", Target: "http://wild"},
		{Prefix: "/api/orders", Target: "http://orders"},
		{Prefix: "/api", Target: "http://api"}, // шире, чем /api/*
		{Prefix: "/static/**", Target: "http://static"},
	})

	checkMatches(t, e, []matchCase{
		{"", "/api/orders/5", "http://orders"},
		{"", "/api/users/5", "http://wild"},
		{"", "/api", "http://api"},
		{"", "/static/a/b", "http://static"},
		{"", "/static", ""},
		{"", "/nope", ""},
	})
}

func TestMatch_LongestPrefix(t *testing.T) {
	e := mustEngine(t, []config.RouteConfig{
		{Prefix: "/api/users", Target: "http://users"},
		{Prefix: "/api/users/delete", Target: "http://users-delete"},
	})

	checkMatches(t, e, []matchCase{
		{"", "/api/users/list", "http://users"},
		{"", "/api/users/delete/5", "http://users-delete"},
		{"", "/nope", ""},
	})
}

func TestMatch_WildcardSegments(t *testing.T) {
	e := mustEngine(t, []config.RouteConfig{
		{Prefix: "/api/*/v1", Target: "http://v1"},
		{Prefix: "/*.js", Target: "http://assets"},
	})

	checkMatches(t, e, []matchCase{
		{"", "/api/x/v1/anything", "http://v1"},
		{"", "/api/x/v2", ""},
		{"", "/app.js", "http://assets"},
		{"", "/static/app.js", ""}, // * не пересекает "/"
	})
}

func TestMatch_WithHost(t *testing.T) {
	e := mustEngine(t, []config.RouteConfig{
		{Prefix: "/api", Host: "api.example.com", Target: "http://api:8080"},
		{Prefix: "/api", Host: "analytics.example.com", Target: "http://analytics:8080"},
		{Prefix: "/api", Target: "http://default:8080"},
	})

	checkMatches(t, e, []matchCase{
		{"api.example.com", "/api", "http://api:8080"},
		{"analytics.example.com", "/api", "http://analytics:8080"},
		{"other.com", "/api", "http://default:8080"},
		{"", "/api", "http://default:8080"},
	})
}

func TestMatch_HostPriority(t *testing.T) {
	e := mustEngine(t, []config.RouteConfig{
		{Prefix: "/api", Target: "http://default:8080"},
		{Prefix: "/api", Host: "api.example.com", Target: "http://api:8080"},
	})

	// host-specific побеждает, даже если объявлен позже
	checkMatches(t, e, []matchCase{{"api.example.com", "/api", "http://api:8080"}})
}

func TestMatch_HostWithCatchAll(t *testing.T) {
	e := mustEngine(t, []config.RouteConfig{
		{Prefix: "/", Target: "https://www.kuronami.fun"},
		{Prefix: "/**", Host: "portainer.kuronami.fun", Target: "http://portainer"},
		{Prefix: "/**", Target: "http://default"},
	})

	checkMatches(t, e, []matchCase{
		{"portainer.kuronami.fun", "/", "http://portainer"},
		{"other.kuronami.fun", "/", "http://default"},
	})
}

func TestMatch_WildcardHost(t *testing.T) {
	e := mustEngine(t, []config.RouteConfig{
		{Prefix: "/", Host: "*.example.com", Target: "http://wildcard:8080"},
		{Prefix: "/", Host: "specific.example.com", Target: "http://specific:8080"},
		{Prefix: "/", Target: "http://default:8080"},
	})

	checkMatches(t, e, []matchCase{
		{"grafana.example.com", "/", "http://wildcard:8080"},
		{"specific.example.com", "/", "http://specific:8080"},
		{"other.com", "/", "http://default:8080"},
		{"a.b.example.com", "/", "http://default:8080"},
	})
}

func TestMatchHost_Wildcard(t *testing.T) {
	cases := []struct {
		routeHost string
		reqHost   string
		want      bool
	}{
		{"*.example.com", "grafana.example.com", true},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "example.com", false},
		{"*.test.example.com", "grafana.test.example.com", true},
		{"*.test.example.com", "a.b.test.example.com", false},
		{"api.example.com", "api.example.com", true},
		{"api.example.com", "other.example.com", false},
		{"", "anything.com", false},
	}

	for _, tc := range cases {
		if got := matchHost(tc.routeHost, tc.reqHost); got != tc.want {
			t.Errorf("matchHost(%q, %q) = %v, want %v", tc.routeHost, tc.reqHost, got, tc.want)
		}
	}
}

func TestNew_Errors(t *testing.T) {
	if _, err := New([]config.RouteConfig{{Prefix: "api/*", Target: "http://x"}}, stubBuilder); err == nil {
		t.Error("expected error for prefix without leading slash")
	}

	failing := func(config.RouteConfig) (http.Handler, error) { return nil, errors.New("boom") }
	if _, err := New([]config.RouteConfig{{Prefix: "/a", Target: "http://x"}}, failing); err == nil {
		t.Error("expected builder error to be returned")
	}
}
