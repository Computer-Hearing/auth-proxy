package gateway

import (
	"auth-proxy/internal/config"
	"auth-proxy/internal/tokens"
	"auth-proxy/internal/users"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// namedBackend отвечает своим именем - видно, куда ушёл запрос
func namedBackend(t *testing.T, name string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(name))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newGateway(t *testing.T, routes []config.RouteConfig) *Gateway {
	t.Helper()
	g, err := New(&Options{
		Routes:  routes,
		Cookie:  config.CookieConfig{AccessName: "access_token", RefreshName: "refresh_token"},
		AuthURL: "http://auth.local",
		Tokens:  tokens.New(tokens.Config{SecretKey: "test-secret"}),
		Users:   users.New(nil),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func serveHost(g *Gateway, host, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	return rec
}

// Права и проксирование берутся из одного маршрута: раньше доступ
// проверялся по host-маршруту, а запрос уходил в открытый маршрут без host.
func TestServeHTTP_AuthAndProxyUseSameRoute(t *testing.T) {
	public := namedBackend(t, "public")
	admin := namedBackend(t, "admin")
	wildcard := namedBackend(t, "wildcard")

	g := newGateway(t, []config.RouteConfig{
		{Prefix: "/api", Target: public.URL, AuthMethod: config.AuthNone},
		{Prefix: "/api", Host: "admin.example.com", Target: admin.URL, AuthMethod: config.AuthJWT,
			RequiredRoles: []string{"superadmin"}},
		{Prefix: "/files", Host: "*.example.com", Target: wildcard.URL, AuthMethod: config.AuthNone},
	})

	// открытый маршрут без host
	if rec := serveHost(g, "other.com", "/api"); rec.Code != http.StatusOK || rec.Body.String() != "public" {
		t.Errorf("other.com/api: got %d %q, want 200 public", rec.Code, rec.Body.String())
	}

	// host-маршрут требует jwt: без кук - редирект на логин, в public не уходим
	rec := serveHost(g, "admin.example.com", "/api")
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "http://auth.local/login") {
		t.Errorf("admin.example.com/api: got %d Location %q, want redirect to login", rec.Code, rec.Header().Get("Location"))
	}

	// host с портом и в другом регистре - тот же маршрут
	rec = serveHost(g, "Admin.Example.com:5000", "/api")
	if rec.Code != http.StatusFound {
		t.Errorf("Admin.Example.com:5000/api: got %d, want redirect to login", rec.Code)
	}

	// wildcard-host маршрут проксируется, а не отдаёт 404
	if rec := serveHost(g, "grafana.example.com", "/files"); rec.Code != http.StatusOK || rec.Body.String() != "wildcard" {
		t.Errorf("grafana.example.com/files: got %d %q, want 200 wildcard", rec.Code, rec.Body.String())
	}
}

func TestServeHTTP_RouteNotFound(t *testing.T) {
	g := newGateway(t, []config.RouteConfig{{Prefix: "/api", Target: "http://x", AuthMethod: config.AuthNone}})
	if rec := serveHost(g, "any", "/nope"); rec.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", rec.Code)
	}
}

// next - полный адрес запроса со схемой и host, чтобы auth вернул на тот же домен
func TestServeHTTP_RedirectKeepsHostInNext(t *testing.T) {
	g := newGateway(t, []config.RouteConfig{
		{Prefix: "/", Host: "*.example.com", Target: "http://x", AuthMethod: config.AuthJWT,
			RequiredRoles: []string{"user"}},
	})

	cases := []struct {
		name      string
		forwarded string
		wantNext  string
	}{
		{"plain http", "", "http://grafana.example.com/d/abc?x=1"},
		{"behind tls proxy", "https", "https://grafana.example.com/d/abc?x=1"},
		{"proxy chain", "https, http", "https://grafana.example.com/d/abc?x=1"},
		{"garbage proto ignored", "javascript", "http://grafana.example.com/d/abc?x=1"},
	}

	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "http://grafana.example.com/d/abc?x=1", nil)
		if tc.forwarded != "" {
			req.Header.Set("X-Forwarded-Proto", tc.forwarded)
		}
		rec := httptest.NewRecorder()
		g.ServeHTTP(rec, req)

		want := "http://auth.local/login?next=" + url.QueryEscape(tc.wantNext)
		if got := rec.Header().Get("Location"); got != want {
			t.Errorf("%s: Location got %q, want %q", tc.name, got, want)
		}
	}
}
