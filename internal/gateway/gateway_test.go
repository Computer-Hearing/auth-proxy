package gateway

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"auth-proxy/internal/config"
	"auth-proxy/internal/reverseproxy"
	"auth-proxy/internal/store"
)

var testRoles = []string{"superadmin", "admin", "user"}

func backend(t *testing.T, name string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(name))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func adminBackend(t *testing.T) int {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("admin"))
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().(*net.TCPAddr).Port
}

func newGateway(t *testing.T, roles []string, routes []config.RouteConfig, adminPort int) *Gateway {
	t.Helper()
	snap, err := store.Build(&config.Routes{Roles: roles, Routes: routes}, func(route config.RouteConfig) (http.Handler, error) {
		return reverseproxy.New(route, slog.Default())
	})
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	g, err := New(&Options{
		Store:        store.New(snap),
		AdminPort:    adminPort,
		SecretHeader: "X-Proxy-Secret",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func do(g *Gateway, method, host, path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://"+host+path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, req)
	return rec
}

func identityHeaders(groups string) map[string]string {
	return map[string]string{
		"X-authentik-username": "alice",
		"X-authentik-groups":   groups,
	}
}

func TestHostRouting_XForwardedHost(t *testing.T) {
	api := backend(t, "api")
	def := backend(t, "default")

	g := newGateway(t, testRoles, []config.RouteConfig{
		{Prefix: "/api", Host: "api.example.com", Target: api.URL},
		{Prefix: "/api", Target: def.URL},
	}, 0)

	cases := []struct {
		name    string
		host    string
		headers map[string]string
		want    string
	}{
		{"x-forwarded-host", "internal:5000", map[string]string{"X-Forwarded-Host": "api.example.com"}, "api"},
		{"r.host fallback", "api.example.com", nil, "api"},
		{"other host", "other.com", nil, "default"},
		{"x-forwarded-host list", "internal:5000", map[string]string{"X-Forwarded-Host": "api.example.com, proxy"}, "api"},
	}
	for _, tc := range cases {
		rec := do(g, http.MethodGet, tc.host, "/api", tc.headers)
		if rec.Code != http.StatusOK || rec.Body.String() != tc.want {
			t.Errorf("%s: got %d %q, want 200 %q", tc.name, rec.Code, rec.Body.String(), tc.want)
		}
	}
}

func TestAuthorize_EmptyGroups(t *testing.T) {
	open := backend(t, "open")
	g := newGateway(t, testRoles, []config.RouteConfig{{Prefix: "/open", Target: open.URL}}, 0)

	if rec := do(g, http.MethodGet, "any", "/open", nil); rec.Code != http.StatusOK || rec.Body.String() != "open" {
		t.Errorf("got %d %q, want 200 open", rec.Code, rec.Body.String())
	}
}

func TestAuthorize_RequiredGroups(t *testing.T) {
	api := backend(t, "api")
	g := newGateway(t, testRoles, []config.RouteConfig{
		{Prefix: "/api", Target: api.URL, RequiredGroups: []string{"admin"}},
	}, 0)

	cases := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"no headers", nil, http.StatusUnauthorized},
		{"lower group", identityHeaders("user"), http.StatusForbidden},
		{"exact group", identityHeaders("admin"), http.StatusOK},
		{"higher group", identityHeaders("superadmin"), http.StatusOK},
		{"unknown ignored", identityHeaders("ghost|admin"), http.StatusOK},
		{"unknown only", identityHeaders("ghost"), http.StatusForbidden},
	}
	for _, tc := range cases {
		rec := do(g, http.MethodGet, "any", "/api", tc.headers)
		if rec.Code != tc.want {
			t.Errorf("%s: got %d, want %d (body %q)", tc.name, rec.Code, tc.want, rec.Body.String())
		}
	}
}

func TestAdminPaths(t *testing.T) {
	adminPort := adminBackend(t)
	g := newGateway(t, testRoles, nil, adminPort)

	cases := []struct {
		name    string
		path    string
		headers map[string]string
		want    int
		body    string
	}{
		{"admin no headers", "/_admin/", nil, http.StatusUnauthorized, ""},
		{"admin lower role", "/_admin/", identityHeaders("admin"), http.StatusForbidden, ""},
		{"admin top role", "/_admin/", identityHeaders("superadmin"), http.StatusOK, "admin"},
		{"config top role", "/config", identityHeaders("superadmin"), http.StatusOK, "admin"},
		{"config no headers", "/config", nil, http.StatusUnauthorized, ""},
	}
	for _, tc := range cases {
		rec := do(g, http.MethodGet, "admin.example.com", tc.path, tc.headers)
		if rec.Code != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, rec.Code, tc.want)
			continue
		}
		if tc.body != "" && rec.Body.String() != tc.body {
			t.Errorf("%s: body got %q, want %q", tc.name, rec.Body.String(), tc.body)
		}
	}
}

func TestHealthz(t *testing.T) {
	g := newGateway(t, testRoles, nil, 0)
	rec := do(g, http.MethodGet, "any", "/healthz", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("got %d, want 200", rec.Code)
	}
}

func TestRouteNotFound(t *testing.T) {
	g := newGateway(t, testRoles, nil, 0)
	if rec := do(g, http.MethodGet, "any", "/nope", nil); rec.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", rec.Code)
	}
}

func TestRequestHost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://Grafana.Example.com:5000/", nil)
	if got := requestHost(req); got != "grafana.example.com" {
		t.Errorf("got %q", got)
	}

	req.Header.Set("X-Forwarded-Host", "API.Example.com:443, proxy")
	if got := requestHost(req); got != "api.example.com" {
		t.Errorf("got %q", got)
	}
}
