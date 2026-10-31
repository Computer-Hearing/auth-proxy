package admin

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"auth-proxy/internal/config"
	"auth-proxy/internal/reverseproxy"
	"auth-proxy/internal/store"
)

var testRoles = []string{"superadmin", "admin", "user"}

func initialRoutes() *config.Routes {
	return &config.Routes{
		Roles: testRoles,
		Routes: []config.RouteConfig{
			{Prefix: "/api", Target: "http://api:8080", RequiredGroups: []string{"admin"}},
		},
	}
}

func newTestAdmin(t *testing.T, routes *config.Routes, routesPath string) *Admin {
	t.Helper()
	snap, err := store.Build(routes, func(route config.RouteConfig) (http.Handler, error) {
		return reverseproxy.New(route, slog.Default())
	})
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	a, err := New(&Options{
		Store:        store.New(snap),
		RoutesPath:   routesPath,
		SecretHeader: "X-Proxy-Secret",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func topHeaders() map[string]string {
	return map[string]string{
		"X-authentik-username": "root",
		"X-authentik-groups":   "superadmin",
	}
}

func call(a *Admin, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, "http://admin.local"+path, nil)
	} else {
		req = httptest.NewRequest(method, "http://admin.local"+path, strings.NewReader(body))
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)
	return rec
}

func writeInitial(t *testing.T, path string) {
	t.Helper()
	if err := config.WriteRoutes(path, initialRoutes()); err != nil {
		t.Fatalf("write initial routes: %v", err)
	}
}

func TestAdmin_GetConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.yaml")
	writeInitial(t, path)
	a := newTestAdmin(t, initialRoutes(), path)

	rec := call(a, http.MethodGet, "/config", "", topHeaders())
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var got config.Routes
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Roles) != 3 || got.Roles[0] != "superadmin" {
		t.Errorf("roles: got %v", got.Roles)
	}
	if len(got.Routes) != 1 || got.Routes[0].Prefix != "/api" {
		t.Errorf("routes: got %+v", got.Routes)
	}
}

func TestAdmin_PutConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.yaml")
	writeInitial(t, path)
	a := newTestAdmin(t, initialRoutes(), path)

	body, err := json.Marshal(config.Routes{
		Roles: testRoles,
		Routes: []config.RouteConfig{
			{
				Host:             "new.example.com",
				Prefix:           "/new",
				Target:           "http://new:8080",
				StripFirstPrefix: true,
				RequiredGroups:   []string{"user"},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	rec := call(a, http.MethodPut, "/config", string(body), topHeaders())
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// файл перезаписан
	onDisk, err := config.LoadRoutes(path)
	if err != nil {
		t.Fatalf("LoadRoutes: %v", err)
	}
	if len(onDisk.Routes) != 1 || onDisk.Routes[0].Host != "new.example.com" {
		t.Errorf("file routes: got %+v", onDisk.Routes)
	}
	if !onDisk.Routes[0].StripFirstPrefix {
		t.Error("strip_first_prefix not persisted")
	}

	// снапшот подменён
	snap := a.store.Load()
	if len(snap.Routes) != 1 || snap.Routes[0].Prefix != "/new" {
		t.Errorf("snapshot routes: got %+v", snap.Routes)
	}

	// GET отдаёт новое состояние
	rec = call(a, http.MethodGet, "/config", "", topHeaders())
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"new.example.com"`)) {
		t.Errorf("GET after PUT: got %d %s", rec.Code, rec.Body.String())
	}
}

func TestAdmin_PutInvalidGroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.yaml")
	writeInitial(t, path)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	a := newTestAdmin(t, initialRoutes(), path)

	body, _ := json.Marshal(config.Routes{
		Roles:  testRoles,
		Routes: []config.RouteConfig{{Prefix: "/x", Target: "http://x:8080", RequiredGroups: []string{"ghost"}}},
	})
	rec := call(a, http.MethodPut, "/config", string(body), topHeaders())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400: %s", rec.Code, rec.Body.String())
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("routes file changed after invalid PUT")
	}
}

func TestAdmin_PutRevokesTop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.yaml")
	writeInitial(t, path)
	a := newTestAdmin(t, initialRoutes(), path)

	body, _ := json.Marshal(config.Routes{
		Roles:  []string{"admin", "user"},
		Routes: []config.RouteConfig{{Prefix: "/api", Target: "http://api:8080"}},
	})
	rec := call(a, http.MethodPut, "/config", string(body), topHeaders())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

func TestAdmin_Auth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.yaml")
	writeInitial(t, path)
	a := newTestAdmin(t, initialRoutes(), path)

	if rec := call(a, http.MethodGet, "/config", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no headers: got %d, want 401", rec.Code)
	}
	if rec := call(a, http.MethodGet, "/config", "", map[string]string{
		"X-authentik-username": "bob",
		"X-authentik-groups":   "admin",
	}); rec.Code != http.StatusForbidden {
		t.Errorf("admin role: got %d, want 403", rec.Code)
	}
	if rec := call(a, http.MethodGet, "/config", "", topHeaders()); rec.Code != http.StatusOK {
		t.Errorf("top role: got %d, want 200", rec.Code)
	}
}

func TestAdmin_Static(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.yaml")
	writeInitial(t, path)
	a := newTestAdmin(t, initialRoutes(), path)

	rec := call(a, http.MethodGet, "/_admin/", "", topHeaders())
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "auth-proxy") {
		t.Error("index.html not served")
	}

	rec = call(a, http.MethodGet, "/_admin/", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("static without headers: got %d, want 401", rec.Code)
	}
}

func TestAdmin_MethodNotAllowed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.yaml")
	writeInitial(t, path)
	a := newTestAdmin(t, initialRoutes(), path)

	rec := call(a, http.MethodPost, "/config", "{}", topHeaders())
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("got %d, want 405", rec.Code)
	}
}

func domainRoutes() *config.Routes {
	return &config.Routes{
		Roles: testRoles,
		Routes: []config.RouteConfig{
			{Prefix: "/", Host: "app.example.com", Target: "http://app:8080"},
			{Prefix: "/", Host: "*.example.com", Target: "http://wild:8080"},
			{Prefix: "/", Target: "http://default:8080"},
		},
	}
}

func TestAdmin_AllowedDomain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.yaml")
	a := newTestAdmin(t, domainRoutes(), path)

	cases := []struct {
		name string
		path string
		want int
	}{
		{"exact", "/internal/allowed-domain?domain=app.example.com", http.StatusOK},
		{"case and port", "/internal/allowed-domain?domain=APP.Example.com:443", http.StatusOK},
		{"trailing dot", "/internal/allowed-domain?domain=app.example.com.", http.StatusOK},
		{"wildcard excluded", "/internal/allowed-domain?domain=grafana.example.com", http.StatusNotFound},
		{"no-host routes excluded", "/internal/allowed-domain?domain=other.com", http.StatusNotFound},
		{"missing param", "/internal/allowed-domain", http.StatusBadRequest},
		{"empty param", "/internal/allowed-domain?domain=", http.StatusBadRequest},
	}
	for _, tc := range cases {
		// Без заголовков Authentik: ручка публичная.
		rec := call(a, http.MethodGet, tc.path, "", nil)
		if rec.Code != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
}

func TestAdmin_AllowedDomain_MethodNotAllowed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.yaml")
	a := newTestAdmin(t, domainRoutes(), path)

	rec := call(a, http.MethodPost, "/internal/allowed-domain?domain=app.example.com", "", nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d, want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != http.MethodGet {
		t.Errorf("Allow: got %q, want GET", got)
	}
}

func TestAdmin_AllowedDomain_HotReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.yaml")
	writeInitial(t, path)
	a := newTestAdmin(t, initialRoutes(), path) // /api без host

	if rec := call(a, http.MethodGet, "/internal/allowed-domain?domain=new.example.com", "", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("before PUT: got %d, want 404", rec.Code)
	}

	body, err := json.Marshal(config.Routes{
		Roles: testRoles,
		Routes: []config.RouteConfig{
			{Prefix: "/", Host: "new.example.com", Target: "http://new:8080"},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if rec := call(a, http.MethodPut, "/config", string(body), topHeaders()); rec.Code != http.StatusOK {
		t.Fatalf("PUT: got %d: %s", rec.Code, rec.Body.String())
	}

	if rec := call(a, http.MethodGet, "/internal/allowed-domain?domain=new.example.com", "", nil); rec.Code != http.StatusOK {
		t.Errorf("after PUT: got %d, want 200", rec.Code)
	}
}
