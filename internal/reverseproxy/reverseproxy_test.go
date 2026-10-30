package reverseproxy

import (
	"auth-proxy/internal/config"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// pathRecorder записывает пути запросов, пришедших на тестовый бэкенд
type pathRecorder struct {
	mu    sync.Mutex
	paths []string
}

func (r *pathRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.paths = append(r.paths, req.URL.Path)
	w.WriteHeader(http.StatusOK)
}

func (r *pathRecorder) Paths() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.paths...)
}

func startBackend(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func mustNew(t *testing.T, route config.RouteConfig) http.Handler {
	t.Helper()
	h, err := New(route, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

func serve(h http.Handler, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://proxy.local"+path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestProxy_KeepsFullPathByDefault(t *testing.T) {
	recorder := &pathRecorder{}
	backend := startBackend(t, recorder)
	h := mustNew(t, config.RouteConfig{Prefix: "/api/v1", Target: backend.URL})

	if rec := serve(h, "/api/v1/users"); rec.Code != http.StatusOK {
		t.Fatalf("got code %d, want %d", rec.Code, http.StatusOK)
	}
	if got, want := recorder.Paths(), []string{"/api/v1/users"}; !slices.Equal(got, want) {
		t.Errorf("backend paths: got %v, want %v", got, want)
	}
}

func TestProxy_StripFirstPrefix(t *testing.T) {
	cases := []struct {
		prefix string
		paths  map[string]string
	}{
		{"/inference", map[string]string{
			"/inference/api/v1": "/api/v1",
			"/inference/":       "/",
			"/inference":        "/",
		}},
		{"/static/**", map[string]string{
			"/static/a/b":    "/a/b",
			"/static/app.js": "/app.js",
			"/static/":       "/",
		}},
	}

	for _, tc := range cases {
		recorder := &pathRecorder{}
		backend := startBackend(t, recorder)
		h := mustNew(t, config.RouteConfig{Prefix: tc.prefix, Target: backend.URL, StripFirstPrefix: true})

		for path, want := range tc.paths {
			if rec := serve(h, path); rec.Code != http.StatusOK {
				t.Errorf("%s: got code %d, want %d", path, rec.Code, http.StatusOK)
			}
			paths := recorder.Paths()
			if len(paths) == 0 || paths[len(paths)-1] != want {
				t.Errorf("%s: backend path got %q, want %q", path, paths, want)
			}
		}
	}
}

func TestRedirect(t *testing.T) {
	plain := mustNew(t, config.RouteConfig{Prefix: "/redir", Target: "http://login:8084/login", Redirect: true})
	strip := mustNew(t, config.RouteConfig{Prefix: "/redir-strip", Target: "http://login:8084/login", Redirect: true, StripFirstPrefix: true})

	cases := []struct {
		h    http.Handler
		path string
		want string
	}{
		{plain, "/redir/api/v1", "http://login:8084/login/redir/api/v1"},
		{plain, "/redir", "http://login:8084/login/redir"},
		{strip, "/redir-strip/api/v1", "http://login:8084/login/api/v1"},
		{strip, "/redir-strip", "http://login:8084/login/"},
	}

	for _, tc := range cases {
		rec := serve(tc.h, tc.path)
		if rec.Code != http.StatusFound {
			t.Errorf("%s: got code %d, want %d", tc.path, rec.Code, http.StatusFound)
		}
		if got := rec.Header().Get("Location"); got != tc.want {
			t.Errorf("%s: Location got %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestProxy_UnreachableTarget(t *testing.T) {
	backend := startBackend(t, http.NotFoundHandler())
	backend.Close() // таргет недоступен

	h := mustNew(t, config.RouteConfig{Prefix: "/api", Target: backend.URL})
	rec := serve(h, "/api")
	if rec.Code != http.StatusBadGateway {
		t.Errorf("got code %d, want %d", rec.Code, http.StatusBadGateway)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type got %q, want application/json", ct)
	}
	if !strings.Contains(rec.Body.String(), "target service unreachable") {
		t.Errorf("body got %q, want JSON error", rec.Body.String())
	}
}

func TestProxy_UnreachableTarget_HTML(t *testing.T) {
	backend := startBackend(t, http.NotFoundHandler())
	backend.Close() // таргет недоступен

	h := mustNew(t, config.RouteConfig{Prefix: "/api", Target: backend.URL})

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/api", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("got code %d, want %d", rec.Code, http.StatusBadGateway)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type got %q, want text/html", ct)
	}
	if !strings.Contains(rec.Body.String(), "502") {
		t.Error("body should contain the 502 error page")
	}
}

func TestNew_InvalidTarget(t *testing.T) {
	if _, err := New(config.RouteConfig{Prefix: "/bad", Target: "http://[::1"}, nil); err == nil {
		t.Error("expected error for invalid target url")
	}
	if _, err := New(config.RouteConfig{Prefix: "/bad", Target: "http://[::1", Redirect: true}, nil); err == nil {
		t.Error("expected error for invalid redirect target url")
	}
}
