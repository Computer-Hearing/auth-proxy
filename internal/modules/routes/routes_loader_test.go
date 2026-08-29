package routes

import (
	"auth-proxy/internal/config"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// pathRecorder записывает пути запросов, пришедших на тестовый бэкенд
type pathRecorder struct {
	mu    sync.Mutex
	paths []string
}

func (r *pathRecorder) ServeHTTPName(_ string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.paths = append(r.paths, req.URL.Path)
		w.WriteHeader(http.StatusOK)
	})
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

func buildProxy(t *testing.T, routes []config.RouteConfig) *RoutesProxy {
	t.Helper()
	rp, err := NewRoutesProxy(&config.Config{Routes: routes})
	if err != nil {
		t.Fatalf("NewRoutesProxy: %v", err)
	}
	return rp
}

func serveRoutes(t *testing.T, rp *RoutesProxy, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://proxy.local"+path, nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)
	return rec
}

func TestRoutesProxy_ServeHTTP_ProxyLongestPrefix(t *testing.T) {
	users := &pathRecorder{}
	usersDelete := &pathRecorder{}

	usersSrv := startBackend(t, users.ServeHTTPName("users"))
	usersDeleteSrv := startBackend(t, usersDelete.ServeHTTPName("users-delete"))

	rp := buildProxy(t, []config.RouteConfig{
		{Prefix: "/api/users", Target: usersSrv.URL, SkipAuth: true},
		{Prefix: "/api/users/delete", Target: usersDeleteSrv.URL, SkipAuth: true},
	})

	if rec := serveRoutes(t, rp, "/api/users/list"); rec.Code != http.StatusOK {
		t.Fatalf("list: got code %d, want %d", rec.Code, http.StatusOK)
	}
	if rec := serveRoutes(t, rp, "/api/users/delete/5"); rec.Code != http.StatusOK {
		t.Fatalf("delete: got code %d, want %d", rec.Code, http.StatusOK)
	}

	if got, want := users.Paths(), []string{"/api/users/list"}; !equalStrings(got, want) {
		t.Errorf("users backend paths: got %v, want %v", got, want)
	}
	if got, want := usersDelete.Paths(), []string{"/api/users/delete/5"}; !equalStrings(got, want) {
		t.Errorf("users-delete backend paths: got %v, want %v", got, want)
	}
}

func TestRoutesProxy_ServeHTTP_StripFirstPrefix(t *testing.T) {
	recorder := &pathRecorder{}
	backend := startBackend(t, recorder.ServeHTTPName("inference"))

	rp := buildProxy(t, []config.RouteConfig{
		{Prefix: "/inference", Target: backend.URL, SkipAuth: true, StripFirstPrefix: true},
	})

	cases := map[string]string{
		"/inference/api/v1": "/api/v1",
		"/inference/":       "/",
		"/inference":        "/",
	}
	for path, want := range cases {
		if rec := serveRoutes(t, rp, path); rec.Code != http.StatusOK {
			t.Errorf("%s: got code %d, want %d", path, rec.Code, http.StatusOK)
		}

		paths := recorder.Paths()
		if len(paths) == 0 || paths[len(paths)-1] != want {
			t.Errorf("%s: backend path got %q, want %q", path, paths, want)
		}
	}
}

func TestRoutesProxy_ServeHTTP_ProxyKeepsFullPathByDefault(t *testing.T) {
	recorder := &pathRecorder{}
	backend := startBackend(t, recorder.ServeHTTPName("no-strip"))

	rp := buildProxy(t, []config.RouteConfig{
		{Prefix: "/api/v1", Target: backend.URL, SkipAuth: true},
	})

	if rec := serveRoutes(t, rp, "/api/v1/users"); rec.Code != http.StatusOK {
		t.Fatalf("got code %d, want %d", rec.Code, http.StatusOK)
	}
	if got, want := recorder.Paths(), []string{"/api/v1/users"}; !equalStrings(got, want) {
		t.Errorf("backend paths: got %v, want %v", got, want)
	}
}

func TestRoutesProxy_ServeHTTP_Redirect(t *testing.T) {
	rp := buildProxy(t, []config.RouteConfig{
		{Prefix: "/redir", Target: "http://login:8084/login", SkipAuth: true, Redirect: true},
		{Prefix: "/redir-strip", Target: "http://login:8084/login", SkipAuth: true, Redirect: true, StripFirstPrefix: true},
	})

	cases := []struct {
		path string
		want string
	}{
		{"/redir/api/v1", "http://login:8084/login/redir/api/v1"},
		{"/redir", "http://login:8084/login/redir"},
		{"/redir-strip/api/v1", "http://login:8084/login/api/v1"},
		{"/redir-strip", "http://login:8084/login/"},
	}

	for _, tc := range cases {
		rec := serveRoutes(t, rp, tc.path)
		if rec.Code != http.StatusFound {
			t.Errorf("%s: got code %d, want %d", tc.path, rec.Code, http.StatusFound)
		}
		if got := rec.Header().Get("Location"); got != tc.want {
			t.Errorf("%s: Location got %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestRoutesProxy_ServeHTTP_PathNotFound(t *testing.T) {
	rp := buildProxy(t, []config.RouteConfig{
		{Prefix: "/api/users", Target: "http://users:8081", SkipAuth: true},
	})

	if rec := serveRoutes(t, rp, "/nope"); rec.Code != http.StatusNotFound {
		t.Errorf("got code %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestRoutesProxy_Proxy(t *testing.T) {
	recorder := &pathRecorder{}
	usersDelete := startBackend(t, recorder.ServeHTTPName("users-delete"))

	rp := buildProxy(t, []config.RouteConfig{
		{Prefix: "/api/users", Target: "http://users:8081", SkipAuth: true},
		{Prefix: "/api/users/delete", Target: usersDelete.URL, SkipAuth: true},
	})

	if proxy := rp.Proxy("/api/users/delete/5"); proxy == nil {
		t.Fatal("expected proxy for longest matching prefix, got nil")
	} else {
		req := httptest.NewRequest(http.MethodGet, "http://proxy.local/api/users/delete/5", nil)
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)
	}

	if got, want := recorder.Paths(), []string{"/api/users/delete/5"}; !equalStrings(got, want) {
		t.Errorf("backend paths: got %v, want %v", got, want)
	}

	if proxy := rp.Proxy("/api/users"); proxy == nil {
		t.Error("expected proxy for /api/users")
	}
	if proxy := rp.Proxy("/unknown"); proxy != nil {
		t.Error("expected nil proxy for unknown path")
	}
}

func TestNewRoutesProxy_Errors(t *testing.T) {
	if _, err := NewRoutesProxy(nil); err == nil {
		t.Error("expected error for nil config")
	}

	if _, err := NewRoutesProxy(&config.Config{
		Routes: []config.RouteConfig{{Prefix: "/bad", Target: "http://[::1"}},
	}); err == nil {
		t.Error("expected error for invalid target url")
	}

	if _, err := NewRoutesProxy(&config.Config{
		Routes: []config.RouteConfig{{Prefix: "api/*", Target: "http://x", SkipAuth: true}},
	}); err == nil {
		t.Error("expected error for prefix without leading slash")
	}
}

func TestRoutesProxy_ServeHTTP_WildcardLiteralBeats(t *testing.T) {
	orders := &pathRecorder{}
	wild := &pathRecorder{}

	ordersSrv := startBackend(t, orders.ServeHTTPName("orders"))
	wildSrv := startBackend(t, wild.ServeHTTPName("wild"))

	rp := buildProxy(t, []config.RouteConfig{
		{Prefix: "/api/*", Target: wildSrv.URL, SkipAuth: true},
		{Prefix: "/api/orders", Target: ordersSrv.URL, SkipAuth: true},
	})

	if rec := serveRoutes(t, rp, "/api/orders/5"); rec.Code != http.StatusOK {
		t.Fatalf("orders: got code %d, want %d", rec.Code, http.StatusOK)
	}
	if rec := serveRoutes(t, rp, "/api/users/5"); rec.Code != http.StatusOK {
		t.Fatalf("wild: got code %d, want %d", rec.Code, http.StatusOK)
	}

	if got, want := orders.Paths(), []string{"/api/orders/5"}; !equalStrings(got, want) {
		t.Errorf("orders backend paths: got %v, want %v", got, want)
	}
	if got, want := wild.Paths(), []string{"/api/users/5"}; !equalStrings(got, want) {
		t.Errorf("wild backend paths: got %v, want %v", got, want)
	}
}

func TestRoutesProxy_ServeHTTP_WildcardMidPath(t *testing.T) {
	recorder := &pathRecorder{}
	backend := startBackend(t, recorder.ServeHTTPName("v1"))

	rp := buildProxy(t, []config.RouteConfig{
		{Prefix: "/api/*/v1", Target: backend.URL, SkipAuth: true},
	})

	if rec := serveRoutes(t, rp, "/api/x/v1/anything"); rec.Code != http.StatusOK {
		t.Errorf("match: got code %d, want %d", rec.Code, http.StatusOK)
	}
	if rec := serveRoutes(t, rp, "/api/x/v2"); rec.Code != http.StatusNotFound {
		t.Errorf("no-match: got code %d, want %d", rec.Code, http.StatusNotFound)
	}

	if got, want := recorder.Paths(), []string{"/api/x/v1/anything"}; !equalStrings(got, want) {
		t.Errorf("backend paths: got %v, want %v", got, want)
	}
}

func TestRoutesProxy_ServeHTTP_WildcardStaticWithStrip(t *testing.T) {
	recorder := &pathRecorder{}
	backend := startBackend(t, recorder.ServeHTTPName("static"))

	rp := buildProxy(t, []config.RouteConfig{
		{Prefix: "/static/**", Target: backend.URL, SkipAuth: true, StripFirstPrefix: true},
	})

	cases := map[string]string{
		"/static/a/b":    "/a/b",
		"/static/app.js": "/app.js",
		"/static/":       "/",
		"/static":        "",
	}
	for path, want := range cases {
		rec := serveRoutes(t, rp, path)
		if want == "" {
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s: got code %d, want %d", path, rec.Code, http.StatusNotFound)
			}
			continue
		}
		if rec.Code != http.StatusOK {
			t.Errorf("%s: got code %d, want %d", path, rec.Code, http.StatusOK)
		}

		paths := recorder.Paths()
		if len(paths) == 0 || paths[len(paths)-1] != want {
			t.Errorf("%s: backend path got %q, want %q", path, paths, want)
		}
	}
}

func TestRoutesProxy_ServeHTTP_WildcardFileRoot(t *testing.T) {
	recorder := &pathRecorder{}
	backend := startBackend(t, recorder.ServeHTTPName("assets"))

	rp := buildProxy(t, []config.RouteConfig{
		{Prefix: "/*.js", Target: backend.URL, SkipAuth: true},
	})

	if rec := serveRoutes(t, rp, "/app.js"); rec.Code != http.StatusOK {
		t.Errorf("match: got code %d, want %d", rec.Code, http.StatusOK)
	}
	if rec := serveRoutes(t, rp, "/static/app.js"); rec.Code != http.StatusNotFound {
		t.Errorf("no cross-segment match: got code %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
