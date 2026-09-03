package handlers

import (
	"auth-proxy/internal/config"
	"auth-proxy/internal/domain"
	"auth-proxy/internal/modules/tokens"
	"auth-proxy/internal/modules/users"
	"auth-proxy/pkg"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const testSecret = "supersecret-access-key-32-chars-min"

// backendStub - заглушка бекенда, в ответе пишет свой адрес: backend:/api/...
func backendStub(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend:" + r.URL.Path))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// testStorage строит UserStorage с двумя пользователями:
// alice (role admin, пароль secret) и bobby (role user, пароль secret).
func testStorage(t *testing.T) users.UserStorage {
	t.Helper()
	hash, err := pkg.HashPassword("secret", 4)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	storage := users.NewUsersCache(&users.UserStorageConfig{Logger: nil})
	storage.LoadUsers(context.Background(), []domain.User{
		{ID: 1, Username: "alice", Email: "alice@t.ru", FirstName: "Alice", HashedPassword: hash, Role: "admin"},
		{ID: 2, Username: "bobby", Email: "bobby@t.ru", FirstName: "Bobby", HashedPassword: hash, Role: "user"},
	})
	return *storage
}

// newTestGateway собирает гейт с бекендом и двумя маршрутами:
// /api (jwt, admin), /public (none), /basic (basic, admin), /basic-user (basic, user)
func newTestGateway(t *testing.T) (*AuthProxy, *tokens.JWTModule) {
	t.Helper()
	backend := backendStub(t)
	storage := testStorage(t)

	cfg := &config.Config{
		Auth: config.AuthConfig{BaseURL: "http://auth.local"},
		JWT: config.JWTConfig{
			AccessCookieKey:  "access_token",
			RefreshCookieKey: "refresh_token",
			AccessSecret:     testSecret,
			RefreshSecret:    testSecret,
			AccessTTL:        15 * time.Minute,
			RefreshTTL:       24 * time.Hour,
		},
		Roles: []string{"user", "admin", "superadmin"},
		Routes: []config.RouteConfig{
			{Prefix: "/api", Target: backend.URL, AuthMethod: config.AuthJWT, RequiredRoles: []string{"admin"}},
			{Prefix: "/public", Target: backend.URL, AuthMethod: config.AuthNone},
			{Prefix: "/basic", Target: backend.URL, AuthMethod: config.AuthBasic, RequiredRoles: []string{"admin"}},
			{Prefix: "/basic-user", Target: backend.URL, AuthMethod: config.AuthBasic, RequiredRoles: []string{"user"}},
		},
	}

	jwt := tokens.NewJWTService(tokens.Config{
		SecretKey:       testSecret,
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
	}, storage)

	h, err := NewHandlers(&Options{Config: cfg, JWT: jwt, Users: storage})
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	return h, jwt
}

// expiredJWT - тот же секрет, но negative TTL: токены сразу просроченные
func expiredJWT() *tokens.JWTModule {
	return tokens.NewJWTService(tokens.Config{
		SecretKey:       testSecret,
		AccessTokenTTL:  -1 * time.Second,
		RefreshTokenTTL: -1 * time.Second,
	}, users.UserStorage{})
}

// nextFromLocation достаёт параметр next из Location после редиректа
func nextFromLocation(t *testing.T, rec *httptest.ResponseRecorder) (string, string, string) {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location %q: %v", loc, err)
	}
	return u.Host, u.Path, u.Query().Get("next")
}

func TestAuthorize_NoCookies_RedirectsToLogin(t *testing.T) {
	h, _ := newTestGateway(t)

	req := httptest.NewRequest(http.MethodGet, "/api/users?page=2", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	host, path, next := nextFromLocation(t, rec)
	if host != "auth.local" || path != "/login" {
		t.Errorf("got %s%s, want http://auth.local/login", host, path)
	}
	if next != "/api/users?page=2" {
		t.Errorf("next: got %q, want preserved original path", next)
	}
}

func TestAuthorize_OnlyRefreshCookie_RedirectsToRefresh(t *testing.T) {
	h, _ := newTestGateway(t)

	// refresh-кука есть, access - нет
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "whatever"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	host, path, next := nextFromLocation(t, rec)
	if host != "auth.local" || path != "/refresh" {
		t.Errorf("got %s%s, want http://auth.local/refresh", host, path)
	}
	if next != "/api/users" {
		t.Errorf("next: got %q, want /api/users", next)
	}
}

func TestAuthorize_ValidTokenAndRole_Proxies(t *testing.T) {
	h, jwt := newTestGateway(t)

	access, _, _ := jwt.GenerateBothTokens(1, "admin", "admin@t.ru", "admin")
	req := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: access})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected proxied 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "backend:/api/orders" {
		t.Errorf("backend body: got %q, want forwarded path", rec.Body.String())
	}
}

func TestAuthorize_ValidTokenLowRole_Forbidden(t *testing.T) {
	h, jwt := newTestGateway(t)

	// роль user, а маршрут открыт только admin
	access, _, _ := jwt.GenerateBothTokens(2, "user", "user@t.ru", "user")
	req := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: access})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for low role, got %d", rec.Code)
	}
}

func TestAuthorize_ExpiredAccessAndRefresh_RedirectsToRefresh(t *testing.T) {
	h, _ := newTestGateway(t)

	access, _, _ := expiredJWT().GenerateBothTokens(1, "admin", "admin@t.ru", "admin")
	req := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: access})
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "refresh"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	_, path, _ := nextFromLocation(t, rec)
	if path != "/refresh" {
		t.Errorf("got path %q, want /refresh (access expired, refresh present)", path)
	}
}

func TestAuthorize_ExpiredAccessNoRefresh_RedirectsToLogin(t *testing.T) {
	h, _ := newTestGateway(t)

	access, _, _ := expiredJWT().GenerateBothTokens(1, "admin", "admin@t.ru", "admin")
	req := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: access})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	_, path, _ := nextFromLocation(t, rec)
	if path != "/login" {
		t.Errorf("got path %q, want /login (expired access, no refresh)", path)
	}
}

func TestAuthorize_TamperedAccess_RedirectsToLogin(t *testing.T) {
	h, jwt := newTestGateway(t)

	access, _, _ := jwt.GenerateBothTokens(1, "admin", "admin@t.ru", "admin")
	// портим подпись: меняем первый символ сигнатуры
	parts := strings.Split(access, ".")
	sig := parts[2]
	if sig[0] == 'A' {
		parts[2] = "B" + sig[1:]
	} else {
		parts[2] = "A" + sig[1:]
	}
	tampered := strings.Join(parts, ".")

	req := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: tampered})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	_, path, _ := nextFromLocation(t, rec)
	// подменённый токен не "протух", а подделан - обновлять нечего, на логин
	if path != "/login" {
		t.Errorf("got path %q, want /login for tampered token", path)
	}
}

func TestPublicRoute_NoAuth(t *testing.T) {
	h, _ := newTestGateway(t)

	// без единой куки, маршрут auth_method: none - открыт
	req := httptest.NewRequest(http.MethodGet, "/public", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on public route, got %d", rec.Code)
	}
	if rec.Body.String() != "backend:/public" {
		t.Errorf("backend body: got %q", rec.Body.String())
	}
}

func TestAuthorizeBasic_NoCreds_401WithWWWAuthenticate(t *testing.T) {
	h, _ := newTestGateway(t)

	req := httptest.NewRequest(http.MethodGet, "/basic", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Basic realm="AUTH-PROXY"` {
		t.Errorf("WWW-Authenticate: got %q", got)
	}
}

func TestAuthorizeBasic_WrongPassword_401(t *testing.T) {
	h, _ := newTestGateway(t)

	req := httptest.NewRequest(http.MethodGet, "/basic", nil)
	req.SetBasicAuth("alice", "wrong")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Basic realm="AUTH-PROXY"` {
		t.Errorf("WWW-Authenticate: got %q", got)
	}
}

func TestAuthorizeBasic_ValidCredsAndRole_Proxies(t *testing.T) {
	h, _ := newTestGateway(t)

	// alice - admin, маршрут /basic требует admin
	req := httptest.NewRequest(http.MethodGet, "/basic/data", nil)
	req.SetBasicAuth("alice", "secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "backend:/basic/data" {
		t.Errorf("backend body: got %q", rec.Body.String())
	}
}

func TestAuthorizeBasic_ValidCredsLowRole_403(t *testing.T) {
	h, _ := newTestGateway(t)

	// bobby - user, а маршрут /basic требует admin -> 403
	req := httptest.NewRequest(http.MethodGet, "/basic", nil)
	req.SetBasicAuth("bobby", "secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for low role, got %d", rec.Code)
	}
}

func TestAuthorizeBasic_UserRoleRoute_Proxies(t *testing.T) {
	h, _ := newTestGateway(t)

	// маршрут /basic-user открыт роли user - bobby проходит
	req := httptest.NewRequest(http.MethodGet, "/basic-user/x", nil)
	req.SetBasicAuth("bobby", "secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "backend:/basic-user/x" {
		t.Errorf("backend body: got %q", rec.Body.String())
	}
}
