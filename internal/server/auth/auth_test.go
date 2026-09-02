package auth

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

// healthz должен отвечать 200 без кук и токенов
func TestHealthz(t *testing.T) {
	s, _ := newTestService(t)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Errorf("body: got %q, want status ok", rec.Body.String())
	}
}

// newTestService собирает Service с одним пользователем в хранилище
func newTestService(t *testing.T) (*Service, users.UserStorage) {
	t.Helper()

	passwordHash, err := pkg.HashPassword("secret", 4)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	storage := users.NewUsersCache(&users.UserStorageConfig{Logger: nil})
	storage.LoadUsers(context.Background(), []domain.User{
		{
			ID:             1,
			Username:       "testuser",
			Email:          "test@t.ru",
			FirstName:      "Test",
			HashedPassword: passwordHash,
			Role:           "admin",
		},
	})

	cfg := &config.Config{
		Gateway: config.GatewayConfig{BaseURL: "http://gateway:5000"},
		JWT: config.JWTConfig{
			AccessCookieKey:  "access_token",
			RefreshCookieKey: "refresh_token",
			AccessSecret:     testSecret,
			RefreshSecret:    testSecret,
			AccessTTL:        15 * time.Minute,
			RefreshTTL:       24 * time.Hour,
		},
	}

	jwt := tokens.NewJWTService(tokens.Config{
		SecretKey:       testSecret,
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
	}, *storage)

	svc, err := New(&Options{Config: cfg, JWT: jwt, Users: *storage})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc, *storage
}

// Кука должна нести указанный Domain, чтобы её видели все поддомены.
// net/http в Cookie.Domain отдаёт без ведущей точки - проверяем хвост.
func TestLogin_POST_SetsCookieDomain(t *testing.T) {
	s, _ := newTestService(t)
	s.cfg.JWT.CookieDomain = ".example.com" // включаем домен для кук

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=testuser&password=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	got := rec.Result().Cookies()
	if len(got) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(got))
	}
	for _, c := range got {
		if c.Domain != "example.com" {
			t.Errorf("cookie %q: Domain = %q, want %q (исходно .example.com)", c.Name, c.Domain, "example.com")
		}
	}
}

func doRequest(t *testing.T, s *Service, method, target string, prepare func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	if prepare != nil {
		prepare(req)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestLogin_GET_RendersForm(t *testing.T) {
	s, _ := newTestService(t)
	rec := doRequest(t, s, http.MethodGet, "/login?next=/dashboard", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Вход в систему") {
		t.Error("expected login form in body")
	}
	// next должен попасть в hidden-поле формы (экранированный)
	if !strings.Contains(rec.Body.String(), `value="/dashboard"`) {
		t.Error("expected next in hidden input")
	}
}

func TestLogin_POST_Success_SetsCookiesAndRedirects(t *testing.T) {
	s, _ := newTestService(t)

	req := httptest.NewRequest(http.MethodPost, "/login?next=/dashboard", strings.NewReader("username=testuser&password=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	// возврат на гейт: абсолютный адрес = gateway.base_url + next
	if rec.Header().Get("Location") != "http://gateway:5000/dashboard" {
		t.Errorf("Location: got %q, want http://gateway:5000/dashboard", rec.Header().Get("Location"))
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}
	seen := map[string]bool{}
	for _, c := range cookies {
		seen[c.Name] = true
		if c.Value == "" || !c.HttpOnly {
			t.Errorf("cookie %s: empty value or not HttpOnly", c.Name)
		}
	}
	if !seen["access_token"] || !seen["refresh_token"] {
		t.Errorf("cookies: got %v, want access_token and refresh_token", seen)
	}
}

func TestLogin_POST_OpenRedirectNextBlocked(t *testing.T) {
	s, _ := newTestService(t)

	// попытка подсунуть внешний адрес: SafeNext сбросит его на "/",
	// а host Location при этом всегда gateway.base_url
	req := httptest.NewRequest(http.MethodPost, "/login?next=//evil.com", strings.NewReader("username=testuser&password=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if u.Host != "gateway:5000" {
		t.Errorf("Location host: got %q, want gateway:5000 (only configured host allowed)", u.Host)
	}
	if u.Path != "/" {
		t.Errorf("Location path: got %q, want / (fallback for dangerous next)", u.Path)
	}
}

func TestLogin_POST_WrongPassword_ShowsError(t *testing.T) {
	s, _ := newTestService(t)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=testuser&password=wrong"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with form, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Неверный логин или пароль") {
		t.Error("expected error message on wrong password")
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Error("no cookies should be set on failed login")
	}
}

func TestRefresh_ValidCookie_IssuesNewPair(t *testing.T) {
	s, storage := newTestService(t)

	oldRefresh, _ := tokens.NewJWTService(tokens.Config{SecretKey: testSecret}, storage).GenerateRefreshToken(1)

	rec := doRequest(t, s, http.MethodGet, "/refresh?next=/dashboard", func(req *http.Request) {
		req.AddCookie(&http.Cookie{Name: "refresh_token", Value: oldRefresh})
	})

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if rec.Header().Get("Location") != "http://gateway:5000/dashboard" {
		t.Errorf("Location: got %q, want http://gateway:5000/dashboard", rec.Header().Get("Location"))
	}

	var newRefresh string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "refresh_token" {
			newRefresh = c.Value
		}
	}
	// ротация: refresh-токен должен смениться
	if newRefresh == "" {
		t.Fatal("expected a new refresh cookie")
	}
	if newRefresh == oldRefresh {
		t.Error("refresh token did not rotate")
	}
}

func TestRefresh_MissingCookie_RedirectsToLogin(t *testing.T) {
	s, _ := newTestService(t)
	rec := doRequest(t, s, http.MethodGet, "/refresh?next=/dashboard", nil)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if u.Path != "/login" || u.Query().Get("next") != "/dashboard" {
		t.Errorf("Location: got %q, want /login?next=/dashboard", loc)
	}
}

func TestRefresh_InvalidCookie_ClearsAndSendsToLogin(t *testing.T) {
	s, _ := newTestService(t)
	rec := doRequest(t, s, http.MethodGet, "/refresh", func(req *http.Request) {
		req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "garbage"})
	})

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if u, _ := url.Parse(rec.Header().Get("Location")); u.Path != "/login" {
		t.Errorf("Location: got %q, want /login", rec.Header().Get("Location"))
	}
	// куки должны очищаться (MaxAge < 0)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge > 0 {
			t.Errorf("cookie %s should be cleared, got MaxAge=%d", c.Name, c.MaxAge)
		}
	}
}

func TestLogout_ClearsCookies(t *testing.T) {
	s, _ := newTestService(t)
	rec := doRequest(t, s, http.MethodGet, "/logout?next=/", func(req *http.Request) {
		req.AddCookie(&http.Cookie{Name: "access_token", Value: "a"})
		req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "r"})
	})

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if rec.Header().Get("Location") != "http://gateway:5000/" {
		t.Errorf("Location: got %q, want http://gateway:5000/", rec.Header().Get("Location"))
	}
	if len(rec.Result().Cookies()) != 2 {
		t.Fatalf("expected 2 cleared cookies, got %d", len(rec.Result().Cookies()))
	}
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge > -1 {
			t.Errorf("cookie %s should be cleared (MaxAge=-1), got %d", c.Name, c.MaxAge)
		}
	}
}

func TestMe_NoCookie_Unauthorized(t *testing.T) {
	s, _ := newTestService(t)
	rec := doRequest(t, s, http.MethodGet, "/user/me", nil)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestMe_ValidCookie_ReturnsUser(t *testing.T) {
	s, storage := newTestService(t)

	access, _ := tokens.NewJWTService(tokens.Config{SecretKey: testSecret}, storage).GenerateAccessToken(1, "testuser", "test@t.ru", "admin")

	rec := doRequest(t, s, http.MethodGet, "/user/me", func(req *http.Request) {
		req.AddCookie(&http.Cookie{Name: "access_token", Value: access})
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"username":"testuser"`) {
		t.Errorf("expected user json, got %s", rec.Body.String())
	}
}
