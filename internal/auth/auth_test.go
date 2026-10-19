package auth

import (
	"auth-proxy/internal/config"
	"auth-proxy/internal/tokens"
	"auth-proxy/internal/users"
	"auth-proxy/pkg/hostmatch"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newService(t *testing.T) *Service {
	t.Helper()
	list, err := users.FromConfig(config.AccessConfig{
		BcryptCost: 4,
		Users:      []config.User{{ID: 1, Login: "alice", Password: "secret", Role: "user"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	storage := users.New(nil)
	storage.Load(context.Background(), list)

	s, err := New(&Options{
		Cookie:        config.CookieConfig{AccessName: "access_token", RefreshName: "refresh_token"},
		GatewayURL:    "http://gw.local",
		RedirectHosts: hostmatch.NewSet("gw.local", "*.example.com"),
		Tokens:        tokens.New(tokens.Config{SecretKey: "test-secret"}),
		Users:         storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func cookieValue(rec *httptest.ResponseRecorder, name string) string {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func TestLoginAndRefresh(t *testing.T) {
	h := newService(t).Handler()

	// логин: ставим обе куки и возвращаем на гейт по next
	form := url.Values{"username": {"alice"}, "password": {"secret"}, "next": {"/app"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "http://gw.local/app" {
		t.Fatalf("login: got %d Location %q", rec.Code, rec.Header().Get("Location"))
	}
	refresh := cookieValue(rec, "refresh_token")
	if refresh == "" || cookieValue(rec, "access_token") == "" {
		t.Fatal("login: expected both auth cookies")
	}

	// refresh: по refresh-куке выдаём новую пару и возвращаем на гейт
	req = httptest.NewRequest(http.MethodGet, "/refresh?next=/app", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refresh})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "http://gw.local/app" {
		t.Fatalf("refresh: got %d Location %q", rec.Code, rec.Header().Get("Location"))
	}
	if cookieValue(rec, "access_token") == "" {
		t.Error("refresh: expected new access cookie")
	}
}

func TestRefresh_InvalidTokenRedirectsToLogin(t *testing.T) {
	h := newService(t).Handler()

	req := httptest.NewRequest(http.MethodGet, "/refresh?next=/app", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "garbage"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "/login?next=") {
		t.Errorf("got %d Location %q, want redirect to /login", rec.Code, rec.Header().Get("Location"))
	}
}

func login(h http.Handler, next string) *httptest.ResponseRecorder {
	form := url.Values{"username": {"alice"}, "password": {"secret"}, "next": {next}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// После логина возвращаем на тот домен, с которого пришли, если он разрешён
func TestLogin_RedirectsBackToOriginHost(t *testing.T) {
	h := newService(t).Handler()

	cases := []struct {
		next string
		want string
	}{
		{"https://grafana.example.com/d/abc?x=1", "https://grafana.example.com/d/abc?x=1"},
		{"http://gw.local/app", "http://gw.local/app"},
		{"/app", "http://gw.local/app"},                  // относительный - на gateway.base_url
		{"https://evil.com/steal", "http://gw.local/"},   // чужой хост
		{"https://a.b.example.com/", "http://gw.local/"}, // wildcard только на уровень
		{"https://u@grafana.example.com/", "http://gw.local/"},
	}

	for _, tc := range cases {
		rec := login(h, tc.next)
		if got := rec.Header().Get("Location"); rec.Code != http.StatusFound || got != tc.want {
			t.Errorf("next %q: got %d Location %q, want %q", tc.next, rec.Code, got, tc.want)
		}
	}
}

func TestRefresh_RedirectsBackToOriginHost(t *testing.T) {
	h := newService(t).Handler()
	refresh := cookieValue(login(h, "/"), "refresh_token")

	next := "https://grafana.example.com/d/abc"
	req := httptest.NewRequest(http.MethodGet, "/refresh?next="+url.QueryEscape(next), nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refresh})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Location"); rec.Code != http.StatusFound || got != next {
		t.Errorf("got %d Location %q, want %q", rec.Code, got, next)
	}
}

// Без refresh-куки уходим на логин, а исходный адрес не теряем
func TestRefresh_NoCookieKeepsNextForLogin(t *testing.T) {
	h := newService(t).Handler()

	next := "https://grafana.example.com/d/abc"
	req := httptest.NewRequest(http.MethodGet, "/refresh?next="+url.QueryEscape(next), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	want := "/login?next=" + url.QueryEscape(next)
	if got := rec.Header().Get("Location"); got != want {
		t.Errorf("Location got %q, want %q", got, want)
	}
}
