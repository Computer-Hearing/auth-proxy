package auth

import (
	"auth-proxy/internal/config"
	"auth-proxy/internal/tokens"
	"auth-proxy/internal/users"
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
		Cookie:     config.CookieConfig{AccessName: "access_token", RefreshName: "refresh_token"},
		GatewayURL: "http://gw.local",
		Tokens:     tokens.New(tokens.Config{SecretKey: "test-secret"}),
		Users:      storage,
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
