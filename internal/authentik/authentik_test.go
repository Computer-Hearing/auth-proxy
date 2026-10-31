package authentik

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestParseGroups(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
	}{
		{"", nil},
		{"foo", []string{"foo"}},
		{"foo|bar|baz", []string{"foo", "bar", "baz"}},
		{" foo | bar ", []string{"foo", "bar"}},
		{"foo||bar", []string{"foo", "bar"}},
	}
	for _, tc := range cases {
		if got := ParseGroups(tc.raw); !slices.Equal(got, tc.want) {
			t.Errorf("ParseGroups(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

var roles = []string{"superadmin", "admin", "user"}

func TestUserRank(t *testing.T) {
	cases := []struct {
		groups []string
		want   int
	}{
		{nil, -1},
		{[]string{"ghost"}, -1},
		{[]string{"user"}, 2},
		{[]string{"admin"}, 1},
		{[]string{"superadmin"}, 0},
		{[]string{"user", "admin"}, 1},
		{[]string{"ghost", "superadmin"}, 0},
	}
	for _, tc := range cases {
		if got := UserRank(roles, tc.groups); got != tc.want {
			t.Errorf("UserRank(%v) = %d, want %d", tc.groups, got, tc.want)
		}
	}
}

func TestAllows(t *testing.T) {
	cases := []struct {
		name     string
		groups   []string
		required []string
		want     bool
	}{
		{"no groups", nil, []string{"admin"}, false},
		{"lower", []string{"user"}, []string{"admin"}, false},
		{"exact", []string{"admin"}, []string{"admin"}, true},
		{"higher", []string{"superadmin"}, []string{"admin"}, true},
		{"higher exact", []string{"superadmin"}, []string{"superadmin"}, true},
		{"unknown only", []string{"ghost"}, []string{"admin"}, false},
		{"unknown and allowed", []string{"ghost", "admin"}, []string{"admin"}, true},
		{"multiple required uses lowest", []string{"user"}, []string{"admin", "user"}, true},
	}
	for _, tc := range cases {
		if got := Allows(roles, tc.groups, tc.required); got != tc.want {
			t.Errorf("%s: Allows = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestIsTop(t *testing.T) {
	if !IsTop(roles, []string{"superadmin"}) {
		t.Error("superadmin should be top")
	}
	if IsTop(roles, []string{"admin"}) {
		t.Error("admin should not be top")
	}
	if IsTop(roles, nil) {
		t.Error("no groups should not be top")
	}
}

func TestMiddleware(t *testing.T) {
	var got Identity
	h := Middleware("X-Proxy-Secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = FromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set(HeaderUsername, "alice")
	req.Header.Set(HeaderEmail, "alice@example.com")
	req.Header.Set(HeaderGroups, "admin|user")
	req.Header.Set("X-Proxy-Secret", "s3cret")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: got %d", rec.Code)
	}
	if got.Username != "alice" || got.Email != "alice@example.com" {
		t.Errorf("identity: got %+v", got)
	}
	if !slices.Equal(got.Groups, []string{"admin", "user"}) {
		t.Errorf("groups: got %v", got.Groups)
	}
	if got.Secret != "s3cret" {
		t.Errorf("secret: got %q", got.Secret)
	}
}

func TestWarnUnknownDoesNotPanic(t *testing.T) {
	WarnUnknown(nil, "alice", roles, []string{"ghost"})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	WarnUnknown(logger, "alice", roles, []string{"ghost"})
}
