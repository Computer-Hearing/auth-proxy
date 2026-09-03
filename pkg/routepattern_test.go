package pkg

import "testing"

func TestRoutePattern_Match(t *testing.T) {
	cases := []struct {
		prefix string
		path   string
		want   bool
	}{
		{"/static/**", "/static/a/b", true},
		{"/static/**", "/static/", true},
		{"/static/**", "/static", false},
		{"/api/*/v1", "/api/x/v1/anything", true},
		{"/api/*/v1", "/api/x/v2", false},
		{"/api/*/v1", "/api/v1", false},
		{"/*.js", "/app.js", true},
		{"/*.js", "/static/app.js", false},
		{"/api/users", "/api/users/delete", true},
		{"/api/users", "/api/usersx", true},
		{"/a", "/a", true},
		{"/a", "/b", false},
		{"/**/*.js", "/assets/js/vendor/jquery.min.js", true},
		{"/grafana/**", "/grafana/api/search?query=test", true},
	}

	for _, tc := range cases {
		p, err := ParseRoutePattern(tc.prefix)
		if err != nil {
			t.Errorf("ParseRoutePattern(%q): %v", tc.prefix, err)
			continue
		}
		if got := p.Match(tc.path); got != tc.want {
			t.Errorf("pattern %q match %q: got %v, want %v", tc.prefix, tc.path, got, tc.want)
		}
	}
}

func TestParseRoutePattern_Errors(t *testing.T) {
	for _, prefix := range []string{"", "api/*"} {
		if _, err := ParseRoutePattern(prefix); err == nil {
			t.Errorf("expected error for prefix %q", prefix)
		}
	}
}

func TestRoutePattern_MoreSpecific(t *testing.T) {
	orders := mustPattern(t, "/api/orders")       // head 11, pattern 11
	wild := mustPattern(t, "/api/*")              // head 5
	ordersSub := mustPattern(t, "/api/orders/**") // head 12

	if !orders.MoreSpecific(wild) {
		t.Error("literal /api/orders should beat /api/*")
	}
	if wild.MoreSpecific(orders) {
		t.Error("/api/* should not beat literal /api/orders")
	}
	if !ordersSub.MoreSpecific(orders) {
		t.Error("/api/orders/** should beat /api/orders (longer head)")
	}
	if orders.MoreSpecific(orders) {
		t.Error("pattern should not be more specific than itself")
	}
}

func TestCachedRoutePattern_ReturnsSameInstance(t *testing.T) {
	a, err := CachedRoutePattern("/api/*")
	if err != nil {
		t.Fatalf("CachedRoutePattern: %v", err)
	}
	b, err := CachedRoutePattern("/api/*")
	if err != nil {
		t.Fatalf("CachedRoutePattern: %v", err)
	}
	if a != b {
		t.Error("CachedRoutePattern should return the same instance")
	}
}

func mustPattern(t *testing.T, prefix string) *RoutePattern {
	t.Helper()
	p, err := ParseRoutePattern(prefix)
	if err != nil {
		t.Fatalf("ParseRoutePattern(%q): %v", prefix, err)
	}
	return p
}
