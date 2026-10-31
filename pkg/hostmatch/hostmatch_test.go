package hostmatch

import "testing"

func TestMatch_Wildcard(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		want    bool
	}{
		{"*.example.com", "grafana.example.com", true},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "example.com", false},
		{"*.test.example.com", "grafana.test.example.com", true},
		{"*.test.example.com", "a.b.test.example.com", false},
		{"api.example.com", "api.example.com", true},
		{"api.example.com", "other.example.com", false},
		{"", "anything.com", false},
	}

	for _, tc := range cases {
		if got := Match(tc.pattern, tc.host); got != tc.want {
			t.Errorf("Match(%q, %q) = %v, want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"Grafana.Example.com:443": "grafana.example.com",
		"localhost:5000":          "localhost",
		"example.com":             "example.com",
		"[::1]:8080":              "::1",
		"[::1]":                   "::1",
		"":                        "",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"App.Example.com.":    "app.example.com",
		"APP.EXAMPLE.COM:443": "app.example.com",
		"example.com":         "example.com",
		"":                    "",
	}
	for in, want := range cases {
		if got := NormalizeDomain(in); got != want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSet_Contains(t *testing.T) {
	s := NewSet("gw.example.com", "*.Apps.example.com", "", "localhost")

	cases := []struct {
		host string
		want bool
	}{
		{"gw.example.com", true},
		{"GW.example.com:443", true},
		{"grafana.apps.example.com", true},
		{"a.b.apps.example.com", false},
		{"apps.example.com", false},
		{"localhost:5000", true},
		{"evil.com", false},
		{"gw.example.com.evil.com", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := s.Contains(tc.host); got != tc.want {
			t.Errorf("Contains(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}
