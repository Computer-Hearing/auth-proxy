package httpx

import (
	"auth-proxy/pkg/hostmatch"
	"testing"
)

func TestSafeNext_RelativePath(t *testing.T) {
	cases := []struct {
		next string
		want string
	}{
		// корректные внутренние пути - вернутся как есть
		{"/", "/"},
		{"/api/users", "/api/users"},
		{"/api/users?page=2", "/api/users?page=2"},
		{"/a/b:c", "/a/b:c"},                             // ":" во втором сегменте - ок
		{"/static/app.js?x=1:2", "/static/app.js?x=1:2"}, // ":" в query - ок

		// опасные значения - сбрасываются на "/"
		{"", "/"},
		{"api/users", "/"},            // не начинается с "/"
		{"//evil.com", "/"},           // protocol-relative
		{"https://evil.com", "/"},     // абсолютный, а хосты не разрешены
		{"/http://evil.com", "/"},     // ":" в первом сегменте
		{"/javascript:alert(1)", "/"}, // ":" в первом сегменте
		{"/:x", "/"},
	}

	for _, tc := range cases {
		if got := SafeNext(tc.next, nil); got != tc.want {
			t.Errorf("SafeNext(%q): got %q, want %q", tc.next, got, tc.want)
		}
	}
}

func TestSafeNext_AbsoluteURL(t *testing.T) {
	allowed := hostmatch.NewSet("gw.example.com", "*.example.com", "localhost")

	cases := []struct {
		next string
		want string
	}{
		// разрешённые хосты - вернутся (в каноническом виде)
		{"https://grafana.example.com/d/abc?x=1", "https://grafana.example.com/d/abc?x=1"},
		{"https://gw.example.com/", "https://gw.example.com/"},
		{"http://localhost:5000/api", "http://localhost:5000/api"},
		{"https://Grafana.Example.com/x", "https://Grafana.Example.com/x"},

		// всё остальное - "/"
		{"https://evil.com/", "/"},
		{"https://grafana.example.com.evil.com/", "/"}, // суффикс-обман
		{"https://a.b.example.com/", "/"},              // wildcard только на один уровень
		{"https://user@grafana.example.com/", "/"},     // userinfo
		{"https://grafana.example.com@evil.com/", "/"}, // userinfo + чужой хост
		{"javascript://grafana.example.com/%0aalert(1)", "/"},
		{"ftp://grafana.example.com/", "/"},
		{"https:///path", "/"},                          // пустой хост
		{"https://grafana.example.com\\@evil.com", "/"}, // backslash в хосте
	}

	for _, tc := range cases {
		if got := SafeNext(tc.next, allowed.Contains); got != tc.want {
			t.Errorf("SafeNext(%q): got %q, want %q", tc.next, got, tc.want)
		}
	}
}
