package pkg

import "testing"

func TestSafeNext(t *testing.T) {
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
		{"https://evil.com", "/"},     // не начинается с "/"
		{"/http://evil.com", "/"},     // ":" в первом сегменте
		{"/javascript:alert(1)", "/"}, // ":" в первом сегменте
		{"/:x", "/"},
	}

	for _, tc := range cases {
		if got := SafeNext(tc.next); got != tc.want {
			t.Errorf("SafeNext(%q): got %q, want %q", tc.next, got, tc.want)
		}
	}
}
