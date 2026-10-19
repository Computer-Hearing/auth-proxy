package app

import (
	"auth-proxy/internal/config"
	"testing"
)

func TestRedirectHosts(t *testing.T) {
	cfg := &config.Config{
		Gateway: config.GatewayConfig{
			BaseURL: "https://gw.example.com:8443",
			Routes: []config.RouteConfig{
				{Prefix: "/", Host: "*.apps.example.com"},
				{Prefix: "/api", Host: "api.example.com"},
				{Prefix: "/open"}, // без host - матчит любой Host, в список не попадает
			},
		},
		Auth: config.AuthConfig{AllowedRedirectHosts: []string{"portal.example.org"}},
	}

	hosts := redirectHosts(cfg)
	for _, host := range []string{"gw.example.com", "grafana.apps.example.com", "api.example.com", "portal.example.org"} {
		if !hosts.Contains(host) {
			t.Errorf("%s should be allowed", host)
		}
	}
	for _, host := range []string{"evil.com", "other.example.com", "a.b.apps.example.com"} {
		if hosts.Contains(host) {
			t.Errorf("%s should not be allowed", host)
		}
	}
}
