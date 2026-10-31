package store

import (
	"net/http"
	"slices"
	"testing"

	"auth-proxy/internal/config"
)

func stubBuild(config.RouteConfig) (http.Handler, error) {
	return http.NotFoundHandler(), nil
}

func TestBuildAndSwap(t *testing.T) {
	routes := &config.Routes{
		Roles:  []string{"superadmin", "admin"},
		Routes: []config.RouteConfig{{Prefix: "/api", Target: "http://api:8080"}},
	}

	snap, err := Build(routes, stubBuild)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !slices.Equal(snap.Roles, routes.Roles) {
		t.Errorf("roles: got %v, want %v", snap.Roles, routes.Roles)
	}
	if len(snap.Routes) != 1 || snap.Engine == nil {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}

	st := New(snap)
	if got := st.Load(); got != snap {
		t.Fatal("Load should return initial snapshot")
	}

	next, err := Build(&config.Routes{Roles: []string{"root"}}, stubBuild)
	if err != nil {
		t.Fatalf("Build next: %v", err)
	}
	st.Swap(next)
	if got := st.Load(); got != next {
		t.Fatal("Swap did not replace snapshot")
	}
}

func TestBuild_ExactHosts(t *testing.T) {
	snap, err := Build(&config.Routes{
		Roles: []string{"root"},
		Routes: []config.RouteConfig{
			{Prefix: "/", Host: "app.example.com", Target: "http://a:8080"},
			{Prefix: "/", Host: "APP.Example.com:443", Target: "http://b:8080"},
			{Prefix: "/", Host: "*.example.com", Target: "http://c:8080"},
			{Prefix: "/", Target: "http://d:8080"},
		},
	}, stubBuild)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if _, ok := snap.ExactHosts["app.example.com"]; !ok {
		t.Error("exact host app.example.com missing")
	}
	if _, ok := snap.ExactHosts["grafana.example.com"]; ok {
		t.Error("wildcard subdomain must not be allowed")
	}
	if len(snap.ExactHosts) != 1 {
		t.Errorf("exact hosts: got %v, want only app.example.com", snap.ExactHosts)
	}
}

func TestBuild_InvalidRoute(t *testing.T) {
	_, err := Build(&config.Routes{
		Roles:  []string{"root"},
		Routes: []config.RouteConfig{{Prefix: "api", Target: "http://x"}},
	}, stubBuild)
	if err == nil {
		t.Fatal("expected error for invalid prefix")
	}
}
