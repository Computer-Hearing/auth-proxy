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

func TestBuild_InvalidRoute(t *testing.T) {
	_, err := Build(&config.Routes{
		Roles:  []string{"root"},
		Routes: []config.RouteConfig{{Prefix: "api", Target: "http://x"}},
	}, stubBuild)
	if err == nil {
		t.Fatal("expected error for invalid prefix")
	}
}
