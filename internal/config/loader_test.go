package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestValidateRoutes_RoleLadder(t *testing.T) {
	cfg := &Config{
		Roles: []string{"user", "admin", "superadmin"},
		Routes: []RouteConfig{
			{Prefix: "/a", Target: "http://x", RequiredRoles: []string{"admin"}},
			{Prefix: "/b", Target: "http://x", RequiredRoles: []string{"superadmin"}},
			{Prefix: "/c", Target: "http://x"},
			{Prefix: "/d", Target: "http://x", SkipAuth: true},
			{Prefix: "/e", Target: "http://x", SkipAuth: true, RequiredRoles: []string{"admin"}},
		},
	}

	if err := validateRoutes(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cases := []struct {
		prefix string
		want   []string
	}{
		{"/a", []string{"admin", "superadmin"}},
		{"/b", []string{"superadmin"}},
		{"/c", []string{"user", "admin", "superadmin"}},
		{"/d", nil},
		{"/e", []string{"admin"}},
	}

	for _, tc := range cases {
		route := cfg.GetRouteByPrefix(tc.prefix)
		if route == nil {
			t.Fatalf("route %s not found", tc.prefix)
		}
		if !slices.Equal(route.RequiredRoles, tc.want) {
			t.Errorf("route %s: got %v, want %v", tc.prefix, route.RequiredRoles, tc.want)
		}
	}
}

func TestValidateRoutes_UnknownRole(t *testing.T) {
	cfg := &Config{
		Roles: []string{"user", "admin", "superadmin"},
		Routes: []RouteConfig{
			{Prefix: "/a", Target: "http://x", RequiredRoles: []string{"ghost"}},
		},
	}

	if err := validateRoutes(cfg); err == nil {
		t.Fatal("expected error for unknown role, got nil")
	}
}

func TestLoad_YAMLPopulatesRolesAndBlacklist(t *testing.T) {
	yamlContent := `
roles:
  - "guest"
  - "member"
  - "owner"
  - "root"

routes:
  - prefix: "/api"
    target: "http://backend:8080"
    skip_auth: true

blacklist:
  - "10.0.0.0/8"
  - "192.168.1.1"
`
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	t.Setenv("YAML_CONFIG_PATH", configPath)
	t.Setenv("JWT_ACCESS_SECRET", "supersecret-access-key-32-chars-min")
	t.Setenv("JWT_REFRESH_SECRET", "supersecret-refresh-key-32-chars-min")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantRoles := []string{"guest", "member", "owner", "root"}
	if !slices.Equal(cfg.Roles, wantRoles) {
		t.Errorf("roles: got %v, want %v (YAML should override ENV defaults)", cfg.Roles, wantRoles)
	}

	wantBlacklist := []string{"10.0.0.0/8", "192.168.1.1"}
	if !slices.Equal(cfg.Blacklist, wantBlacklist) {
		t.Errorf("blacklist: got %v, want %v (should be populated from YAML)", cfg.Blacklist, wantBlacklist)
	}
}

func TestLoad_RolesEnvDefaultWhenNotInYAML(t *testing.T) {
	if prev, ok := os.LookupEnv("ROLES"); ok {
		os.Unsetenv("ROLES")
		t.Cleanup(func() { os.Setenv("ROLES", prev) })
	}

	yamlContent := `
routes:
  - prefix: "/api"
    target: "http://backend:8080"
    skip_auth: true
`
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	t.Setenv("YAML_CONFIG_PATH", configPath)
	t.Setenv("JWT_ACCESS_SECRET", "supersecret-access-key-32-chars-min")
	t.Setenv("JWT_REFRESH_SECRET", "supersecret-refresh-key-32-chars-min")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantRoles := []string{"user", "admin", "superadmin"}
	if !slices.Equal(cfg.Roles, wantRoles) {
		t.Errorf("roles: got %v, want default %v", cfg.Roles, wantRoles)
	}
}

func TestValidateRoutes_DuplicatePrefix(t *testing.T) {
	cfg := &Config{
		Roles: []string{"user", "admin", "superadmin"},
		Routes: []RouteConfig{
			{Prefix: "/a", Target: "http://x", RequiredRoles: []string{"admin"}},
			{Prefix: "/a", Target: "http://y", RequiredRoles: []string{"admin"}},
		},
	}

	if err := validateRoutes(cfg); err == nil {
		t.Fatal("expected error for duplicate prefix, got nil")
	}
}
