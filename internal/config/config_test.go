package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

var testRoles = []string{"superadmin", "admin", "user"}

func validRoutes() *Routes {
	return &Routes{
		Roles: testRoles,
		Routes: []RouteConfig{
			{Prefix: "/api", Target: "http://api:8080", RequiredGroups: []string{"admin"}},
			{Prefix: "/", Host: "example.com", Target: "http://web:8080"},
		},
	}
}

func TestValidateRoutes_Valid(t *testing.T) {
	if err := ValidateRoutes(validRoutes()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRoutes_EmptyList(t *testing.T) {
	if err := ValidateRoutes(&Routes{Roles: testRoles}); err != nil {
		t.Fatalf("empty routes list should be valid: %v", err)
	}
}

func TestValidateRoutes_NoRoles(t *testing.T) {
	r := validRoutes()
	r.Roles = nil
	if err := ValidateRoutes(r); err == nil {
		t.Fatal("expected error for empty roles")
	}
}

func TestValidateRoutes_DuplicateRoles(t *testing.T) {
	r := validRoutes()
	r.Roles = []string{"admin", "admin"}
	if err := ValidateRoutes(r); err == nil {
		t.Fatal("expected error for duplicate roles")
	}
}

func TestValidateRoutes_UnknownGroup(t *testing.T) {
	r := validRoutes()
	r.Routes[0].RequiredGroups = []string{"ghost"}
	if err := ValidateRoutes(r); err == nil {
		t.Fatal("expected error for unknown group")
	}
}

func TestValidateRoutes_DuplicatePrefixSameHost(t *testing.T) {
	r := validRoutes()
	r.Routes = append(r.Routes, RouteConfig{Prefix: "/api", Target: "http://other:8080"})
	if err := ValidateRoutes(r); err == nil {
		t.Fatal("expected error for duplicate prefix with same host")
	}
}

func TestValidateRoutes_SamePrefixDifferentHosts(t *testing.T) {
	r := &Routes{
		Roles: testRoles,
		Routes: []RouteConfig{
			{Prefix: "/api", Host: "api.example.com", Target: "http://a:8080"},
			{Prefix: "/api", Host: "analytics.example.com", Target: "http://b:8080"},
			{Prefix: "/api", Target: "http://c:8080"},
		},
	}
	if err := ValidateRoutes(r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRoutes_InvalidPrefix(t *testing.T) {
	r := validRoutes()
	r.Routes[0].Prefix = "api/*"
	if err := ValidateRoutes(r); err == nil {
		t.Fatal("expected error for prefix without leading slash")
	}
}

func TestValidateRoutes_ReservedPrefixes(t *testing.T) {
	for _, prefix := range []string{"/_admin", "/_admin/", "/_admin/x", "/config", "/config/", "/conf*"} {
		r := &Routes{
			Roles:  testRoles,
			Routes: []RouteConfig{{Prefix: prefix, Target: "http://x:8080"}},
		}
		if err := ValidateRoutes(r); err == nil {
			t.Errorf("prefix %q: expected reserved-path error", prefix)
		}
	}

	// "/" и "/**" разрешены: reserved проверяется раньше движка.
	for _, prefix := range []string{"/", "/**", "/api", "/_adm"} {
		r := &Routes{
			Roles:  testRoles,
			Routes: []RouteConfig{{Prefix: prefix, Target: "http://x:8080"}},
		}
		if prefix == "/_adm" {
			// "/_adm" пересекается с "/_admin" и должен быть отклонён
			if err := ValidateRoutes(r); err == nil {
				t.Errorf("prefix %q: expected reserved-path error", prefix)
			}
			continue
		}
		if err := ValidateRoutes(r); err != nil {
			t.Errorf("prefix %q: unexpected error: %v", prefix, err)
		}
	}
}

func TestValidateRoutes_WildcardHost(t *testing.T) {
	r := &Routes{
		Roles:  testRoles,
		Routes: []RouteConfig{{Prefix: "/", Host: "*.example.com", Target: "http://x:8080"}},
	}
	if err := ValidateRoutes(r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r.Routes[0].Host = "*example.com"
	if err := ValidateRoutes(r); err == nil {
		t.Fatal("expected error for malformed wildcard host")
	}
}

func TestWriteRoutes_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.yaml")
	want := validRoutes()

	if err := WriteRoutes(path, want); err != nil {
		t.Fatalf("WriteRoutes: %v", err)
	}

	got, err := LoadRoutes(path)
	if err != nil {
		t.Fatalf("LoadRoutes: %v", err)
	}
	if !slices.Equal(got.Roles, want.Roles) {
		t.Errorf("roles: got %v, want %v", got.Roles, want.Roles)
	}
	if len(got.Routes) != len(want.Routes) {
		t.Fatalf("routes: got %d, want %d", len(got.Routes), len(want.Routes))
	}
	if got.Routes[0].Prefix != want.Routes[0].Prefix || got.Routes[0].Target != want.Routes[0].Target {
		t.Errorf("route[0]: got %+v, want %+v", got.Routes[0], want.Routes[0])
	}

	// временных файлов не осталось
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestLoadRoutes_MissingFile(t *testing.T) {
	if _, err := LoadRoutes(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error for missing routes file")
	}
}

func TestLoad_GatewayAndRoutes(t *testing.T) {
	dir := t.TempDir()
	routesPath := filepath.Join(dir, "routes.yaml")
	gatewayPath := filepath.Join(dir, "gateway.yaml")

	if err := WriteRoutes(routesPath, validRoutes()); err != nil {
		t.Fatalf("write routes: %v", err)
	}
	gatewayYAML := `
log_level: debug
shutdown_timeout: 5s
server:
  port: 5100
  read_timeout: 3s
  write_timeout: 4s
admin:
  port: 7100
authentik:
  secret_header: "X-Test-Secret"
  secret: "topsecret"
routes_file: "` + filepath.ToSlash(routesPath) + `"
`
	if err := os.WriteFile(gatewayPath, []byte(gatewayYAML), 0o600); err != nil {
		t.Fatalf("write gateway: %v", err)
	}
	t.Setenv("YAML_CONFIG_PATH", gatewayPath)

	gw, routes, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if gw.Server.Port != 5100 || gw.Admin.Port != 7100 {
		t.Errorf("ports: got server %d admin %d, want 5100/7100", gw.Server.Port, gw.Admin.Port)
	}
	if gw.Server.Timeouts.ReadTimeout.String() != "3s" {
		t.Errorf("read timeout: got %s, want 3s", gw.Server.Timeouts.ReadTimeout)
	}
	if gw.Authentik.SecretHeader != "X-Test-Secret" || gw.Authentik.Secret != "topsecret" {
		t.Errorf("authentik: got %+v", gw.Authentik)
	}
	if filepath.Clean(gw.RoutesFile) != filepath.Clean(routesPath) {
		t.Errorf("routes_file: got %q, want %q", gw.RoutesFile, routesPath)
	}
	if !slices.Equal(routes.Roles, testRoles) {
		t.Errorf("roles: got %v, want %v", routes.Roles, testRoles)
	}
}

func TestLoad_MissingGateway(t *testing.T) {
	t.Setenv("YAML_CONFIG_PATH", filepath.Join(t.TempDir(), "nope.yaml"))
	if _, _, err := Load(); err == nil {
		t.Fatal("expected error for missing gateway config")
	}
}
