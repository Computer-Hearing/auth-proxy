package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

var testRoles = []string{"user", "admin", "superadmin"}

// prepare - то, что Load делает после validator: проверки + дефолты
func prepare(cfg *Config) error {
	if err := validate(cfg); err != nil {
		return err
	}
	normalize(cfg)
	return nil
}

func routeByPrefix(routes []RouteConfig, prefix string) *RouteConfig {
	for i := range routes {
		if routes[i].Prefix == prefix {
			return &routes[i]
		}
	}
	return nil
}

// writeConfig пишет YAML во временный файл и настраивает обязательные ENV
func writeConfig(t *testing.T, yamlContent string) {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	t.Setenv("YAML_CONFIG_PATH", configPath)
	t.Setenv("SESSION_ACCESS_SECRET", "supersecret-access-key-32-chars-min")
	t.Setenv("SESSION_REFRESH_SECRET", "supersecret-refresh-key-32-chars-min")
}

// unsetEnv убирает переменную на время теста
func unsetEnv(t *testing.T, key string) {
	t.Helper()
	if prev, ok := os.LookupEnv(key); ok {
		t.Setenv(key, prev) // восстановит значение после теста
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset %s: %v", key, err)
		}
	}
}

func TestNormalize_RoleLadder(t *testing.T) {
	cfg := &Config{
		Access: AccessConfig{Roles: testRoles},
		Gateway: GatewayConfig{Routes: []RouteConfig{
			{Prefix: "/a", Target: "http://x", RequiredRoles: []string{"admin"}},
			{Prefix: "/b", Target: "http://x", RequiredRoles: []string{"superadmin"}},
			{Prefix: "/c", Target: "http://x"},
			{Prefix: "/d", Target: "http://x", AuthMethod: AuthNone},
			{Prefix: "/e", Target: "http://x", AuthMethod: AuthNone, RequiredRoles: []string{"admin"}},
		}},
	}

	if err := prepare(cfg); err != nil {
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
		route := routeByPrefix(cfg.Gateway.Routes, tc.prefix)
		if route == nil {
			t.Fatalf("route %s not found", tc.prefix)
		}
		if !slices.Equal(route.RequiredRoles, tc.want) {
			t.Errorf("route %s: got %v, want %v", tc.prefix, route.RequiredRoles, tc.want)
		}
	}

	// auth_method не указан -> по умолчанию jwt
	if got := routeByPrefix(cfg.Gateway.Routes, "/c").AuthMethod; got != AuthJWT {
		t.Errorf("route /c: default auth_method = %q, want %q", got, AuthJWT)
	}
	// none-маршрут остаётся none
	if got := routeByPrefix(cfg.Gateway.Routes, "/d").AuthMethod; got != AuthNone {
		t.Errorf("route /d: auth_method = %q, want %q", got, AuthNone)
	}
}

func TestValidate_UnknownRole(t *testing.T) {
	cfg := &Config{
		Access: AccessConfig{Roles: testRoles},
		Gateway: GatewayConfig{Routes: []RouteConfig{
			{Prefix: "/a", Target: "http://x", RequiredRoles: []string{"ghost"}},
		}},
	}

	if err := validate(cfg); err == nil {
		t.Fatal("expected error for unknown role, got nil")
	}
}

func TestLoad_YAMLOverridesRoles(t *testing.T) {
	writeConfig(t, `
auth:
  port: 8081
  base_url: "http://localhost:8081"

access:
  roles:
    - "guest"
    - "member"
    - "owner"
    - "root"

gateway:
  routes:
    - prefix: "/api"
      target: "http://backend:8080"
      auth_method: none
`)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantRoles := []string{"guest", "member", "owner", "root"}
	if !slices.Equal(cfg.Access.Roles, wantRoles) {
		t.Errorf("roles: got %v, want %v (YAML should override ENV defaults)", cfg.Access.Roles, wantRoles)
	}
}

func TestLoad_RolesEnvDefaultWhenNotInYAML(t *testing.T) {
	unsetEnv(t, "ACCESS_ROLES")
	writeConfig(t, `
auth:
  port: 8081
  base_url: "http://localhost:8081"

gateway:
  routes:
    - prefix: "/api"
      target: "http://backend:8080"
      auth_method: none
`)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(cfg.Access.Roles, testRoles) {
		t.Errorf("roles: got %v, want default %v", cfg.Access.Roles, testRoles)
	}
}

func TestLoad_MissingAuthBaseURL(t *testing.T) {
	// добиваемся, чтобы AUTH_BASE_URL пришёл пустым из окружения
	unsetEnv(t, "AUTH_BASE_URL")
	writeConfig(t, `
gateway:
  routes:
    - prefix: "/api"
      target: "http://backend:8080"
      auth_method: none
`)

	if _, err := Load(); err == nil {
		t.Fatal("expected error when Auth.BaseURL is missing, got nil")
	}
}

func TestLoad_Defaults(t *testing.T) {
	// добиваемся, чтобы переменные не были заданы (проверяем envDefault)
	for _, key := range []string{"GATEWAY_BASE_URL", "GATEWAY_PORT", "AUTH_PORT", "AUTH_READ_TIMEOUT", "ENV"} {
		unsetEnv(t, key)
	}
	writeConfig(t, `
auth:
  base_url: "http://localhost:8081"
  write_timeout: 30s

gateway:
  routes:
    - prefix: "/api"
      target: "http://backend:8080"
      auth_method: none
`)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Gateway.BaseURL != "http://localhost:5000" {
		t.Errorf("Gateway.BaseURL: got %q, want default http://localhost:5000", cfg.Gateway.BaseURL)
	}
	if cfg.Gateway.Port != 5000 || cfg.Auth.Port != 6000 {
		t.Errorf("ports: got gateway %d, auth %d, want 5000/6000", cfg.Gateway.Port, cfg.Auth.Port)
	}
	if got := cfg.Auth.Timeouts.ReadTimeout.String(); got != "5s" {
		t.Errorf("Auth.ReadTimeout: got %s, want default 5s", got)
	}
	// write_timeout из YAML (inline в секции auth) перекрывает дефолт
	if got := cfg.Auth.Timeouts.WriteTimeout.String(); got != "30s" {
		t.Errorf("Auth.WriteTimeout: got %s, want 30s from YAML", got)
	}
	if cfg.Session.Cookie.Secure {
		t.Error("Cookie.Secure should be false outside production")
	}
}

func TestNormalize_CookieSecureInProduction(t *testing.T) {
	cfg := &Config{
		ENV:     "production",
		Access:  AccessConfig{Roles: testRoles},
		Gateway: GatewayConfig{Routes: []RouteConfig{{Prefix: "/a", Target: "http://x"}}},
	}
	if err := prepare(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Session.Cookie.Secure {
		t.Error("Cookie.Secure should be true in production")
	}
}

func TestValidate_DuplicatePrefix(t *testing.T) {
	cfg := &Config{
		Access: AccessConfig{Roles: testRoles},
		Gateway: GatewayConfig{Routes: []RouteConfig{
			{Prefix: "/a", Target: "http://x", RequiredRoles: []string{"admin"}},
			{Prefix: "/a", Target: "http://y", RequiredRoles: []string{"admin"}},
		}},
	}

	if err := validate(cfg); err == nil {
		t.Fatal("expected error for duplicate prefix, got nil")
	}
}

func TestValidate_UserRoleNotInList(t *testing.T) {
	cfg := &Config{
		Access: AccessConfig{
			Roles: testRoles,
			Users: []User{{ID: 1, Login: "alice", Password: "secret", Role: "ghost"}},
		},
		Gateway: GatewayConfig{Routes: []RouteConfig{{Prefix: "/a", Target: "http://x", AuthMethod: AuthNone}}},
	}

	if err := validate(cfg); err == nil {
		t.Fatal("expected error for unknown user role, got nil")
	}
}

func TestNormalize_KeepsUsersAsIs(t *testing.T) {
	cfg := &Config{
		Access: AccessConfig{
			Roles: testRoles,
			Users: []User{{ID: 1, Login: "alice", Password: "secret", Role: "superadmin"}},
		},
		Gateway: GatewayConfig{Routes: []RouteConfig{{Prefix: "/a", Target: "http://x", AuthMethod: AuthNone}}},
	}

	if err := prepare(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Access.Users) != 1 {
		t.Fatalf("expected exactly 1 user, got %d", len(cfg.Access.Users))
	}
	// хеширование - забота users.FromConfig, конфиг хранит пароль как есть
	if cfg.Access.Users[0].Password != "secret" {
		t.Errorf("password: got %q, want plain %q", cfg.Access.Users[0].Password, "secret")
	}
}

func TestNormalize_AutoSuperAdmin(t *testing.T) {
	cfg := &Config{
		Access: AccessConfig{
			Roles: testRoles,
			Users: []User{{ID: 5, Login: "alice", Password: "secret", Role: "user"}},
		},
		Gateway: GatewayConfig{Routes: []RouteConfig{{Prefix: "/a", Target: "http://x", AuthMethod: AuthNone}}},
	}

	if err := prepare(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Access.Users) != 2 {
		t.Fatalf("expected 2 users (user + auto superadmin), got %d", len(cfg.Access.Users))
	}

	sa := cfg.Access.Users[1]
	if sa.Login != "superadmin" {
		t.Errorf("login: got %q, want %q", sa.Login, "superadmin")
	}
	if sa.Role != "superadmin" {
		t.Errorf("role: got %q, want top role %q", sa.Role, "superadmin")
	}
	if sa.ID != 6 {
		t.Errorf("id: got %d, want max+1 = 6", sa.ID)
	}
	if sa.Password != "superadmin" {
		t.Errorf("auto superadmin password: got %q, want %q", sa.Password, "superadmin")
	}
}

func TestNormalize_NoUsers_AutoSuperAdmin(t *testing.T) {
	cfg := &Config{
		Access:  AccessConfig{Roles: testRoles},
		Gateway: GatewayConfig{Routes: []RouteConfig{{Prefix: "/a", Target: "http://x", AuthMethod: AuthNone}}},
	}

	if err := prepare(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Access.Users) != 1 {
		t.Fatalf("expected auto superadmin, got %d users", len(cfg.Access.Users))
	}
}

func TestValidate_DuplicatePrefixWithSameHost(t *testing.T) {
	cfg := &Config{
		Access: AccessConfig{Roles: testRoles},
		Gateway: GatewayConfig{Routes: []RouteConfig{
			{Prefix: "/api", Host: "api.example.com", Target: "http://x", AuthMethod: AuthNone},
			{Prefix: "/api", Host: "api.example.com", Target: "http://y", AuthMethod: AuthNone},
		}},
	}

	if err := validate(cfg); err == nil {
		t.Fatal("expected error for duplicate prefix with same host, got nil")
	}
}

func TestValidate_SamePrefixDifferentHosts(t *testing.T) {
	cfg := &Config{
		Access: AccessConfig{Roles: testRoles},
		Gateway: GatewayConfig{Routes: []RouteConfig{
			{Prefix: "/api", Host: "api.example.com", Target: "http://x", AuthMethod: AuthNone},
			{Prefix: "/api", Host: "analytics.example.com", Target: "http://y", AuthMethod: AuthNone},
			{Prefix: "/api", Target: "http://z", AuthMethod: AuthNone},
		}},
	}

	if err := validate(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_InvalidWildcardPrefix(t *testing.T) {
	cfg := &Config{
		Access: AccessConfig{Roles: testRoles},
		Gateway: GatewayConfig{Routes: []RouteConfig{
			{Prefix: "api/*", Target: "http://x", AuthMethod: AuthNone},
		}},
	}

	if err := validate(cfg); err == nil {
		t.Fatal("expected error for prefix without leading slash, got nil")
	}
}
