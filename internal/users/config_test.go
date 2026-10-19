package users

import (
	"auth-proxy/internal/config"
	"auth-proxy/pkg/password"
	"context"
	"testing"
)

func TestFromConfig_HashesPasswordAndBuildsBasicAuth(t *testing.T) {
	users, err := FromConfig(config.AccessConfig{
		BcryptCost: 4,
		Users: []config.User{
			{ID: 1, Login: "alice", Password: "secret", Email: "a@x.io", FullName: "Alice", Role: "admin"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}

	u := users[0]
	if u.Username != "alice" || u.FirstName != "Alice" || u.Role != "admin" || u.ID != 1 {
		t.Errorf("unexpected user fields: %+v", u)
	}
	if u.HashedPassword == "secret" || !password.Check("secret", u.HashedPassword) {
		t.Error("password should be bcrypt-hashed and match original")
	}
	if u.BasicAuth != password.BasicAuthHeader("alice", "secret") {
		t.Errorf("BasicAuth: got %q, want Basic header for alice:secret", u.BasicAuth)
	}
}

func TestStorage_Authenticate(t *testing.T) {
	users, err := FromConfig(config.AccessConfig{
		BcryptCost: 4,
		Users:      []config.User{{ID: 7, Login: "alice", Password: "secret", Role: "user"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := New(nil)
	s.Load(context.Background(), users)

	if _, ok := s.Authenticate(context.Background(), "alice", "secret"); !ok {
		t.Error("expected successful authentication")
	}
	if _, ok := s.Authenticate(context.Background(), "alice", "wrong"); ok {
		t.Error("expected failure on wrong password")
	}
	if u, ok := s.GetByID(context.Background(), 7); !ok || u.Username != "alice" {
		t.Errorf("GetByID: got %+v, %v", u, ok)
	}
}
