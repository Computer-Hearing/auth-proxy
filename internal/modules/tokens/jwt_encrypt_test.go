package tokens

import (
	"testing"
	"time"
)

func TestJWTService(t *testing.T) {
	config := Config{
		SecretKey:       "test-secret",
		AccessTokenTTL:  5 * time.Minute,
		RefreshTokenTTL: 1 * time.Hour,
	}
	service := NewJWTService(config)

	// Тест генерации
	token, err := service.GenerateAccessToken(1, "test-username", "test@test.com", "user")
	if err != nil {
		t.Fatal(err)
	}

	// Тест валидации
	claims, err := service.ValidateAccessToken(token)
	if err != nil {
		t.Fatal(err)
	}

	if claims.UserID != 1 || claims.Email != "test@test.com" {
		t.Errorf("unexpected claims: %+v", claims)
	}

	// Тест с истекшим токеном
	config2 := config
	config2.AccessTokenTTL = -1 * time.Second
	service2 := NewJWTService(config2)
	expiredToken, _ := service2.GenerateAccessToken(1, "test-username", "test@test.com", "user")

	_, err = service.ValidateAccessToken(expiredToken)
	if err == nil {
		t.Error("expected error for expired token")
	}
}
