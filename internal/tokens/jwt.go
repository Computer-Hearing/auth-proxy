package tokens

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// ServiceName - issuer токенов по умолчанию
	ServiceName = "auth-proxy"
	// DefaultAccessTTL - дефолтное время жизни access токена
	DefaultAccessTTL = 15 * time.Minute
	// DefaultRefreshTTL - дефолтное время жизни refresh токена
	DefaultRefreshTTL = 24 * time.Hour
)

var ErrInvalidToken = errors.New("invalid token")

// Claims - структура кастомных данных в токене
type Claims struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// Config - конфигурация JWT сервиса
type Config struct {
	SecretKey       string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	Issuer          string
}

// Service выпускает и проверяет JWT. О пользователях не знает:
// refresh-флоу (refresh -> пользователь -> новая пара) собирает auth-сервис.
type Service struct {
	config Config
}

// New - конструктор сервиса.
func New(config Config) *Service {
	if config.AccessTokenTTL == 0 {
		config.AccessTokenTTL = DefaultAccessTTL
	}
	if config.RefreshTokenTTL == 0 {
		config.RefreshTokenTTL = DefaultRefreshTTL
	}
	if config.Issuer == "" {
		config.Issuer = ServiceName
	}
	return &Service{config: config}
}

// GenerateAccessToken - создает access токен
func (s *Service) GenerateAccessToken(userID int64, username, email, role string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:   userID,
		Username: username,
		Email:    email,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.AccessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.config.Issuer,
			Subject:   fmt.Sprintf("%d", userID),
			ID:        generateTokenID(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.config.SecretKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return tokenString, nil
}

// GenerateRefreshToken - создает refresh токен
func (s *Service) GenerateRefreshToken(userID int64) (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(now.Add(s.config.RefreshTokenTTL)),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Issuer:    s.config.Issuer,
		Subject:   fmt.Sprintf("%d", userID),
		ID:        generateTokenID(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.config.SecretKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign refresh token: %w", err)
	}
	return tokenString, nil
}

// GenerateBothTokens - создает оба токена за раз
func (s *Service) GenerateBothTokens(userID int64, username, email, role string) (accessToken, refreshToken string, err error) {
	access, err := s.GenerateAccessToken(userID, username, email, role)
	if err != nil {
		return "", "", err
	}

	refresh, err := s.GenerateRefreshToken(userID)
	if err != nil {
		return "", "", err
	}

	return access, refresh, nil
}

// ValidateAccessToken - проверяет access токен и возвращает данные пользователя
func (s *Service) ValidateAccessToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Проверка алгоритма подписи
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.SecretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// ValidateRefreshToken - проверяет refresh токен и возвращает userID
func (s *Service) ValidateRefreshToken(tokenString string) (int64, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.SecretKey), nil
	})

	if err != nil {
		return 0, fmt.Errorf("failed to parse refresh token: %w", err)
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return 0, ErrInvalidToken
	}

	var userID int64
	_, _ = fmt.Sscanf(claims.Subject, "%d", &userID)
	return userID, nil
}

// generateTokenID - генерирует уникальный ID для токена
func generateTokenID() string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return hex.EncodeToString([]byte(time.Now().String()))
	}
	return hex.EncodeToString(bytes)
}
