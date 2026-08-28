package pkg

import "time"

const (
	ServiceName = "auth-proxy"

	MinUsernameLen       = 4
	MaxUsernameLen       = 128
	MinHashedPasswordLen = 60
	MinFirstNameLen      = 1
	MaxFirstNameLen      = 128

	// DefaultJWTAccessTTL - дефолтное время жизни access токена
	DefaultJWTAccessTTL = 15 * time.Minute
	// DefaultJWTRefreshTTL - дефолтное время жизни refresh токена
	DefaultJWTRefreshTTL = 24 * time.Hour
	// DefaultTokenCacheTTL - время жизни токена в кеше, чуть меньше 4 минут (если AccessTTL 15 min)
	DefaultTokenCacheTTL             = DefaultJWTAccessTTL / 4
	DefaultTokenCacheCleanupInterval = DefaultTokenCacheTTL / 4
)
