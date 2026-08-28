package tokens

import (
	"auth-proxy/pkg"
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/patrickmn/go-cache"
)

type TokenCacheConfig struct {
	FieldTTL        time.Duration
	CleanupInterval time.Duration
	Logger          *slog.Logger
}

type TokenCache struct {
	cache  *cache.Cache
	logger *slog.Logger

	FieldTTL        time.Duration
	CleanupInterval time.Duration
}

func NewTokenCache(cfg *TokenCacheConfig) *TokenCache {
	if cfg == nil {
		panic("token cache config is nil")
	}

	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.FieldTTL == 0 {
		cfg.FieldTTL = pkg.DefaultTokenCacheTTL
	}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = pkg.DefaultTokenCacheCleanupInterval
	}

	return &TokenCache{
		cache:  cache.New(cfg.FieldTTL, cfg.CleanupInterval),
		logger: cfg.Logger,
	}
}

// Set добавляет токен в кеш.
func (uc *TokenCache) Set(_ context.Context, userId int64, tokenId string) {
	uc.cache.Set(tokenFingerprint(userId, tokenId), struct{}{}, uc.FieldTTL)
}

func (uc *TokenCache) Get(_ context.Context, userId int64, tokenId string) bool {
	_, ok := uc.cache.Get(tokenFingerprint(userId, tokenId))
	if !ok {
		return false
	}
	return true
}

func (uc *TokenCache) Delete(_ context.Context, userId int64, tokenId string) {
	uc.cache.Delete(tokenFingerprint(userId, tokenId))
}

func tokenFingerprint(userId int64, tokenId string) string {
	return fmt.Sprintf("%d:%s", userId, tokenId)
}
