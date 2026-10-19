package config

import "time"

// SessionConfig - общее для обоих сервисов: auth-сервис выдаёт куки с JWT, гейт их проверяет.
type SessionConfig struct {
	Cookie CookieConfig `yaml:"cookie"`
	JWT    JWTConfig    `yaml:"jwt"`
}

// CookieConfig - имена и атрибуты auth-кук.
type CookieConfig struct {
	AccessName  string `yaml:"access_name" env:"SESSION_ACCESS_COOKIE" envDefault:"access_token"`
	RefreshName string `yaml:"refresh_name" env:"SESSION_REFRESH_COOKIE" envDefault:"refresh_token"`
	// Domain - общий домен кук (напр. .example.com), когда гейт и auth-сервис
	// на разных поддоменах. Пусто = привязка к текущему хосту.
	Domain string `yaml:"domain" env:"SESSION_COOKIE_DOMAIN"`
	// Secure - вычисляется при загрузке: true в production.
	Secure bool `yaml:"-"`
}

// JWTConfig - секреты и время жизни токенов.
type JWTConfig struct {
	AccessSecret  string        `yaml:"access_secret" env:"SESSION_ACCESS_SECRET" validate:"required,min=32"`
	RefreshSecret string        `yaml:"refresh_secret" env:"SESSION_REFRESH_SECRET" validate:"required,min=32"`
	AccessTTL     time.Duration `yaml:"access_ttl" env:"SESSION_ACCESS_TTL" envDefault:"15m" validate:"gte=1m"`
	RefreshTTL    time.Duration `yaml:"refresh_ttl" env:"SESSION_REFRESH_TTL" envDefault:"24h" validate:"gte=1m,gtfield=AccessTTL"`
}
