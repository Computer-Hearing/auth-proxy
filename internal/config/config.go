package config

import (
	"time"
)

// Config - главная структура конфига
type Config struct {
	Server    ServerConfig  `yaml:"server" validate:"required"`
	JWT       JWTConfig     `yaml:"jwt" validate:"required"`
	Bcrypt    BcryptConfig  `yaml:"bcrypt"`
	Routes    []RouteConfig `yaml:"routes" validate:"required,min=1,dive"`
	Roles     []string      `yaml:"roles" env:"ROLES" envDefault:"user,admin,superadmin" validate:"required,min=3,dive,required"`
	Blacklist []string      `yaml:"blacklist"`
	Users     []User        `yaml:"users" validate:"dive"`
}

// ServerConfig - настройки сервера
type ServerConfig struct {
	Port            int           `yaml:"port" env:"SERVER_PORT" envDefault:"5000" validate:"gte=1,lte=65535"`
	ReadTimeout     time.Duration `yaml:"read_timeout" env:"SERVER_READ_TIMEOUT" envDefault:"5s" validate:"gte=1s"`
	WriteTimeout    time.Duration `yaml:"write_timeout" env:"SERVER_WRITE_TIMEOUT" envDefault:"10s" validate:"gte=1s"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" env:"SERVER_SHUTDOWN_TIMEOUT" envDefault:"10s" validate:"gte=1s"`
}

// JWTConfig - настройки JWT (обязательные секреты из ENV)
type JWTConfig struct {
	AccessCookieKey  string        `yaml:"access_cookie_key" env:"JWT_ACCESS_COOKIE_KEY" envDefault:"access_token"`
	RefreshCookieKey string        `yaml:"refresh_cookie_key" env:"JWT_REFRESH_COOKIE_KEY" envDefault:"refresh_token"`
	AccessSecret     string        `yaml:"access_secret" env:"JWT_ACCESS_SECRET" validate:"required,min=32"`
	RefreshSecret    string        `yaml:"refresh_secret" env:"JWT_REFRESH_SECRET" validate:"required,min=32"`
	AccessTTL        time.Duration `yaml:"access_ttl" env:"JWT_ACCESS_TTL" envDefault:"15m" validate:"gte=1m"`
	RefreshTTL       time.Duration `yaml:"refresh_ttl" env:"JWT_REFRESH_TTL" envDefault:"24h" validate:"gte=1m,gtfield=AccessTTL"`
}

// BcryptConfig - настройки хеширования
type BcryptConfig struct {
	Cost int `yaml:"cost" env:"BCRYPT_COST" envDefault:"12" validate:"gte=4,lte=31"`
}

// RouteConfig - маршрут для Gateway
type RouteConfig struct {
	Prefix           string   `yaml:"prefix" validate:"required"`
	Target           string   `yaml:"target" validate:"required,url"`
	SkipAuth         bool     `yaml:"skip_auth"`
	Redirect         bool     `yaml:"redirect"`
	StripFirstPrefix bool     `yaml:"strip_first_prefix"`
	RequiredRoles    []string `yaml:"required_roles" validate:"dive,required"`
}

type User struct {
	ID       int64  `yaml:"id" json:"id" validate:"required,gte=1"`
	Login    string `yaml:"login" json:"login" validate:"required,min=4,max=128"`
	Password string `yaml:"password" json:"-" validate:"required,min=4,max=72"`
	Email    string `yaml:"email" json:"email" validate:"omitempty,email"`
	FullName string `yaml:"full_name" json:"full_name"`
	Role     string `yaml:"role" json:"role" validate:"required"`
}
