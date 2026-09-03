package config

import (
	"auth-proxy/internal/domain"
	"time"
)

// Config - главная структура конфига
type Config struct {
	ENV       string        `yaml:"env" env:"ENV" envDefault:"development" validate:"oneof=development production"`
	LogLevel  string        `yaml:"log_level" env:"LOG_LEVEL" envDefault:"debug" validate:"oneof=debug info"`
	Server    ServerConfig  `yaml:"server" validate:"required"`
	Gateway   GatewayConfig `yaml:"gateway" validate:"required"`
	Auth      AuthConfig    `yaml:"auth" validate:"required"`
	JWT       JWTConfig     `yaml:"jwt" validate:"required"`
	Bcrypt    BcryptConfig  `yaml:"bcrypt"`
	Routes    []RouteConfig `yaml:"routes" validate:"required,min=1,dive"`
	Roles     []string      `yaml:"roles" env:"ROLES" envDefault:"user,admin,superadmin" validate:"required,min=3,dive,required"`
	Blacklist []string      `yaml:"blacklist"`
	Users     []User        `yaml:"users" validate:"dive"`
}

// GatewayConfig - внешний адрес гейта (auth-proxy),
// на него auth-сервис возвращает пользователя после логина/обновления токена/
// выхода через параметр next.
type GatewayConfig struct {
	BaseURL string `yaml:"base_url" env:"GATEWAY_BASE_URL" envDefault:"http://localhost:5000" validate:"required,url"`
}

// ServerConfig - настройки сервера
type ServerConfig struct {
	Port            int           `yaml:"port" env:"SERVER_PORT" envDefault:"5000" validate:"gte=1,lte=65535"`
	ReadTimeout     time.Duration `yaml:"read_timeout" env:"SERVER_READ_TIMEOUT" envDefault:"5s" validate:"gte=1s"`
	WriteTimeout    time.Duration `yaml:"write_timeout" env:"SERVER_WRITE_TIMEOUT" envDefault:"10s" validate:"gte=1s"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" env:"SERVER_SHUTDOWN_TIMEOUT" envDefault:"10s" validate:"gte=1s"`
}

// AuthConfig - настройки auth-сервиса (второй http-слушатель в том же бинарнике)
type AuthConfig struct {
	// Port - порт, на котором отвечают /login /refresh /logout /user/me
	Port int `yaml:"port" env:"AUTH_PORT" envDefault:"6000" validate:"gte=1,lte=65535"`
	// BaseURL - внешний адрес auth-сервиса (для Location в редиректах гейта)
	BaseURL string `yaml:"base_url" env:"AUTH_BASE_URL" validate:"required,url"`
}

// JWTConfig - настройки JWT (обязательные секреты из ENV)
type JWTConfig struct {
	AccessCookieKey  string        `yaml:"access_cookie_key" env:"JWT_ACCESS_COOKIE_KEY" envDefault:"access_token"`
	RefreshCookieKey string        `yaml:"refresh_cookie_key" env:"JWT_REFRESH_COOKIE_KEY" envDefault:"refresh_token"`
	CookieDomain     string        `yaml:"cookie_domain" env:"JWT_COOKIE_DOMAIN"`
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
	Prefix           string     `yaml:"prefix" validate:"required"`
	Target           string     `yaml:"target" validate:"required,url"`
	AuthMethod       AuthMethod `yaml:"auth_method" validate:"omitempty,oneof=jwt basic none"`
	Redirect         bool       `yaml:"redirect"`
	StripFirstPrefix bool       `yaml:"strip_first_prefix"`
	RequiredRoles    []string   `yaml:"required_roles" validate:"dive,required"`
}

// AuthMethod - способ аутентификации маршрута.
type AuthMethod string

const (
	// AuthNone - маршрут открыт, без какой-либо проверки.
	AuthNone AuthMethod = "none"
	// AuthBasic - проверка login/password из Basic-заголовка по кешу пользователей.
	// Роль проверяется через RequiredRoles, как и для jwt.
	AuthBasic AuthMethod = "basic"
	// AuthJWT - проверка access/refresh кук (JWT). Используется по умолчанию.
	AuthJWT AuthMethod = "jwt"
)

type User struct {
	ID       int64  `yaml:"id" json:"id" validate:"required,gte=1"`
	Login    string `yaml:"login" json:"login" validate:"required,min=4,max=128"`
	Password string `yaml:"password" json:"-" validate:"required,min=4,max=72"`
	Email    string `yaml:"email" json:"email" validate:"omitempty,email"`
	FullName string `yaml:"full_name" json:"full_name"`
	Role     string `yaml:"role" json:"role" validate:"required"`
}

// ToDomainUsers превращает юзеров конфига в доменные (для users-кеша).
// Поля зовутся по-разному (login -> username, full_name -> first_name),
// а пароль в конфиге уже лежит BCrypt-хешем - после validateRoutes.
func (c *Config) ToDomainUsers() []domain.User {
	users := make([]domain.User, 0, len(c.Users))
	for _, u := range c.Users {
		users = append(users, domain.User{
			ID:             u.ID,
			Username:       u.Login,
			Email:          u.Email,
			FirstName:      u.FullName,
			HashedPassword: u.Password,
			Role:           u.Role,
		})
	}
	return users
}
