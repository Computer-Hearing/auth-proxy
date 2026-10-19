package config

// GatewayConfig - гейт: проксирует трафик по routes после проверки доступа.
type GatewayConfig struct {
	Port     int      `yaml:"port" env:"GATEWAY_PORT" envDefault:"5000" validate:"gte=1,lte=65535"`
	Timeouts Timeouts `yaml:",inline" envPrefix:"GATEWAY_"`
	// BaseURL - внешний адрес гейта, на него auth-сервис возвращает
	// пользователя после логина/обновления токена (через параметр next).
	BaseURL string        `yaml:"base_url" env:"GATEWAY_BASE_URL" envDefault:"http://localhost:5000" validate:"required,url"`
	Routes  []RouteConfig `yaml:"routes" validate:"required,min=1,dive"`
}

// RouteConfig - маршрут гейта
type RouteConfig struct {
	Host             string     `yaml:"host"`
	Prefix           string     `yaml:"prefix" validate:"required"`
	Target           string     `yaml:"target" validate:"required,url"`
	AuthMethod       AuthMethod `yaml:"auth_method" validate:"omitempty,oneof=jwt basic jwt2basic none"`
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
	// AuthJWTBasic - проверка JWT-кук, как для AuthJWT, но при проксировании
	// в целевой бэкенд подставляется заголовок Authorization: Basic
	// (base64(login:password)), сформированный при загрузке пользователей.
	AuthJWTBasic AuthMethod = "jwt2basic"
)
