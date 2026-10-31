package config

import "time"

// Gateway - статический конфиг (gateway.yaml): то, что меняется вручную
// и применяется после рестарта. Маршруты и роли живут отдельно, в routes.yaml.
type Gateway struct {
	LogLevel        string        `yaml:"log_level" env:"LOG_LEVEL" envDefault:"info" validate:"oneof=debug info warn error"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" env:"SHUTDOWN_TIMEOUT" envDefault:"10s" validate:"gte=1s"`

	Server     ServerConfig    `yaml:"server"`
	Admin      AdminConfig     `yaml:"admin"`
	Authentik  AuthentikConfig `yaml:"authentik"`
	RoutesFile string          `yaml:"routes_file" env:"ROUTES_FILE" envDefault:"/etc/auth-proxy/routes.yaml" validate:"required"`
}

// ServerConfig - основной http-слушатель (gateway), через него идут маршруты.
type ServerConfig struct {
	Port     int      `yaml:"port" env:"SERVER_PORT" envDefault:"5000" validate:"gte=1,lte=65535"`
	Timeouts Timeouts `yaml:",inline" envPrefix:"SERVER_"`
}

// AdminConfig - слушатель админки: статика и JSON API.
type AdminConfig struct {
	Port     int      `yaml:"port" env:"ADMIN_PORT" envDefault:"7000" validate:"gte=1,lte=65535"`
	Timeouts Timeouts `yaml:",inline" envPrefix:"ADMIN_"`
}

// AuthentikConfig - доверенные заголовки Authentik.
// Secret пока читается middleware, но не проверяется (TODO).
type AuthentikConfig struct {
	SecretHeader string `yaml:"secret_header" env:"AUTHENTIK_SECRET_HEADER" envDefault:"X-Proxy-Secret"`
	Secret       string `yaml:"secret" env:"AUTHENTIK_SECRET"`
}

// Timeouts - таймауты http-слушателя; у каждого сервиса свои.
type Timeouts struct {
	ReadTimeout  time.Duration `yaml:"read_timeout" env:"READ_TIMEOUT" envDefault:"5s" validate:"gte=1s"`
	WriteTimeout time.Duration `yaml:"write_timeout" env:"WRITE_TIMEOUT" envDefault:"10s" validate:"gte=1s"`
}
