package config

import "time"

// Config - главная структура конфига.
// Разбита по зонам: два сервиса (gateway, auth) и то, что они делят
// между собой (session - куки и JWT, access - роли и пользователи).
type Config struct {
	ENV             string        `yaml:"env" env:"ENV" envDefault:"development" validate:"oneof=development production"`
	LogLevel        string        `yaml:"log_level" env:"LOG_LEVEL" envDefault:"debug" validate:"oneof=debug info"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" env:"SHUTDOWN_TIMEOUT" envDefault:"10s" validate:"gte=1s"`

	Gateway GatewayConfig `yaml:"gateway"`
	Auth    AuthConfig    `yaml:"auth"`
	Session SessionConfig `yaml:"session"`
	Access  AccessConfig  `yaml:"access"`
}

// Timeouts - таймауты http-слушателя; у каждого сервиса свои.
type Timeouts struct {
	ReadTimeout  time.Duration `yaml:"read_timeout" env:"READ_TIMEOUT" envDefault:"5s" validate:"gte=1s"`
	WriteTimeout time.Duration `yaml:"write_timeout" env:"WRITE_TIMEOUT" envDefault:"10s" validate:"gte=1s"`
}
