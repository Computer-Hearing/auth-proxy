package config

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/caarlos0/env/v11"
	"github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

// Load загружает конфиг из ENV + YAML + дефолтов
func Load() (*Config, error) {
	cfg := &Config{}

	// загружаем .env файл в переменные окружения если есть,
	// он там не перезапишет уже имеющиеся переменные окружения
	slog.Info("Loading env config from: /.env")
	_ = godotenv.Load(".env")

	// Парсим ENV (с дефолтами из тегов)
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("parse env: %w", err)
	}

	// Загружаем конфиг из YAML (обязательный файл) - переопределяет всё, что в нём явно указано
	configPath := os.Getenv("YAML_CONFIG_PATH")
	if configPath == "" {
		slog.Info("YAML_CONFIG_PATH env variable not set, using default: /etc/auth-proxy/config.yaml")
		configPath = "/etc/auth-proxy/config.yaml"
	}

	if err := loadFromYAML(configPath, cfg); err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	// Валидация всех полей по тегам
	if err := validator.New().Struct(cfg); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Проверки, которые не выразить тегами
	if err := validate(cfg); err != nil {
		return nil, err
	}

	// Достраиваем значения по умолчанию
	normalize(cfg)

	return cfg, nil
}

// loadFromYAML загружает конфиг из YAML-файла прямо в cfg
func loadFromYAML(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}

	if len(cfg.Gateway.Routes) == 0 {
		return fmt.Errorf("no routes defined in %s", path)
	}

	return nil
}
