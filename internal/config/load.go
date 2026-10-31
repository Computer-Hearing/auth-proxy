package config

import (
	"fmt"
	"os"

	"github.com/caarlos0/env/v11"
	"github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

const defaultGatewayPath = "/etc/auth-proxy/gateway.yaml"

// Load читает gateway.yaml (ENV + YAML) и routes.yaml.
// Отсутствие любого из файлов - ошибка.
func Load() (*Gateway, *Routes, error) {
	gw := &Gateway{}

	// .env не перезаписывает уже заданные переменные окружения
	_ = godotenv.Load(".env")

	if err := env.Parse(gw); err != nil {
		return nil, nil, fmt.Errorf("parse env: %w", err)
	}

	gatewayPath := os.Getenv("YAML_CONFIG_PATH")
	if gatewayPath == "" {
		gatewayPath = defaultGatewayPath
	}
	if err := loadGatewayYAML(gatewayPath, gw); err != nil {
		return nil, nil, err
	}

	if err := validator.New().Struct(gw); err != nil {
		return nil, nil, fmt.Errorf("validation failed: %w", err)
	}

	routes, err := LoadRoutes(gw.RoutesFile)
	if err != nil {
		return nil, nil, err
	}

	return gw, routes, nil
}

// loadGatewayYAML загружает статический конфиг из YAML поверх ENV.
func loadGatewayYAML(path string, gw *Gateway) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read gateway config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, gw); err != nil {
		return fmt.Errorf("parse gateway config %s: %w", path, err)
	}
	return nil
}

// LoadRoutes читает и валидирует routes.yaml.
func LoadRoutes(path string) (*Routes, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read routes config %s: %w", path, err)
	}
	routes := &Routes{}
	if err := yaml.Unmarshal(data, routes); err != nil {
		return nil, fmt.Errorf("parse routes config %s: %w", path, err)
	}
	if err := ValidateRoutes(routes); err != nil {
		return nil, fmt.Errorf("validate routes config %s: %w", path, err)
	}
	return routes, nil
}
