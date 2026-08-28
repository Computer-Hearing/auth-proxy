package config

import (
	"auth-proxy/pkg"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/caarlos0/env/v11"
	"github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

var (
	ErrConfigIsNil = errors.New("config file is nil")
)

// Load загружает конфиг из ENV + YAML + дефолтов
func Load() (*Config, error) {
	cfg := &Config{}

	// загружаем .env файл в переменные окружения если есть
	// если читать либу, то он там не перезапишет уже имеющиеся переменные окружения
	_ = godotenv.Load(".env")

	// Парсим ENV (с дефолтами из тегов, включая Roles)
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("parse env: %w", err)
	}

	// Загружаем конфиг из YAML (обязательный файл) - переопределяет всё, что в нём явно указано
	configPath := os.Getenv("YAML_CONFIG_PATH")
	if configPath == "" {
		configPath = "config.yaml"
	}

	if err := loadFromYAML(configPath, cfg); err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	validate := validator.New()
	// Валидация всех полей
	if err := validate.Struct(cfg); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Дополнительная валидация маршрутов
	if err := validateRoutes(cfg); err != nil {
		return nil, err
	}

	// Дополнительная валидация blacklist
	if err := validateBlacklist(cfg); err != nil {
		return nil, err
	}

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

	if len(cfg.Routes) == 0 {
		return fmt.Errorf("no routes defined in %s", path)
	}

	return nil
}

// validateRoutes проверяет маршруты
func validateRoutes(cfg *Config) error {
	// Проверяем, что маршруты уникальны (по префиксу)
	seen := make(map[string]bool)
	for i, route := range cfg.Routes {
		if route.Prefix == "" {
			return fmt.Errorf("route[%d]: prefix is required", i)
		}
		if route.Target == "" {
			return fmt.Errorf("route[%d]: target is required", i)
		}

		// Проверяем, что required_roles существуют в общем списке ролей
		for _, role := range route.RequiredRoles {
			if !cfg.IsValidRole(role) {
				return fmt.Errorf("route[%d]: unknown role '%s' (available: %v)", i, role, cfg.Roles)
			}
		}

		// Достраиваем роли "лесенкой": роли в cfg.Roles идут по возрастанию полномочий,
		// поэтому если роут открыт роли X, он должен быть открыт и всем ролям выше X.
		// Если у роута вообще нет ролей - открываем его для всех ролей.
		if !route.SkipAuth {
			minIdx := 0
			if len(route.RequiredRoles) > 0 {
				minIdx = len(cfg.Roles) - 1
				for _, role := range route.RequiredRoles {
					if idx := slices.Index(cfg.Roles, role); idx < minIdx {
						minIdx = idx
					}
				}
			}
			cfg.Routes[i].RequiredRoles = slices.Clone(cfg.Roles[minIdx:])
		}

		// Проверка на дубликаты префиксов
		if seen[route.Prefix] {
			return fmt.Errorf("route[%d]: duplicate prefix '%s'", i, route.Prefix)
		}
		seen[route.Prefix] = true
	}

	// Валидация пользователей, за одно проверяем есть ли хотя бы один суперадмин
	hasSuperAdmin := false
	for i, user := range cfg.Users {
		// есть ли роль в списке ролей
		if !slices.Contains(cfg.Roles, user.Role) {
			return fmt.Errorf("user[%d]: role '%s' is not in Roles list", user.ID, user.Role)
		}

		// хешируем пароль
		hashPass, err := pkg.HashPassword(user.Password, cfg.Bcrypt.Cost)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}
		cfg.Users[i].Password = hashPass

		// проверяем самая главная роль ли это
		if user.Role == cfg.Roles[len(cfg.Roles)-1] {
			hasSuperAdmin = true
		}
	}

	// Если не нашли ни одного супер админа (пользователя с самой главной ролью), то создаем
	if !hasSuperAdmin {
		usr, err := createDefaultSuperAdmin(cfg)
		if err != nil {
			return err
		}
		cfg.Users = append(cfg.Users, usr)
	}

	return nil
}

// validateBlacklist проверяет IP-адреса в черном списке
func validateBlacklist(cfg *Config) error {
	for _, entry := range cfg.Blacklist {
		if net.ParseIP(entry) == nil {
			if _, _, err := net.ParseCIDR(entry); err != nil {
				return fmt.Errorf("invalid IP or CIDR in blacklist: %s", entry)
			}
		}
	}
	return nil
}

// IsValidRole проверяет, существует ли роль в списке
func (c *Config) IsValidRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// IsIPBlacklisted проверяет, заблокирован ли IP
func (c *Config) IsIPBlacklisted(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, entry := range c.Blacklist {
		if net.ParseIP(entry) != nil && entry == ipStr {
			return true
		}

		if _, network, err := net.ParseCIDR(entry); err == nil {
			if network.Contains(ip) {
				return true
			}
		}
	}

	return false
}

// GetRouteByPrefix ищет маршрут по префиксу (самый длинный совпадающий)
func (c *Config) GetRouteByPrefix(path string) *RouteConfig {
	var best *RouteConfig
	bestLen := -1

	for _, route := range c.Routes {
		if strings.HasPrefix(path, route.Prefix) {
			if len(route.Prefix) > bestLen {
				bestLen = len(route.Prefix)
				best = &route
			}
		}
	}

	return best
}

func createDefaultSuperAdmin(cfg *Config) (User, error) {
	if cfg == nil {
		return User{}, ErrConfigIsNil
	}

	superadminPass, err := pkg.HashPassword("superadmin", cfg.Bcrypt.Cost)
	if err != nil {
		return User{}, fmt.Errorf("hash password: %w", err)
	}

	maxID := int64(0)
	for _, u := range cfg.Users {
		if u.ID > maxID {
			maxID = u.ID
		}
	}

	superAdmin := User{
		ID:       maxID + 1,
		Login:    "superadmin",
		Password: superadminPass,
		FullName: "superadmin",
		Role:     cfg.Roles[len(cfg.Roles)-1],
	}
	return superAdmin, nil
}
