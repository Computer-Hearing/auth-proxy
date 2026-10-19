package config

import (
	"auth-proxy/pkg/routepattern"
	"fmt"
	"slices"
)

// validate - проверки маршрутов и пользователей, которые не выразить тегами.
// Конфиг не меняет.
func validate(cfg *Config) error {
	if err := validateRoutes(cfg.Gateway.Routes, cfg.Access.Roles); err != nil {
		return err
	}
	return validateUsers(cfg.Access)
}

// validateRoutes проверяет маршруты
func validateRoutes(routes []RouteConfig, roles []string) error {
	// Проверяем, что маршруты уникальны (по префиксу и host)
	seen := make(map[string]bool)
	for i, route := range routes {
		if route.Prefix == "" {
			return fmt.Errorf("route[%d]: prefix is required", i)
		}
		if route.Target == "" {
			return fmt.Errorf("route[%d]: target is required", i)
		}

		// Проверяем, что prefix парсится как паттерн маршрута
		if _, err := routepattern.Parse(route.Prefix); err != nil {
			return fmt.Errorf("route[%d]: invalid prefix %q: %w", i, route.Prefix, err)
		}

		// Проверяем, что required_roles существуют в общем списке ролей
		for _, role := range route.RequiredRoles {
			if !slices.Contains(roles, role) {
				return fmt.Errorf("route[%d]: unknown role '%s' (available: %v)", i, role, roles)
			}
		}

		// Проверка на дубликаты префиксов (с учётом host)
		routeKey := route.Prefix + "|" + route.Host
		if seen[routeKey] {
			return fmt.Errorf("route[%d]: duplicate prefix '%s' with host '%s'", i, route.Prefix, route.Host)
		}
		seen[routeKey] = true
	}
	return nil
}

// validateUsers проверяет, что роли пользователей есть в списке ролей
func validateUsers(access AccessConfig) error {
	for _, user := range access.Users {
		if !slices.Contains(access.Roles, user.Role) {
			return fmt.Errorf("user[%d]: role '%s' is not in Roles list", user.ID, user.Role)
		}
	}
	return nil
}
