package config

import (
	"fmt"
	"slices"
	"strings"

	"github.com/go-playground/validator/v10"

	"auth-proxy/pkg/hostmatch"
	"auth-proxy/pkg/routepattern"
)

// ValidateRoutes проверяет роли и маршруты. Возвращает первую ошибку.
func ValidateRoutes(r *Routes) error {
	if r == nil {
		return fmt.Errorf("routes config is nil")
	}
	if err := validator.New().Struct(r); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	if err := validateRoles(r.Roles); err != nil {
		return err
	}
	return validateRoutes(r.Routes, r.Roles)
}

// validateRoles проверяет, что роли непустые и уникальные.
func validateRoles(roles []string) error {
	seen := make(map[string]bool, len(roles))
	for i, role := range roles {
		if role == "" {
			return fmt.Errorf("roles[%d]: empty role", i)
		}
		if seen[role] {
			return fmt.Errorf("roles[%d]: duplicate role %q", i, role)
		}
		seen[role] = true
	}
	return nil
}

// validateRoutes проверяет маршруты: паттерн, host, группы, дубликаты и
// зарезервированные под админку пути.
func validateRoutes(routes []RouteConfig, roles []string) error {
	seen := make(map[string]bool, len(routes))
	for i, route := range routes {
		if route.Prefix == "" {
			return fmt.Errorf("route[%d]: prefix is required", i)
		}
		if route.Target == "" {
			return fmt.Errorf("route[%d]: target is required", i)
		}
		if _, err := routepattern.Parse(route.Prefix); err != nil {
			return fmt.Errorf("route[%d]: invalid prefix %q: %w", i, route.Prefix, err)
		}
		if err := validateReservedPrefix(route.Prefix); err != nil {
			return fmt.Errorf("route[%d]: %w", i, err)
		}
		if err := validateHost(route.Host); err != nil {
			return fmt.Errorf("route[%d]: %w", i, err)
		}
		for _, group := range route.RequiredGroups {
			if !slices.Contains(roles, group) {
				return fmt.Errorf("route[%d]: unknown group %q (available: %v)", i, group, roles)
			}
		}

		key := route.Prefix + "|" + route.Host
		if seen[key] {
			return fmt.Errorf("route[%d]: duplicate prefix %q with host %q", i, route.Prefix, route.Host)
		}
		seen[key] = true
	}
	return nil
}

// validateHost - пустой host (любой домен), точный host или *.wildcard.
func validateHost(host string) error {
	if host == "" {
		return nil
	}
	if strings.ContainsAny(host, " /") {
		return fmt.Errorf("invalid host %q", host)
	}
	if hostmatch.IsWildcard(host) {
		base := host[2:]
		if base == "" || strings.Contains(base, "*") || strings.Contains(base, ".") && strings.HasPrefix(base, ".") {
			return fmt.Errorf("invalid wildcard host %q", host)
		}
		return nil
	}
	if strings.Contains(host, "*") {
		return fmt.Errorf("invalid host %q: wildcard must be *.example.com", host)
	}
	return nil
}

// validateReservedPrefix не даёт маршруту занять путь админки.
// Catch-all "/" разрешён: зарезервированные пути проверяются раньше движка.
func validateReservedPrefix(prefix string) error {
	literal := prefix
	if i := strings.IndexByte(prefix, '*'); i >= 0 {
		literal = prefix[:i]
	}
	if literal == "/" || literal == "" {
		return nil
	}
	for _, reserved := range ReservedPrefixes {
		if strings.HasPrefix(literal, reserved) || strings.HasPrefix(reserved, literal) {
			return fmt.Errorf("prefix %q overlaps reserved admin path %q", prefix, reserved)
		}
	}
	return nil
}
