package app

import (
	"auth-proxy/internal/config"
	"log/slog"
	"os"
)

func newLogger(level string) *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slogLevel(level),
		AddSource: slogLevel(level) == slog.LevelDebug,
	}))
}

func printConfig(logger *slog.Logger, cfg *config.Config, version string) {
	if logger == nil || cfg == nil {
		return
	}

	// Собираем все в один структурный лог (секреты не выводим)
	configMap := map[string]interface{}{
		"env":              cfg.ENV,
		"log_level":        cfg.LogLevel,
		"version":          version,
		"shutdown_timeout": cfg.ShutdownTimeout.String(),
		"gateway": map[string]interface{}{
			"port":          cfg.Gateway.Port,
			"read_timeout":  cfg.Gateway.Timeouts.ReadTimeout.String(),
			"write_timeout": cfg.Gateway.Timeouts.WriteTimeout.String(),
			"base_url":      cfg.Gateway.BaseURL,
			"routes":        len(cfg.Gateway.Routes),
		},
		"auth": map[string]interface{}{
			"port":          cfg.Auth.Port,
			"read_timeout":  cfg.Auth.Timeouts.ReadTimeout.String(),
			"write_timeout": cfg.Auth.Timeouts.WriteTimeout.String(),
			"base_url":      cfg.Auth.BaseURL,
			"allow_origins": cfg.Auth.AllowOrigins,
			// куда можно вернуть пользователя после логина по абсолютному next
			"redirect_hosts": redirectHosts(cfg).Patterns(),
		},
		"session": map[string]interface{}{
			"access_cookie":  cfg.Session.Cookie.AccessName,
			"refresh_cookie": cfg.Session.Cookie.RefreshName,
			"cookie_domain":  cfg.Session.Cookie.Domain,
			"cookie_secure":  cfg.Session.Cookie.Secure,
			"access_ttl":     cfg.Session.JWT.AccessTTL.String(),
			"refresh_ttl":    cfg.Session.JWT.RefreshTTL.String(),
		},
		"access": map[string]interface{}{
			"roles":       cfg.Access.Roles,
			"bcrypt_cost": cfg.Access.BcryptCost,
			"users":       len(cfg.Access.Users),
		},
	}

	logger.Info("configuration loaded", "config", configMap)

	// Детальные маршруты - отдельно, чтобы не засорять
	for i, route := range cfg.Gateway.Routes {
		logger.Debug("route detail",
			slog.Int("index", i),
			slog.String("host", route.Host),
			slog.String("prefix", route.Prefix),
			slog.String("target", route.Target),
			slog.String("auth_method", string(route.AuthMethod)),
			slog.Bool("redirect", route.Redirect),
			slog.Bool("strip_first_prefix", route.StripFirstPrefix),
			slog.Any("required_roles", route.RequiredRoles),
		)
	}
}

func slogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelDebug
	}
}
