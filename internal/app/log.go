package app

import (
	"log/slog"
	"os"

	"auth-proxy/internal/config"
	"auth-proxy/internal/store"
)

func newLogger(level string) *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slogLevel(level),
		AddSource: slogLevel(level) == slog.LevelDebug,
	}))
}

func printConfig(logger *slog.Logger, cfg *config.Gateway, snap *store.Snapshot, version string) {
	if logger == nil || cfg == nil || snap == nil {
		return
	}

	// Секрет не выводим: только признак, что он задан.
	logger.Info("configuration loaded", "config", map[string]interface{}{
		"version":          version,
		"log_level":        cfg.LogLevel,
		"shutdown_timeout": cfg.ShutdownTimeout.String(),
		"server": map[string]interface{}{
			"port":          cfg.Server.Port,
			"read_timeout":  cfg.Server.Timeouts.ReadTimeout.String(),
			"write_timeout": cfg.Server.Timeouts.WriteTimeout.String(),
		},
		"admin": map[string]interface{}{
			"port":          cfg.Admin.Port,
			"read_timeout":  cfg.Admin.Timeouts.ReadTimeout.String(),
			"write_timeout": cfg.Admin.Timeouts.WriteTimeout.String(),
		},
		"authentik": map[string]interface{}{
			"secret_header": cfg.Authentik.SecretHeader,
			"secret_set":    cfg.Authentik.Secret != "",
		},
		"routes_file": cfg.RoutesFile,
		"roles":       snap.Roles,
		"routes":      len(snap.Routes),
	})

	// Детальные маршруты - отдельно, чтобы не засорять.
	for i, route := range snap.Routes {
		logger.Debug("route detail",
			slog.Int("index", i),
			slog.String("host", route.Host),
			slog.String("prefix", route.Prefix),
			slog.String("target", route.Target),
			slog.Bool("redirect", route.Redirect),
			slog.Bool("strip_first_prefix", route.StripFirstPrefix),
			slog.Any("required_groups", route.RequiredGroups),
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
		return slog.LevelInfo
	}
}
