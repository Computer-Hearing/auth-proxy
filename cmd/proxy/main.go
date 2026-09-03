package main

import (
	"auth-proxy/internal/config"
	"auth-proxy/internal/modules/tokens"
	"auth-proxy/internal/modules/users"
	"auth-proxy/internal/server/auth"
	"auth-proxy/internal/server/handlers"
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

// version подставляется при сборке: -ldflags "-X main.version=v1.2.3"
var version = "dev"

func main() {
	printBanner()

	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err.Error())
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slogLevel(cfg.LogLevel),
		AddSource: slogLevel(cfg.LogLevel) == slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	// Выводим конфиг для дебага
	printConfig(logger, cfg)

	// Общее хранилище пользователей: гейт и auth-сервис работают
	// с одним и тем же набором пользователей из конфига.
	userStorage := users.NewUsersCache(&users.UserStorageConfig{
		Logger: logger.With(slog.String("component", "user-storage"))})
	userStorage.LoadUsers(context.Background(), cfg.ToDomainUsers())

	// Общий JWT-модуль: гейт валидирует access-токены, auth-сервис их выдаёт.
	jwtModule := tokens.NewJWTService(tokens.Config{
		SecretKey:       cfg.JWT.AccessSecret,
		AccessTokenTTL:  cfg.JWT.AccessTTL,
		RefreshTokenTTL: cfg.JWT.RefreshTTL,
	}, *userStorage)

	// Гейт: проксирует трафик после проверки токенов и ролей
	handler, err := handlers.NewHandlers(&handlers.Options{
		Logger: logger.With(slog.String("component", "gateway-handler")),
		Config: cfg,
		JWT:    jwtModule,
	})
	if err != nil {
		log.Fatal(err.Error())
	}

	// Auth-сервис: /login /refresh /logout /user/me (отдельный порт)
	authService, err := auth.New(&auth.Options{
		Logger: logger.With(slog.String("component", "auth-handler")),
		Config: cfg,
		JWT:    jwtModule,
		Users:  *userStorage,
	})
	if err != nil {
		log.Fatal(err.Error())
	}

	gatewayServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      newGatewayHandlerWithHealthz(handler, version),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	authServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Auth.Port),
		Handler:      authService.Handler(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// Запускаем оба сервера параллельно; ошибка любого из них - фатальная
	errCh := make(chan error, 2)
	go serve("gateway", gatewayServer, logger.With(slog.String("component", "gateway-server")), errCh)
	go serve("auth", authServer, logger.With(slog.String("component", "auth-server")), errCh)

	// Ждём сигнала выключения или ошибки сервера
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		logger.Error("server stopped with error", "error", err.Error())
	case sig := <-stop:
		logger.Info("received signal, shutting down", "signal", sig.String())
	}

	// Даём серверам закончить обработку активных запросов с таймаутом
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()
	if err := gatewayServer.Shutdown(ctx); err != nil {
		logger.Error("gateway shutdown", "error", err.Error())
	}
	if err := authServer.Shutdown(ctx); err != nil {
		logger.Error("auth shutdown", "error", err.Error())
	}
}

// serve запускает один http.Server и сообщает об ошибке в errCh.
// ErrServerClosed (штатное выключение через Shutdown) не считаем ошибкой.
func serve(name string, srv *http.Server, logger *slog.Logger, errCh chan<- error) {
	logger.Info("listening", "name", name, "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errCh <- fmt.Errorf("%s server: %w", name, err)
	}
}

// newGatewayHandler вешает /healthz рядом с прокси-хендлером
func newGatewayHandlerWithHealthz(proxy http.Handler, version string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","version":%q}`+"\n", version)
	})
	mux.Handle("/", proxy)
	return mux
}

// printBanner выводит красивый баннер с названием программы
func printBanner() {
	banner := `
    ╔══════════════════════════════════════════════════╗
    ║                                                  ║
    ║     █████╗ ██╗   ██╗████████╗██╗  ██╗            ║
    ║    ██╔══██╗██║   ██║╚══██╔══╝██║  ██║            ║
    ║    ███████║██║   ██║   ██║   ███████║            ║
    ║    ██╔══██║██║   ██║   ██║   ██╔══██║            ║
    ║    ██║  ██║╚██████╔╝   ██║   ██║  ██║            ║
    ║    ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝            ║
    ║                                                  ║
    ║    ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗    ║
    ║    ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝    ║
    ║    ██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚════╝      ║
    ║    ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗  ██╔═══╝     ║
    ║    ██║     ██║  ██║╚██████╔╝██╔╝ ██╗ ██║         ║
    ║    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═╝         ║
    ║                                                  ║
    ║                AUTH-PROXY v1.0.0                 ║
    ║       Authentication & Authorization Proxy       ║
    ║                                                  ║
    ╚══════════════════════════════════════════════════╝
    `
	fmt.Println(banner)
}

func printConfig(logger *slog.Logger, cfg *config.Config) {
	if logger == nil || cfg == nil {
		return
	}

	// Собираем все в один структурный лог
	configMap := map[string]interface{}{
		"env":       cfg.ENV,
		"log_level": cfg.LogLevel,
		"version":   version,
		"server": map[string]interface{}{
			"port":             cfg.Server.Port,
			"read_timeout":     cfg.Server.ReadTimeout.String(),
			"write_timeout":    cfg.Server.WriteTimeout.String(),
			"shutdown_timeout": cfg.Server.ShutdownTimeout.String(),
		},
		"gateway": map[string]interface{}{
			"base_url": cfg.Gateway.BaseURL,
		},
		"auth": map[string]interface{}{
			"port":     cfg.Auth.Port,
			"base_url": cfg.Auth.BaseURL,
		},
		"jwt": map[string]interface{}{
			"access_cookie_key":  cfg.JWT.AccessCookieKey,
			"refresh_cookie_key": cfg.JWT.RefreshCookieKey,
			"cookie_domain":      cfg.JWT.CookieDomain,
			"access_ttl":         cfg.JWT.AccessTTL.String(),
			"refresh_ttl":        cfg.JWT.RefreshTTL.String(),
			// "access_secret":    "***", // скрываем
			// "refresh_secret":   "***", // скрываем
		},
		"bcrypt": map[string]interface{}{
			"cost": cfg.Bcrypt.Cost,
		},
		"routes": len(cfg.Routes),
		"roles":  cfg.Roles,
		"users":  len(cfg.Users),
	}

	logger.Info("configuration loaded", "config", configMap)

	// Детальные маршруты - отдельно, чтобы не засорять
	if len(cfg.Routes) > 0 {
		for i, route := range cfg.Routes {
			logger.Debug("route detail",
				slog.Int("index", i),
				slog.String("prefix", route.Prefix),
				slog.String("target", route.Target),
				slog.Bool("skip_auth", route.SkipAuth),
				slog.Bool("redirect", route.Redirect),
				slog.Bool("strip_first_prefix", route.StripFirstPrefix),
				slog.Any("required_roles", route.RequiredRoles),
			)
		}
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
