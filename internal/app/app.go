package app

import (
	"auth-proxy/internal/auth"
	"auth-proxy/internal/config"
	"auth-proxy/internal/gateway"
	"auth-proxy/internal/tokens"
	"auth-proxy/internal/users"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

// Run собирает зависимости, поднимает два http-слушателя (гейт и auth-сервис)
// и ждёт сигнала выключения или ошибки сервера.
func Run(version string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	logger := newLogger(cfg.LogLevel)
	slog.SetDefault(logger)

	// Выводим конфиг для дебага
	printConfig(logger, cfg, version)

	// Общее хранилище пользователей: гейт и auth-сервис работают
	// с одним и тем же набором пользователей из конфига.
	userList, err := users.FromConfig(cfg.Access)
	if err != nil {
		return fmt.Errorf("load users: %w", err)
	}
	userStorage := users.New(logger.With(slog.String("component", "user-storage")))
	userStorage.Load(context.Background(), userList)

	// Общий JWT-сервис: гейт валидирует access-токены, auth-сервис их выдаёт.
	tokenService := tokens.New(tokens.Config{
		SecretKey:       cfg.Session.JWT.AccessSecret,
		AccessTokenTTL:  cfg.Session.JWT.AccessTTL,
		RefreshTokenTTL: cfg.Session.JWT.RefreshTTL,
	})

	// Гейт: проксирует трафик после проверки токенов и ролей
	gw, err := gateway.New(&gateway.Options{
		Logger:     logger.With(slog.String("component", "gateway-handler")),
		Routes:     cfg.Gateway.Routes,
		Cookie:     cfg.Session.Cookie,
		AuthURL:    cfg.Auth.BaseURL,
		Tokens:     tokenService,
		Users:      userStorage,
		AppVersion: version,
	})
	if err != nil {
		return err
	}

	// Auth-сервис: /login /refresh /logout /user/me (отдельный порт)
	authService, err := auth.New(&auth.Options{
		Logger:       logger.With(slog.String("component", "auth-handler")),
		Cookie:       cfg.Session.Cookie,
		AllowOrigins: cfg.Auth.AllowOrigins,
		GatewayURL:   cfg.Gateway.BaseURL,
		Tokens:       tokenService,
		Users:        userStorage,
	})
	if err != nil {
		return err
	}

	gatewayServer := newServer(cfg.Gateway.Port, cfg.Gateway.Timeouts, gw.Handler())
	authServer := newServer(cfg.Auth.Port, cfg.Auth.Timeouts, authService.Handler())

	// Запускаем оба сервера параллельно; ошибка любого из них - фатальная
	errCh := make(chan error, 2)
	go serve("gateway", gatewayServer, logger.With(slog.String("component", "gateway-server")), errCh)
	go serve("auth", authServer, logger.With(slog.String("component", "auth-server")), errCh)

	// Ждём сигнала выключения или ошибки сервера
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	var serveErr error
	select {
	case serveErr = <-errCh:
		logger.Error("server stopped with error", "error", serveErr.Error())
	case sig := <-stop:
		logger.Info("received signal, shutting down", "signal", sig.String())
	}

	// Даём серверам закончить обработку активных запросов с таймаутом
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := gatewayServer.Shutdown(ctx); err != nil {
		logger.Error("gateway shutdown", "error", err.Error())
	}
	if err := authServer.Shutdown(ctx); err != nil {
		logger.Error("auth shutdown", "error", err.Error())
	}
	return serveErr
}

func newServer(port int, timeouts config.Timeouts, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      handler,
		ReadTimeout:  timeouts.ReadTimeout,
		WriteTimeout: timeouts.WriteTimeout,
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
