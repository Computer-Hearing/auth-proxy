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

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err.Error())
	}

	logger := slog.Default()

	// Общее хранилище пользователей: гейт и auth-сервис работают
	// с одним и тем же набором пользователей из конфига.
	userStorage := users.NewUsersCache(&users.UserStorageConfig{Logger: logger})
	userStorage.LoadUsers(context.Background(), cfg.ToDomainUsers())

	// Общий JWT-модуль: гейт валидирует access-токены, auth-сервис их выдаёт.
	jwtModule := tokens.NewJWTService(tokens.Config{
		SecretKey:       cfg.JWT.AccessSecret,
		AccessTokenTTL:  cfg.JWT.AccessTTL,
		RefreshTokenTTL: cfg.JWT.RefreshTTL,
	}, *userStorage)

	// Гейт: проксирует трафик после проверки токенов и ролей
	handler, err := handlers.NewHandlers(&handlers.Options{
		Logger: logger,
		Config: cfg,
		JWT:    jwtModule,
	})
	if err != nil {
		log.Fatal(err.Error())
	}

	// Auth-сервис: /login /refresh /logout /user/me (отдельный порт)
	authService, err := auth.New(&auth.Options{
		Logger: logger,
		Config: cfg,
		JWT:    jwtModule,
		Users:  *userStorage,
	})
	if err != nil {
		log.Fatal(err.Error())
	}

	gatewayServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      handler,
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
	go serve("gateway", gatewayServer, logger, errCh)
	go serve("auth", authServer, logger, errCh)

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
