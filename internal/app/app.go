package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"auth-proxy/internal/admin"
	"auth-proxy/internal/config"
	"auth-proxy/internal/gateway"
	"auth-proxy/internal/reverseproxy"
	"auth-proxy/internal/store"
)

// Run собирает зависимости, поднимает два http-слушателя
// (gateway и admin) и ждёт сигнала выключения или ошибки сервера.
func Run(version string) error {
	gwCfg, routesCfg, err := config.Load()
	if err != nil {
		return err
	}

	logger := newLogger(gwCfg.LogLevel)
	slog.SetDefault(logger)

	// Начальный снапшот маршрутов и ролей.
	snap, err := store.Build(routesCfg, func(route config.RouteConfig) (http.Handler, error) {
		return reverseproxy.New(route, logger)
	})
	if err != nil {
		return fmt.Errorf("build routes: %w", err)
	}
	st := store.New(snap)

	printConfig(logger, gwCfg, snap, version)

	gw, err := gateway.New(&gateway.Options{
		Logger:       logger.With(slog.String("component", "gateway-handler")),
		Store:        st,
		AdminPort:    gwCfg.Admin.Port,
		SecretHeader: gwCfg.Authentik.SecretHeader,
		AppVersion:   version,
	})
	if err != nil {
		return err
	}

	adm, err := admin.New(&admin.Options{
		Logger:       logger.With(slog.String("component", "admin-handler")),
		Store:        st,
		RoutesPath:   gwCfg.RoutesFile,
		SecretHeader: gwCfg.Authentik.SecretHeader,
		AppVersion:   version,
	})
	if err != nil {
		return err
	}

	gatewayServer := newServer(gwCfg.Server.Port, gwCfg.Server.Timeouts, gw.Handler())
	adminServer := newServer(gwCfg.Admin.Port, gwCfg.Admin.Timeouts, adm.Handler())

	// Запускаем оба сервера параллельно; ошибка любого из них - фатальная.
	errCh := make(chan error, 2)
	go serve("gateway", gatewayServer, logger.With(slog.String("component", "gateway-server")), errCh)
	go serve("admin", adminServer, logger.With(slog.String("component", "admin-server")), errCh)

	// Ждём сигнала выключения или ошибки сервера.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	var serveErr error
	select {
	case serveErr = <-errCh:
		logger.Error("server stopped with error", "error", serveErr.Error())
	case sig := <-stop:
		logger.Info("received signal, shutting down", "signal", sig.String())
	}

	// Даём серверам закончить обработку активных запросов с таймаутом.
	ctx, cancel := context.WithTimeout(context.Background(), gwCfg.ShutdownTimeout)
	defer cancel()
	if err := gatewayServer.Shutdown(ctx); err != nil {
		logger.Error("gateway shutdown", "error", err.Error())
	}
	if err := adminServer.Shutdown(ctx); err != nil {
		logger.Error("admin shutdown", "error", err.Error())
	}
	return serveErr
}

// newServer собирает http.Server для одного слушателя.
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
