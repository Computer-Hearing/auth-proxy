package main

import (
	"auth-proxy/internal/config"
	"auth-proxy/internal/server/handlers"
	"fmt"
	"log"
	"log/slog"
	"net/http"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println(cfg)

	handler, err := handlers.NewHandlers(&handlers.Options{Logger: slog.Default(), Config: cfg})
	if err != nil {
		log.Fatal(err.Error())
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handler.ServeHTTP)

	server := http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	server.ListenAndServe()
}
