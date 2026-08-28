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

	routes := handlers.NewHandlers(cfg, slog.Default())

	mux := http.NewServeMux()
	mux.HandleFunc("/", routes.ServeHTTP)

	server := http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	server.ListenAndServe()
}
