package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"leprechaun/users/internal/application"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"leprechaun/users/internal/infrastructure/config"
	"leprechaun/users/internal/infrastructure/mongodb"
	"leprechaun/users/internal/infrastructure/vpnclient"
	"leprechaun/users/internal/infrastructure/yandex"
	transport "leprechaun/users/internal/transport/http"
)

func main() {
	if err := run(); err != nil {
		slog.Error("service stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	startupCtx, startupCancel := context.WithTimeout(ctx, 15*time.Second)
	defer startupCancel()
	client, repository, err := mongodb.Open(startupCtx, cfg.MongoURI, cfg.MongoDatabase)
	if err != nil {
		return fmt.Errorf("initialize storage: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := client.Disconnect(cleanupCtx); err != nil {
			slog.Error("MongoDB disconnect failed")
		}
	}()
	var routes []func(*http.ServeMux)
	if cfg.YandexClientID != "" || cfg.YandexClientSecret != "" {
		if cfg.YandexClientID == "" || cfg.YandexClientSecret == "" || cfg.YandexRedirectURL == "" {
			return errors.New("set YANDEX_CLIENT_ID, YANDEX_CLIENT_SECRET and YANDEX_REDIRECT_URL together")
		}
		sessions, err := mongodb.OpenSessions(startupCtx, client.Database(cfg.MongoDatabase))
		if err != nil {
			return errors.New("initialize authentication storage failed")
		}
		provider := yandex.New(cfg.YandexClientID, cfg.YandexClientSecret, cfg.YandexRedirectURL)
		service := application.New(repository, provider, rand.Text, time.Now, cfg.AdminYandexID)
		directory := application.NewDirectory(repository, cfg.AdminYandexID)
		auth, err := transport.NewAuth(service, directory, sessions, provider.AuthorizationURL, cfg.YandexRedirectURL)
		if err != nil {
			return err
		}
		if err := auth.SetFrontendOrigin(cfg.FrontendOrigin); err != nil {
			return err
		}
		routes = append(routes, auth.Register)
		var gateway application.ConfigGateway
		if cfg.InternalToken != "" {
			gateway, err = vpnclient.New(cfg.PeerAPIURL, cfg.InternalToken)
			if err != nil {
				return err
			}
		}
		routes = append(routes, func(mux *http.ServeMux) {
			auth.RegisterInternal(mux, cfg.InternalToken)
			auth.RegisterConfigRoutes(mux, gateway)
		})
	} else {
		routes = append(routes, func(mux *http.ServeMux) {
			mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "Set YANDEX_CLIENT_ID and YANDEX_CLIENT_SECRET in .env to enable sign-in", http.StatusServiceUnavailable)
			})
		})
	}
	startupCancel()
	server := &http.Server{
		Addr: cfg.HTTPAddress, Handler: transport.NewRouter(func(ctx context.Context) error { return client.Ping(ctx, nil) }, routes...),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}
	result := make(chan error, 1)
	go func() { result <- server.ListenAndServe() }()
	slog.Info("service listening", "service", "users", "address", cfg.HTTPAddress)
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return err
		}
		return nil
	}
}
