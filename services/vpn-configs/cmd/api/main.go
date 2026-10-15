package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"leprechaun/vpn-configs/internal/application"
	"leprechaun/vpn-configs/internal/infrastructure/amnezia"
	"leprechaun/vpn-configs/internal/infrastructure/config"
	"leprechaun/vpn-configs/internal/infrastructure/mongodb"
	"leprechaun/vpn-configs/internal/infrastructure/usersclient"
	"leprechaun/vpn-configs/internal/infrastructure/vault"
	transport "leprechaun/vpn-configs/internal/transport/http"
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
	client, repository, err := mongodb.Open(startupCtx, cfg.MongoURI, cfg.MongoDatabase)
	startupCancel()
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
	if cfg.InternalToken != "" {
		access, err := usersclient.New(cfg.PeerAPIURL, cfg.InternalToken)
		if err != nil {
			return err
		}
		files, err := vault.New(mongodb.NewFileStore(client.Database(cfg.MongoDatabase)), cfg.EncryptionKey)
		if err != nil {
			return err
		}
		var host application.Provisioner
		if cfg.KnownHostsFile != "" {
			host, err = amnezia.New(amnezia.Settings{Address: cfg.HostAddress, Username: cfg.HostUsername, Password: cfg.HostPassword, KnownHostsFile: cfg.KnownHostsFile, PublicEndpoint: cfg.PublicEndpoint})
			if err != nil {
				return err
			}
		}
		manager := application.NewManager(repository, access, host, files, rand.Text, time.Now)
		api := transport.NewBatchAPI(manager, cfg.InternalToken)
		routes = append(routes, api.Register)
		if host != nil {
			workerCtx, cancel := context.WithCancel(ctx)
			done := make(chan struct{})
			go func() { defer close(done); manager.RunWorker(workerCtx, repository) }()
			defer func() { cancel(); <-done }()
		}
	}
	server := &http.Server{
		Addr: cfg.HTTPAddress, Handler: transport.NewRouter(func(ctx context.Context) error { return client.Ping(ctx, nil) }, routes...),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}
	result := make(chan error, 1)
	go func() { result <- server.ListenAndServe() }()
	slog.Info("service listening", "service", "vpn-configs", "address", cfg.HTTPAddress)
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
