// Command node-agent starts the constrained outbound ScaleVault bridge.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/JTM-rootstorm/scalevault/services/memory-node-agent/internal/config"
	"github.com/JTM-rootstorm/scalevault/services/memory-node-agent/internal/health"
)

func main() {
	cfg, err := config.FromEnvironment()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(2)
	}

	httpServer := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           health.NewHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	shutdownContext, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stop()

	go func() {
		<-shutdownContext.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			slog.Error("node agent shutdown failed", "error", err)
		}
	}()

	slog.Info(
		"node agent health listener started",
		"address", cfg.ListenAddress,
		"upstream", cfg.UpstreamURL.Redacted(),
	)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("node agent stopped unexpectedly", "error", err)
		os.Exit(1)
	}
}
