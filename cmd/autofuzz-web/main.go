package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"autofuzz/internal/webui"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "HTTP listen address")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	manager := webui.NewManager(ctx)
	server := &http.Server{
		Addr: *listen, Handler: webui.NewServer(manager),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	}()
	fmt.Printf("Autofuzz Web: http://%s\n", *listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
