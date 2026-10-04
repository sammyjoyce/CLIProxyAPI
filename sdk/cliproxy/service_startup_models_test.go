package cliproxy

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// A restart must not serve requests before stored auths have their models bound:
// the HTTP listener used to open about a second before the watcher's first auth
// batch registered them, so every model answered "unknown provider" in between.
func TestServiceRun_RegistersStoredAuthModelsBeforeServing(t *testing.T) {
	ln, errListen := net.Listen("tcp", "127.0.0.1:0")
	if errListen != nil {
		t.Fatalf("failed to listen: %v", errListen)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if errClose := ln.Close(); errClose != nil {
		t.Fatalf("failed to close listener: %v", errClose)
	}

	authDir := t.TempDir()
	const authFile = "claude-startup-models-test.json"
	if errWrite := os.WriteFile(filepath.Join(authDir, authFile), []byte(`{"type":"claude","email":"startup@example.com","access_token":"sk-ant-oat-startup"}`), 0o600); errWrite != nil {
		t.Fatalf("failed to write auth file: %v", errWrite)
	}
	cfgPath := filepath.Join(authDir, "config.yaml")
	if errWrite := os.WriteFile(cfgPath, []byte("{}"), 0o644); errWrite != nil {
		t.Fatalf("failed to write config: %v", errWrite)
	}
	t.Cleanup(func() { GlobalModelRegistry().UnregisterClient(authFile) })

	modelsAtStart := make(chan int, 1)
	service, errBuild := NewBuilder().
		WithConfig(&config.Config{Host: "127.0.0.1", Port: port, AuthDir: authDir}).
		WithConfigPath(cfgPath).
		WithHooks(Hooks{OnBeforeStart: func(*config.Config) {
			modelsAtStart <- len(GlobalModelRegistry().GetModelsForClient(authFile))
		}}).
		Build()
	if errBuild != nil {
		t.Fatalf("failed to build service: %v", errBuild)
	}

	runCtx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- service.Run(runCtx) }()
	defer func() {
		cancel()
		select {
		case errRun := <-runDone:
			if errRun != nil && !errors.Is(errRun, context.Canceled) {
				t.Errorf("service.Run error: %v", errRun)
			}
		case <-time.After(10 * time.Second):
			t.Error("timed out waiting for service.Run to exit")
		}
	}()

	select {
	case count := <-modelsAtStart:
		if count == 0 {
			t.Fatal("stored claude auth had no registered models when the HTTP server started")
		}
	case errRun := <-runDone:
		t.Fatalf("service.Run exited before start: %v", errRun)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for OnBeforeStart")
	}
}
