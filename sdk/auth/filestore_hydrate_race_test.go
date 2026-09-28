package auth

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	claudeauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/claude"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// fixedPayloadTokenStorage persists more keys than the in-memory metadata map
// holds, which is exactly the shape Save-side hydration exists for.
type fixedPayloadTokenStorage struct{}

func (s *fixedPayloadTokenStorage) SetMetadata(map[string]any) {}

func (s *fixedPayloadTokenStorage) SaveTokenToFile(authFilePath string) error {
	return os.WriteFile(authFilePath, []byte(`{"type":"test","setup_token":true}`), 0o600)
}

// TestFileTokenStore_Save_HydrationRaceWithClaudeMetadataReaders guards the
// Save-side metadata hydration against the concurrent map access crash both
// review rounds flagged: FileTokenStore.Save mutates the live shared
// Auth.Metadata map, while every Claude request path reads the same map under
// claudeDevicePoolMu. Run with -race.
func TestFileTokenStore_Save_HydrationRaceWithClaudeMetadataReaders(t *testing.T) {
	ctx := context.Background()
	baseDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(baseDir, "001"), 0o700); err != nil {
		t.Fatalf("create dir: %v", err)
	}

	store := NewFileTokenStore()
	store.SetBaseDir(baseDir)

	auth := &cliproxyauth.Auth{
		ID:       "shared.json",
		Provider: "test",
		FileName: "shared.json",
		Storage:  &fixedPayloadTokenStorage{},
		Metadata: map[string]any{"type": "test"},
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 200 {
			if _, err := store.Save(ctx, auth); err != nil {
				t.Errorf("Save() error: %v", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for range 200 {
			_ = claudeauth.ReadMetadataBool(&auth.Metadata, "setup_token")
			_ = claudeauth.ReadMetadataString(&auth.Metadata, "type")
		}
	}()
	wg.Wait()

	if !claudeauth.ReadMetadataBool(&auth.Metadata, "setup_token") {
		t.Fatalf("hydrated metadata missing setup_token after Save: %v", auth.Metadata)
	}
}
