package auth

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	claudeauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/empty"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type testTokenStorage struct {
	meta map[string]any
}

func (s *testTokenStorage) SetMetadata(meta map[string]any) { s.meta = meta }

func (s *testTokenStorage) SaveTokenToFile(authFilePath string) error {
	raw, err := json.Marshal(s.meta)
	if err != nil {
		return err
	}
	return os.WriteFile(authFilePath, raw, 0o600)
}

func TestFileTokenStore_Save_DisabledPersistsFlagForTokenStorage(t *testing.T) {
	ctx := context.Background()
	baseDir := t.TempDir()
	path := filepath.Join(baseDir, "disabled.json")

	if err := os.WriteFile(path, []byte(`{"type":"test","disabled":true}`), 0o600); err != nil {
		t.Fatalf("seed auth file: %v", err)
	}

	store := NewFileTokenStore()
	store.SetBaseDir(baseDir)
	storage := &testTokenStorage{}

	auth := &cliproxyauth.Auth{
		ID:       "disabled.json",
		Provider: "test",
		FileName: "disabled.json",
		Disabled: true,
		Storage:  storage,
		Metadata: map[string]any{"type": "test"},
	}

	if _, err := store.Save(ctx, auth); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read auth file: %v", err)
	}
	var meta map[string]any
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("unmarshal auth file: %v", err)
	}
	if disabled, _ := meta["disabled"].(bool); !disabled {
		t.Fatalf("disabled=%v, want true (raw=%s)", meta["disabled"], string(raw))
	}
}

func TestFileTokenStore_Save_HydratesMetadataFromTokenStorageFile(t *testing.T) {
	for _, tc := range []struct {
		name     string
		metadata map[string]any
	}{
		{name: "nil metadata"},
		{name: "hook metadata", metadata: map[string]any{
			"email": "alias@example.com", "timestamp": int64(1<<53 + 1),
			"headers": map[string]string{"X-Test": "value"},
			"empty":   "", "false": false, "null": nil,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := NewFileTokenStore()
			store.SetBaseDir(t.TempDir())
			auth := &cliproxyauth.Auth{
				ID: "claude-account.json", Provider: "claude", Metadata: tc.metadata,
				Storage: &claudeauth.ClaudeTokenStorage{
					AccessToken: "test-access-token", RefreshToken: "test-refresh-token",
					Email: "account@example.com", Expire: "2026-08-18T18:30:31Z", LastRefresh: "2026-08-18T10:30:32Z",
				},
			}
			want := map[string]any{
				"access_token": "test-access-token", "refresh_token": "test-refresh-token",
				"type": "claude", "email": "account@example.com", "disabled": false,
				"expired": "2026-08-18T18:30:31Z", "last_refresh": "2026-08-18T10:30:32Z",
			}
			maps.Copy(want, tc.metadata)
			path, errSave := store.Save(t.Context(), auth)
			if errSave != nil {
				t.Fatal(errSave)
			}
			for key, value := range want {
				if got, exists := auth.Metadata[key]; !exists || !reflect.DeepEqual(got, value) {
					t.Errorf("metadata %q was not hydrated or its existing value/type changed", key)
				}
			}
			if tc.metadata != nil && tc.metadata["access_token"] != want["access_token"] {
				t.Fatal("hydration replaced rather than updated the metadata map")
			}
			if auth.Attributes[cliproxyauth.AttributePath] != path || auth.FileName != auth.ID {
				t.Fatal("Save did not finish populating file identity")
			}
			// Runtime metadata remains authoritative over the original login storage.
			auth.Metadata["access_token"] = "test-refreshed-token"
			if _, errSave = store.Save(t.Context(), auth); errSave != nil {
				t.Fatal(errSave)
			}
			raw, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatal(errRead)
			}
			var persisted map[string]any
			if err := json.Unmarshal(raw, &persisted); err != nil {
				t.Fatal(err)
			}
			if persisted["access_token"] != "test-refreshed-token" || auth.Metadata["access_token"] != persisted["access_token"] {
				t.Fatal("repeated Save lost the runtime token update")
			}
		})
	}
}

func TestFileTokenStore_Save_HydrationAllowsNoOpStorage(t *testing.T) {
	store := NewFileTokenStore()
	store.SetBaseDir(t.TempDir())
	auth := &cliproxyauth.Auth{ID: "empty.json", Storage: &empty.EmptyStorage{}}
	path, err := store.Save(t.Context(), auth)
	if err != nil {
		t.Fatalf("no-op storage Save failed: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("no-op storage unexpectedly created a file: %v", err)
	}
}

type fileTokenStorageFunc func(string) error

func (f fileTokenStorageFunc) SaveTokenToFile(path string) error { return f(path) }

func TestFileTokenStore_Save_HydrationFailuresDoNotMergeMetadata(t *testing.T) {
	writeFailure := errors.New("test save failure")
	for _, tc := range []struct {
		name    string
		storage fileTokenStorageFunc
		wantErr string
	}{
		{"save failure", func(string) error { return writeFailure }, "test save failure"},
		{"read failure", func(path string) error { return os.Mkdir(path, 0o700) }, "reread persisted file failed"},
		{"empty file", func(path string) error { return os.WriteFile(path, nil, 0o600) }, ""},
		{"invalid JSON", func(path string) error {
			return os.WriteFile(path, []byte(`{"access_token":"partial-test-token","broken":`), 0o600)
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := NewFileTokenStore()
			store.SetBaseDir(t.TempDir())
			auth := &cliproxyauth.Auth{ID: "failure.json", Storage: tc.storage, Metadata: map[string]any{"timestamp": int64(42)}}
			_, err := store.Save(t.Context(), auth)
			if tc.wantErr == "" {
				// Hydration is best-effort: a file that cannot be unmarshaled must not
				// fail a Save that already wrote it successfully.
				if err != nil {
					t.Fatalf("Save error = %v, want nil for unmarshalable persisted file", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Save error = %v, want %q", err, tc.wantErr)
			}
			if tc.name == "save failure" && !errors.Is(err, writeFailure) {
				t.Fatal("Save lost the original storage error")
			}
			if _, exists := auth.Metadata["access_token"]; exists || auth.Metadata["timestamp"] != int64(42) {
				t.Fatal("failed hydration partially changed metadata")
			}
		})
	}
}

func TestFileTokenStore_Save_DisabledLoginCreatesCanonicalFile(t *testing.T) {
	baseDir := t.TempDir()
	path := filepath.Join(baseDir, "canonical-disabled.json")
	store := NewFileTokenStore()
	store.SetBaseDir(baseDir)

	auth := &cliproxyauth.Auth{
		ID:       "canonical-disabled.json",
		Provider: "test",
		FileName: "canonical-disabled.json",
		Disabled: true,
		Storage:  &testTokenStorage{},
		Metadata: map[string]any{"type": "test"},
	}

	ctx := cliproxyauth.WithAuthCreationIntent(context.Background())
	savedPath, err := store.Save(ctx, auth)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if savedPath != path {
		t.Fatalf("Save() path = %q, want %q", savedPath, path)
	}
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read canonical disabled credential: %v", errRead)
	}
	var metadata map[string]any
	if errUnmarshal := json.Unmarshal(raw, &metadata); errUnmarshal != nil {
		t.Fatalf("unmarshal canonical disabled credential: %v", errUnmarshal)
	}
	if disabled, _ := metadata["disabled"].(bool); !disabled {
		t.Fatalf("disabled = %v, want true", metadata["disabled"])
	}
}

func TestFileTokenStore_Save_DisabledStorageBackedRuntimeDoesNotRecreateMissingFile(t *testing.T) {
	baseDir := t.TempDir()
	path := filepath.Join(baseDir, "removed-disabled.json")
	store := NewFileTokenStore()
	store.SetBaseDir(baseDir)

	auth := &cliproxyauth.Auth{
		ID:       "removed-disabled.json",
		Provider: "test",
		FileName: "removed-disabled.json",
		Disabled: true,
		Storage:  &testTokenStorage{},
		Metadata: map[string]any{"type": "test"},
	}

	savedPath, err := store.Save(context.Background(), auth)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if savedPath != "" {
		t.Fatalf("Save() path = %q, want empty", savedPath)
	}
	if _, errStat := os.Stat(path); !os.IsNotExist(errStat) {
		t.Fatalf("removed credential was recreated or stat failed: %v", errStat)
	}
}
