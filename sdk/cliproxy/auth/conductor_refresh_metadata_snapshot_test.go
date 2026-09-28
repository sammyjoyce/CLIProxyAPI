package auth

import (
	"context"
	"net/http"
	"sync"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const refreshMetadataProbeKey = "__refresh_metadata_probe__"

// metadataWritingRefreshExecutor writes into the metadata map of the auth it is
// handed, so a test can see whether that map is still the manager's live one.
type metadataWritingRefreshExecutor struct {
	id string
}

func (e *metadataWritingRefreshExecutor) Identifier() string { return e.id }

func (e *metadataWritingRefreshExecutor) Execute(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *metadataWritingRefreshExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}

func (e *metadataWritingRefreshExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata[refreshMetadataProbeKey] = true
	auth.Metadata["access_token"] = "refreshed-token"
	return auth, nil
}

func (e *metadataWritingRefreshExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *metadataWritingRefreshExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func newRefreshMetadataProbeManager(t *testing.T, authID string) (*Manager, map[string]any) {
	t.Helper()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(&metadataWritingRefreshExecutor{id: "probe"})
	if _, errRegister := manager.Register(context.Background(), &Auth{
		ID:       authID,
		Provider: "probe",
		Metadata: map[string]any{},
	}); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	manager.mu.RLock()
	liveMetadata := manager.auths[authID].Metadata
	manager.mu.RUnlock()
	if liveMetadata == nil {
		t.Fatal("live metadata map is nil, want the registered empty map")
	}
	return manager, liveMetadata
}

// TestRefreshAuthForRequestDoesNotWriteThroughToLiveMetadata pins the borrowed
// credential boundary: refreshAuthForRequest clones the credential under m.mu
// before the executor touches it, and Auth.Clone detaches even an empty metadata
// map, so an executor metadata write can no longer land in the map the manager
// still shares with the request and persist paths.
func TestRefreshAuthForRequestDoesNotWriteThroughToLiveMetadata(t *testing.T) {
	manager, liveMetadata := newRefreshMetadataProbeManager(t, "snapshot-auth")

	if _, errRefresh := manager.refreshAuthForRequest(context.Background(), "snapshot-auth", ""); errRefresh != nil {
		t.Fatalf("refreshAuthForRequest() error = %v", errRefresh)
	}

	if _, leaked := liveMetadata[refreshMetadataProbeKey]; leaked {
		t.Fatalf("executor metadata write reached the live credential map: %#v", liveMetadata)
	}
	if len(liveMetadata) != 0 {
		t.Fatalf("live credential metadata changed: %#v", liveMetadata)
	}
}

// TestAuthCloneDetachesEmptyMetadataMap guards the aliasing case directly: a
// clone must own its metadata map even when the source map is empty, and a nil
// map must stay nil.
func TestAuthCloneDetachesEmptyMetadataMap(t *testing.T) {
	source := &Auth{ID: "clone-auth", Metadata: map[string]any{}}
	clone := source.Clone()
	if clone.Metadata == nil {
		t.Fatal("clone metadata map = nil, want an empty non-nil map")
	}
	clone.Metadata["access_token"] = "refreshed-token"
	if len(source.Metadata) != 0 {
		t.Fatalf("clone write reached the source map: %#v", source.Metadata)
	}

	nilSource := &Auth{ID: "nil-auth"}
	if got := nilSource.Clone(); got.Metadata != nil {
		t.Fatalf("clone of a nil metadata map = %#v, want nil", got.Metadata)
	}
}

// raceLiveMetadataWriter runs a manager path loop against a writer that rewrites
// the live credential's metadata under m.mu, which is the window a path must not
// read or clone that credential from. Run with -race.
func raceLiveMetadataWriter(t *testing.T, manager *Manager, authID string, path func() error) {
	t.Helper()
	const iterations = 256
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for index := 0; index < iterations; index++ {
			manager.mu.Lock()
			if live := manager.auths[authID]; live != nil {
				if live.Metadata == nil {
					live.Metadata = make(map[string]any)
				}
				live.Metadata["last_refresh"] = index
			}
			manager.mu.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		for index := 0; index < iterations; index++ {
			if errPath := path(); errPath != nil {
				t.Errorf("manager path error = %v", errPath)
				return
			}
		}
	}()

	wg.Wait()
}

// TestRefreshAuthForRequestMetadataRaceWithLiveWriter is the runnable regression
// for the window between m.mu.RUnlock and the metadata reads: a request-scoped
// refresh must snapshot the borrowed credential instead of reading it unlocked.
func TestRefreshAuthForRequestMetadataRaceWithLiveWriter(t *testing.T) {
	const authID = "race-auth"
	manager, _ := newRefreshMetadataProbeManager(t, authID)

	raceLiveMetadataWriter(t, manager, authID, func() error {
		_, errRefresh := manager.refreshAuthForRequest(context.Background(), authID, "")
		return errRefresh
	})
}

// TestRegisterMetadataRaceWithLiveWriter covers the other manager path that
// publishes a credential and keeps using it: the scheduler entry must be cloned
// while m.mu is still held, because the published clone's metadata map is
// reachable to concurrent writers.
func TestRegisterMetadataRaceWithLiveWriter(t *testing.T) {
	const authID = "register-race-auth"
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(&metadataWritingRefreshExecutor{id: "probe"})
	if _, errRegister := manager.Register(context.Background(), &Auth{ID: authID, Provider: "probe", Metadata: map[string]any{}}); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	raceLiveMetadataWriter(t, manager, authID, func() error {
		_, errRegister := manager.Register(context.Background(), &Auth{ID: authID, Provider: "probe", Metadata: map[string]any{}})
		return errRegister
	})
}
