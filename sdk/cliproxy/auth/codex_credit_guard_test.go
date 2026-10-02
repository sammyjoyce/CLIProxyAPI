package auth

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	internallogging "github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestCodexIncludedUsageExhaustedUntil(t *testing.T) {
	observed := time.Unix(1_790_000_000, 0)
	reset := observed.Add(40 * time.Hour)
	unix := func(at time.Time) string { return strconv.FormatInt(at.Unix(), 10) }
	for _, tc := range []struct {
		name      string
		signals   map[string]string
		exhausted bool
		until     time.Time
	}{
		{"below limit", map[string]string{"X-Codex-Primary-Used-Percent": "72", "X-Codex-Primary-Reset-At": unix(reset)}, false, time.Time{}},
		{"primary exhausted", map[string]string{"X-Codex-Primary-Used-Percent": "100", "X-Codex-Primary-Reset-At": unix(reset), "X-Codex-Credits-Has-Credits": "True"}, true, reset},
		{"fractional over", map[string]string{"X-Codex-Primary-Used-Percent": "100.0", "X-Codex-Primary-Reset-After-Seconds": "3600"}, true, observed.Add(time.Hour)},
		{"secondary exhausted", map[string]string{"X-Codex-Primary-Used-Percent": "10", "X-Codex-Primary-Reset-At": unix(observed.Add(time.Hour)), "X-Codex-Secondary-Used-Percent": "100", "X-Codex-Secondary-Reset-At": unix(reset)}, true, reset},
		{"both exhausted uses latest reset", map[string]string{"X-Codex-Primary-Used-Percent": "100", "X-Codex-Primary-Reset-At": unix(observed.Add(time.Hour)), "X-Codex-Secondary-Used-Percent": "100", "X-Codex-Secondary-Reset-At": unix(reset)}, true, reset},
		{"limit reached flag", map[string]string{"X-Codex-Limit-Reached": "True", "X-Codex-Primary-Used-Percent": "99", "X-Codex-Primary-Reset-At": unix(reset)}, true, reset},
		{"limit not reached flag", map[string]string{"X-Codex-Limit-Reached": "false", "X-Codex-Primary-Used-Percent": "99"}, false, time.Time{}},
		{"no reset uses fallback", map[string]string{"X-Codex-Primary-Used-Percent": "100"}, true, observed.Add(codexCreditGuardFallback)},
		{"past reset uses fallback", map[string]string{"X-Codex-Primary-Used-Percent": "100", "X-Codex-Primary-Reset-At": unix(observed.Add(-time.Minute))}, true, observed.Add(codexCreditGuardFallback)},
		{"far future capped", map[string]string{"X-Codex-Primary-Used-Percent": "100", "X-Codex-Primary-Reset-At": unix(observed.Add(90 * 24 * time.Hour))}, true, observed.Add(codexCreditGuardMaxBlock)},
		{"additional limit alone ignored", map[string]string{"X-Codex-Additional-Gpt-Reserve-Primary-Used-Percent": "100", "X-Codex-Primary-Used-Percent": "5"}, false, time.Time{}},
		{"garbage ignored", map[string]string{"X-Codex-Primary-Used-Percent": "full"}, false, time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			until, exhausted := codexIncludedUsageExhaustedUntil(tc.signals, observed)
			if exhausted != tc.exhausted || !until.Equal(tc.until) {
				t.Fatalf("got (%v, %v), want (%v, %v)", until, exhausted, tc.until, tc.exhausted)
			}
		})
	}
}

func markCodexQuota(t *testing.T, manager *Manager, authID, provider string, headers http.Header) {
	t.Helper()
	ctx := internallogging.WithResponseHeadersHolder(context.Background())
	internallogging.SetResponseHeaders(ctx, headers)
	manager.MarkResult(ctx, Result{AuthID: authID, Provider: provider, Model: "gpt-6-sol", Success: true})
}

func TestMarkResultCodexCreditGuardBlocksUntilReset(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	auth, errRegister := manager.Register(context.Background(), &Auth{ID: "codex-credit-guard", Provider: "codex", Status: StatusActive})
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	reset := time.Now().Add(40 * time.Hour).Truncate(time.Second)

	markCodexQuota(t, manager, auth.ID, "codex", http.Header{"X-Codex-Primary-Used-Percent": {"60"}, "X-Codex-Primary-Reset-At": {strconv.FormatInt(reset.Unix(), 10)}})
	current, _ := manager.GetByID(auth.ID)
	if blocked, _, _ := isAuthBlockedForModel(current, "gpt-6-sol", time.Now()); blocked {
		t.Fatal("credential below the included limit must stay available")
	}

	markCodexQuota(t, manager, auth.ID, "codex", http.Header{
		"X-Codex-Primary-Used-Percent": {"100"}, "X-Codex-Primary-Reset-At": {strconv.FormatInt(reset.Unix(), 10)},
		"X-Codex-Credits-Has-Credits": {"True"}, "X-Codex-Credits-Balance": {"58865.53"},
	})
	current, _ = manager.GetByID(auth.ID)
	if !current.Quota.Exceeded || current.Quota.Reason != "credential_quota" || !current.Quota.NextRecoverAt.Equal(reset) {
		t.Fatalf("quota = %+v, want credential cooldown until %v", current.Quota, reset)
	}
	for _, model := range []string{"gpt-6-sol", "gpt-6.1-sol", ""} {
		if blocked, _, next := isAuthBlockedForModel(current, model, time.Now()); !blocked || !next.Equal(reset) {
			t.Fatalf("model %q blocked=%v next=%v, want blocked until %v", model, blocked, next, reset)
		}
	}
	if !isCredentialBlocked(current, 3, time.Now()) {
		t.Fatal("scheduler must treat the credential as blocked")
	}

	// A later success without quota headers must not lift the guard.
	manager.MarkResult(context.Background(), Result{AuthID: auth.ID, Provider: "codex", Model: "gpt-6-sol", Success: true})
	current, _ = manager.GetByID(auth.ID)
	if blocked, _, _ := isAuthBlockedForModel(current, "gpt-6-sol", time.Now()); !blocked {
		t.Fatal("success without a fresh snapshot lifted the credit guard")
	}
	if blocked, _, _ := isAuthBlockedForModel(current, "gpt-6-sol", reset.Add(time.Second)); blocked {
		t.Fatal("credential must become available once the window resets")
	}
}

func TestMarkResultCodexCreditGuardIgnoresOtherProviders(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	auth, errRegister := manager.Register(context.Background(), &Auth{ID: "claude-credit-guard", Provider: "claude", Status: StatusActive})
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	markCodexQuota(t, manager, auth.ID, "claude", http.Header{"X-Codex-Primary-Used-Percent": {"100"}, "Anthropic-Ratelimit-Unified-Status": {"allowed"}})
	current, _ := manager.GetByID(auth.ID)
	if current.Quota.Exceeded {
		t.Fatalf("non-Codex credential was blocked: %+v", current.Quota)
	}
}

func TestExecuteCodexCreditGuardFailsOverAfterExhaustion(t *testing.T) {
	const model = "credit-guard-model"
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	highID, lowID := "credit-guard-high-"+t.Name(), "credit-guard-low-"+t.Name()
	for _, candidate := range []*Auth{
		{ID: highID, Provider: "codex", Status: StatusActive, Attributes: map[string]string{"priority": "4"}},
		{ID: lowID, Provider: "codex", Status: StatusActive, Attributes: map[string]string{"priority": "3"}},
	} {
		registry.GetGlobalRegistry().RegisterClient(candidate.ID, "codex", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(candidate.ID) })
		if _, errRegister := manager.Register(context.Background(), candidate); errRegister != nil {
			t.Fatal(errRegister)
		}
	}
	reset := strconv.FormatInt(time.Now().Add(40*time.Hour).Unix(), 10)
	var attempts []string
	manager.RegisterExecutor(&customStreamMockExecutor{identifier: "codex", mockCustomErrorExecutor: mockCustomErrorExecutor{
		executeFn: func(ctx context.Context, selected *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
			attempts = append(attempts, selected.ID)
			used := "40"
			if selected.ID == highID {
				used = "100"
			}
			internallogging.SetResponseHeaders(ctx, http.Header{"X-Codex-Primary-Used-Percent": {used}, "X-Codex-Primary-Reset-At": {reset}})
			return cliproxyexecutor.Response{Payload: []byte(selected.ID)}, nil
		},
	}})
	for i := 0; i < 3; i++ {
		ctx := internallogging.WithResponseHeadersHolder(context.Background())
		if _, errExecute := manager.Execute(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{}); errExecute != nil {
			t.Fatal(errExecute)
		}
	}
	if len(attempts) != 3 || attempts[0] != highID || attempts[1] != lowID || attempts[2] != lowID {
		t.Fatalf("attempts = %v, want exhausted account once, then only the account with included usage", attempts)
	}
}
