package auth

import (
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// Gateway policy: never let Codex bill purchased credits.
//
// ChatGPT plans fall through to purchased credits automatically once the
// plan's included Codex usage window is exhausted, and upstream offers no
// switch to stop that. Codex reports the window state on every response
// (x-codex-primary-* / x-codex-secondary-* headers and websocket
// codex.rate_limits events), so as soon as a response shows an exhausted
// window the credential is put into a credential-wide quota cooldown until the
// window resets. The existing credential_quota cooldown is honoured by the
// selector and scheduler, survives successful results and auth file reloads,
// and expires on its own at NextRecoverAt.
const (
	codexCreditGuardReason = "codex included usage exhausted; blocked to avoid spending credits"
	// codexCreditGuardFallback applies when an exhausted window carries no
	// usable reset time.
	codexCreditGuardFallback = time.Hour
	// codexCreditGuardMaxBlock bounds a corrupt or far-future reset time.
	codexCreditGuardMaxBlock = 8 * 24 * time.Hour
)

var codexCreditGuardWindows = []string{"Primary", "Secondary"}

// codexIncludedUsageExhaustedUntil reports whether a Codex quota snapshot shows
// an exhausted included-usage window and, if so, when the latest exhausted
// window resets.
func codexIncludedUsageExhaustedUntil(signals map[string]string, observedAt time.Time) (time.Time, bool) {
	if len(signals) == 0 {
		return time.Time{}, false
	}
	if observedAt.IsZero() {
		observedAt = time.Now()
	}
	exhausted := false
	var until time.Time
	for _, window := range codexCreditGuardWindows {
		prefix := "X-Codex-" + window + "-"
		used, ok := parseCodexSignalFloat(signals[prefix+"Used-Percent"])
		if !ok || used < 100 {
			continue
		}
		exhausted = true
		if reset := codexSignalResetTime(signals, prefix, observedAt); reset.After(until) {
			until = reset
		}
	}
	if strings.EqualFold(strings.TrimSpace(signals["X-Codex-Limit-Reached"]), "true") {
		exhausted = true
		for _, window := range codexCreditGuardWindows {
			if reset := codexSignalResetTime(signals, "X-Codex-"+window+"-", observedAt); reset.After(until) {
				until = reset
			}
		}
	}
	if !exhausted {
		return time.Time{}, false
	}
	if !until.After(observedAt) {
		until = observedAt.Add(codexCreditGuardFallback)
	}
	if limit := observedAt.Add(codexCreditGuardMaxBlock); until.After(limit) {
		until = limit
	}
	return until, true
}

func codexSignalResetTime(signals map[string]string, prefix string, observedAt time.Time) time.Time {
	if at, ok := parseCodexSignalFloat(signals[prefix+"Reset-At"]); ok && at > 0 {
		return time.Unix(int64(at), 0)
	}
	if after, ok := parseCodexSignalFloat(signals[prefix+"Reset-After-Seconds"]); ok && after > 0 {
		return observedAt.Add(time.Duration(after * float64(time.Second)))
	}
	return time.Time{}
}

func parseCodexSignalFloat(value string) (float64, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

// applyCodexCreditGuardLocked blocks a Codex credential whose freshly observed
// quota snapshot shows exhausted included usage. Callers hold m.mu.
func applyCodexCreditGuardLocked(auth *Auth, provider string, now time.Time) {
	if auth == nil || !strings.EqualFold(strings.TrimSpace(provider), "codex") {
		return
	}
	until, exhausted := codexIncludedUsageExhaustedUntil(auth.Quota.Signals, auth.Quota.ObservedAt)
	if !exhausted || !until.After(now) {
		return
	}
	alreadyBlocked := auth.Quota.Exceeded && auth.Quota.Reason == "credential_quota" && auth.Quota.NextRecoverAt.After(now)
	if alreadyBlocked && !auth.Quota.NextRecoverAt.Before(until) {
		return
	}
	auth.Unavailable = true
	auth.Quota.Exceeded = true
	auth.Quota.Reason = "credential_quota"
	auth.Quota.NextRecoverAt = until
	if auth.NextRetryAfter.Before(until) {
		auth.NextRetryAfter = until
	}
	auth.Status = StatusError
	auth.StatusMessage = codexCreditGuardReason
	if !alreadyBlocked {
		log.Warnf("codex credit guard: %s (%s) included usage exhausted; blocked until %s so purchased credits are not used",
			auth.ID, auth.Label, until.UTC().Format(time.RFC3339))
	}
}
