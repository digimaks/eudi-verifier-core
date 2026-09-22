package sessiondb

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Fake is the in-memory MetadataStore for unit tests (no network rule).
// It mirrors procedure semantics: unknown id → session:not_found → 404.
type Fake struct {
	mu       sync.Mutex
	sessions map[string]*Session
	reports  map[string]json.RawMessage
	seq      int
}

// NewFake returns an empty in-memory MetadataStore.
func NewFake() *Fake {
	return &Fake{sessions: map[string]*Session{}, reports: map[string]json.RawMessage{}}
}

// Create stores a session, minting a fake 26-char id when none is supplied.
func (f *Fake) Create(_ context.Context, in CreateInput) (*Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	id := in.ID
	if id == "" {
		id = fmt.Sprintf("01JZXFAKE%017d", f.seq)
	}
	s := &Session{
		ID:            id,
		ClientID:      in.ClientID,
		CorrelationID: in.CorrelationID,
		Flow:          in.Flow,
		Status:        "pending",
		Policy:        in.Policy,
		WebhookURL:    in.WebhookURL,
		RedirectURI:   in.RedirectURI,
		ExpiresAt:     in.ExpiresAt,
	}
	if s.ExpiresAt.IsZero() {
		s.ExpiresAt = time.Now().Add(5 * time.Minute)
	}
	f.sessions[s.ID] = s
	cp := *s
	return &cp, nil
}

// Get returns a copy of the stored session, or a not-found (404) error.
func (f *Fake) Get(_ context.Context, id string) (*Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[id]
	if !ok {
		return nil, resultError("session:not_found")
	}
	cp := *s
	return &cp, nil
}

// SetStatus updates the stored session status, or returns not-found (404).
func (f *Fake) SetStatus(_ context.Context, id, status string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[id]
	if !ok {
		return resultError("session:not_found")
	}
	s.Status = status
	return nil
}

// SaveReport stores a copy of the report for id, or returns not-found (404).
func (f *Fake) SaveReport(_ context.Context, id string, report json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.sessions[id]; !ok {
		return resultError("session:not_found")
	}
	f.reports[id] = append(json.RawMessage(nil), report...)
	return nil
}

// Dump returns a JSON snapshot of every stored session row and report. It backs
// the verified-deletion canary (App.SessionDBFakeDump): reports hold
// check results and claim NAMES only, so the dump must contain no attribute
// VALUES.
func (f *Fake) Dump() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	snap := struct {
		Sessions map[string]*Session        `json:"sessions"`
		Reports  map[string]json.RawMessage `json:"reports"`
	}{Sessions: f.sessions, Reports: f.reports}
	b, err := json.Marshal(snap)
	if err != nil {
		return []byte(fmt.Sprintf(`{"dump_error":%q}`, err.Error()))
	}
	return b
}

// GetReport returns a copy of the stored report for id, or not-found (404).
func (f *Fake) GetReport(_ context.Context, id string) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.reports[id]
	if !ok {
		return nil, resultError("session:not_found")
	}
	return append(json.RawMessage(nil), r...), nil
}
