package sessiondb

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Fixed procedure names (see call()).
const (
	procCreate     = "session.create_session"
	procGet        = "session.get_session"
	procSetStatus  = "session.set_status"
	procSaveReport = "session.save_report"
	procGetReport  = "session.get_report"
)

// Session is a session-metadata row as projected by session.get_session. It
// carries structure and identifiers only — never verified attribute values.
// Policy is the per-client snapshot.
type Session struct {
	ID            string          `json:"id"`
	ClientID      string          `json:"client_id"`
	CorrelationID string          `json:"correlation_id"`
	Flow          string          `json:"flow"`
	Status        string          `json:"status"`
	Policy        json.RawMessage `json:"policy"`
	WebhookURL    string          `json:"webhook_url"`
	RedirectURI   string          `json:"redirect_uri"`
	ExpiresAt     time.Time       `json:"expires_at"`
}

// CreateInput is the argument to Create. ID is optional: when set, the
// oid4vp engine's session id is reused so one id names the session in Valkey,
// Postgres, and the wallet URL; when empty the schema mints a ULID.
type CreateInput struct {
	ID            string          `json:"id,omitempty"` // optional: engine-minted id (one id everywhere)
	ClientID      string          `json:"client_id"`
	CorrelationID string          `json:"correlation_id"`
	Flow          string          `json:"flow"`
	Policy        json.RawMessage `json:"policy"`
	WebhookURL    string          `json:"webhook_url"`
	RedirectURI   string          `json:"redirect_uri,omitempty"`
	ExpiresAt     time.Time       `json:"expires_at"`
}

// MetadataStore is the seam unit tests fake (fake.go) and prod backs with pg.
type MetadataStore interface {
	Create(ctx context.Context, in CreateInput) (*Session, error)
	Get(ctx context.Context, id string) (*Session, error)
	SetStatus(ctx context.Context, id, status string) error
	SaveReport(ctx context.Context, id string, report json.RawMessage) error
	GetReport(ctx context.Context, id string) (json.RawMessage, error)
}

// PG is the production MetadataStore: it calls the session-schema procedures
// through the pgx pool (never raw table SQL).
type PG struct{ pool *pgxpool.Pool }

// NewPG returns a PG-backed MetadataStore over pool.
func NewPG(pool *pgxpool.Pool) *PG { return &PG{pool: pool} }

// Create inserts a session via session.create_session and returns the stored row.
func (p *PG) Create(ctx context.Context, in CreateInput) (*Session, error) {
	data, err := call(ctx, p.pool, procCreate, in)
	if err != nil {
		return nil, err
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return p.Get(ctx, out.ID)
}

// Get returns the session via session.get_session (err:session:not-found → 404).
func (p *PG) Get(ctx context.Context, id string) (*Session, error) {
	data, err := call(ctx, p.pool, procGet, map[string]string{"id": id})
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// SetStatus updates the session status via session.set_status (unknown id or
// invalid status rolls back with a structured P0001 error).
func (p *PG) SetStatus(ctx context.Context, id, status string) error {
	_, err := call(ctx, p.pool, procSetStatus, map[string]string{"id": id, "status": status})
	return err
}

// SaveReport appends a verification report via session.save_report. The report
// holds CheckResults and claim NAMES only — never attribute values.
func (p *PG) SaveReport(ctx context.Context, id string, report json.RawMessage) error {
	_, err := call(ctx, p.pool, procSaveReport, map[string]any{"session_id": id, "report": report})
	return err
}

// GetReport returns the latest verification report via session.get_report.
func (p *PG) GetReport(ctx context.Context, id string) (json.RawMessage, error) {
	data, err := call(ctx, p.pool, procGetReport, map[string]string{"session_id": id})
	if err != nil {
		return nil, err
	}
	var out struct {
		Report json.RawMessage `json:"report"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out.Report, nil
}
