package domain

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

// ErrInvalidAuditCursor is returned when an audit cursor cannot be decoded.
var ErrInvalidAuditCursor = errors.New("invalid audit cursor")

// AuditEventFilter selects audit events by object, action, request, and time.
// All fields are optional; a zero value means the condition is not applied.
type AuditEventFilter struct {
	EntityType string
	EntityID   string
	Action     string
	RequestKey string
	From       time.Time
	To         time.Time
}

// AuditPageMeta carries pagination state for audit responses.
type AuditPageMeta struct {
	Limit      int    `json:"limit"`
	NextCursor string `json:"next_cursor,omitempty"`
	ExportID   string `json:"export_id,omitempty"`
}

// AuditEventPage is one page of audit events returned by a query.
type AuditEventPage struct {
	Items []AuditEvent  `json:"items"`
	Meta  AuditPageMeta `json:"meta"`
}

// AuditExport is a controlled, fingerprinted export of audit events.
// The fingerprint covers every matching event in the snapshot, not just
// the current page, so the client can verify the complete export.
type AuditExport struct {
	Fingerprint string        `json:"fingerprint"`
	TotalCount  int           `json:"total_count"`
	Items       []AuditEvent  `json:"items"`
	Meta        AuditPageMeta `json:"meta"`
}

// auditCursor is the keyset pagination key. Sorting by (at, id) gives a
// stable total order that survives restarts because both fields are
// immutable values from the event itself.
type auditCursor struct {
	At time.Time `json:"at"`
	ID string    `json:"id"`
}

// EncodeAuditCursor encodes the sort key into a stable, URL-safe cursor.
func EncodeAuditCursor(at time.Time, id string) string {
	payload, _ := json.Marshal(auditCursor{At: at.UTC(), ID: id})
	return base64.RawURLEncoding.EncodeToString(payload)
}

// DecodeAuditCursor decodes a cursor previously produced by EncodeAuditCursor.
// An empty cursor returns a zero key (start from the beginning).
func DecodeAuditCursor(value string) (time.Time, string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, "", nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return time.Time{}, "", ErrInvalidAuditCursor
	}
	var cursor auditCursor
	if err := json.Unmarshal(payload, &cursor); err != nil {
		return time.Time{}, "", ErrInvalidAuditCursor
	}
	return cursor.At, cursor.ID, nil
}

// SortAuditEvents sorts events by (at ascending, id ascending). This is the
// fixed sort order used for both queries and exports.
func SortAuditEvents(events []AuditEvent) {
	sort.Slice(events, func(i, j int) bool {
		if !events[i].At.Equal(events[j].At) {
			return events[i].At.Before(events[j].At)
		}
		return events[i].ID < events[j].ID
	})
}

// FilterAuditEvents returns the events that match the filter. The input slice
// is not modified. Request-key filtering reads the request_key attribute that
// is stored on events produced by idempotent operations.
func FilterAuditEvents(events []AuditEvent, filter AuditEventFilter) []AuditEvent {
	result := make([]AuditEvent, 0, len(events))
	for _, event := range events {
		if filter.EntityType != "" && event.EntityType != filter.EntityType {
			continue
		}
		if filter.EntityID != "" && event.EntityID != filter.EntityID {
			continue
		}
		if filter.Action != "" && event.Action != filter.Action {
			continue
		}
		if filter.RequestKey != "" {
			value, ok := event.Attributes["request_key"]
			if !ok || value != filter.RequestKey {
				continue
			}
		}
		if !filter.From.IsZero() && event.At.Before(filter.From) {
			continue
		}
		if !filter.To.IsZero() && event.At.After(filter.To) {
			continue
		}
		result = append(result, event)
	}
	return result
}

// ApplyAuditCursor returns the events strictly after the cursor in the fixed
// sort order. Events at or before the cursor are skipped.
func ApplyAuditCursor(events []AuditEvent, afterAt time.Time, afterID string) []AuditEvent {
	if afterID == "" {
		return events
	}
	result := make([]AuditEvent, 0, len(events))
	for _, event := range events {
		if event.At.Before(afterAt) || (event.At.Equal(afterAt) && event.ID <= afterID) {
			continue
		}
		result = append(result, event)
	}
	return result
}

// AuditFingerprint computes a stable content fingerprint over the events. The
// events must already be sorted by SortAuditEvents. The fingerprint is a
// SHA-256 hash of the canonical JSON encoding, which is deterministic across
// restarts.
func AuditFingerprint(events []AuditEvent) string {
	payload, _ := json.Marshal(events)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
