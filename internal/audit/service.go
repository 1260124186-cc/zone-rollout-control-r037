package audit

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash"

	"solo-0014-zone-rollout-control/internal/domain"
	"solo-0014-zone-rollout-control/internal/platform"
	"solo-0014-zone-rollout-control/internal/store"
)

// writeFingerprintEvent folds one event into a streaming set hash using the
// same length-prefixed JSON encoding as domain.AuditSetFingerprint, so the
// streamed digest equals the materialized one.
func writeFingerprintEvent(hasher hash.Hash, event domain.AuditEvent) {
	payload, _ := json.Marshal(event)
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(payload)))
	hasher.Write(length[:])
	hasher.Write(payload)
}

const (
	// Order is the only supported audit ordering: sequence ascending.
	Order = "seq"

	maxLimit = 100
)

type Service struct {
	store *store.Store
	clock platform.Clock
}

func New(stateStore *store.Store, clock platform.Clock) *Service {
	return &Service{store: stateStore, clock: clock}
}

// Query is a strictly read-only, fixed-order (seq ascending), cursor
// paginated audit search. It never opens a write transaction.
func (s *Service) Query(
	ctx context.Context,
	filter domain.AuditFilter,
	limit int,
	cursor string,
) (domain.AuditPage, error) {
	if limit < 1 || limit > maxLimit {
		return domain.AuditPage{}, domain.Validation("limit must be between 1 and 100", map[string]any{
			"limit": limit,
		})
	}
	after, err := decodeQueryCursor(cursor)
	if err != nil {
		return domain.AuditPage{}, domain.Validation("cursor is invalid", nil)
	}
	filterFingerprint := domain.AuditFilterFingerprint(filter)
	if cursor != "" && after.FilterFingerprint != filterFingerprint {
		return domain.AuditPage{}, domain.Validation("cursor does not match the request filter", map[string]any{
			"cursor": cursor,
		})
	}

	var page domain.AuditPage
	page.Items = []domain.AuditEvent{}
	err = s.store.Read(ctx, func(state *domain.State) error {
		items := make([]domain.AuditEvent, 0, limit)
		for _, event := range state.AuditEvents {
			if event.Seq <= after.Seq {
				continue
			}
			if !matches(event, filter) {
				continue
			}
			items = append(items, event)
			if len(items) == limit+1 {
				break
			}
		}
		page.Meta.Limit = limit
		page.Meta.StateRevision = state.Revision
		page.Meta.Order = Order
		page.Meta.Filter = filter.View()
		if len(items) > limit {
			page.Items = append(page.Items, items[:limit]...)
			page.Meta.NextCursor = encodeQueryCursor(queryCursor{
				Seq:               items[limit-1].Seq,
				FilterFingerprint: filterFingerprint,
			})
		} else {
			page.Items = append(page.Items, items...)
		}
		page.Meta.ContentFingerprint = domain.AuditSetFingerprint(page.Items)
		return nil
	})
	return page, err
}

// CreateExport pins the current filter result set to one read point. It is
// read-only: it opens a single read transaction, computes the full result-set
// fingerprint in one streaming pass, and returns a self-contained export
// token. No state is written and no state revision is consumed.
func (s *Service) CreateExport(
	ctx context.Context,
	filter domain.AuditFilter,
) (domain.AuditExportRef, string, error) {
	var ref domain.AuditExportRef
	err := s.store.Read(ctx, func(state *domain.State) error {
		hasher := sha256.New()
		count := 0
		lastSeq := uint64(0)
		for _, event := range state.AuditEvents {
			lastSeq = event.Seq
			if !matches(event, filter) {
				continue
			}
			writeFingerprintEvent(hasher, event)
			count++
		}
		ref = domain.AuditExportRef{
			StateRevision:      state.Revision,
			LastSeq:            lastSeq,
			Filter:             filter.View(),
			ContentFingerprint: hex.EncodeToString(hasher.Sum(nil)),
			EventCount:         count,
			CreatedAt:          s.clock.Now().UTC(),
		}
		return nil
	})
	if err != nil {
		return domain.AuditExportRef{}, "", err
	}
	token, err := encodeExportToken(exportToken{
		Ref:   ref,
		Query: filter,
		After: 0,
	})
	if err != nil {
		return domain.AuditExportRef{}, "", domain.NewError(domain.CodeInternal, "could not encode export token", nil)
	}
	return ref, token, nil
}

// ExportPage returns one page of a pinned export. The pinned set's
// fingerprint is re-verified in one bounded-memory streaming pass over the
// export's (last seq, filter) boundary, so every page demonstrably references
// the same read point even after restart or later writes. Only the page's
// events (at most limit+1) are held in memory.
func (s *Service) ExportPage(
	ctx context.Context,
	token string,
	limit int,
) (domain.AuditExportPage, string, error) {
	if limit < 1 || limit > maxLimit {
		return domain.AuditExportPage{}, "", domain.Validation("limit must be between 1 and 100", map[string]any{
			"limit": limit,
		})
	}
	export, err := decodeExportToken(token)
	if err != nil {
		return domain.AuditExportPage{}, "", domain.Validation("export token is invalid", nil)
	}

	var page domain.AuditExportPage
	var nextToken string
	page.Items = []domain.AuditEvent{}
	err = s.store.Read(ctx, func(state *domain.State) error {
		hasher := sha256.New()
		matchedCount := 0
		items := make([]domain.AuditEvent, 0, limit+1)
		for _, event := range state.AuditEvents {
			if event.Seq > export.Ref.LastSeq {
				break
			}
			if !matches(event, export.Query) {
				continue
			}
			writeFingerprintEvent(hasher, event)
			matchedCount++
			if event.Seq > export.After && len(items) <= limit {
				items = append(items, event)
			}
		}
		// Audit events are append-only and immutable; a mismatch means the
		// token was altered or produced against different data.
		if hex.EncodeToString(hasher.Sum(nil)) != export.Ref.ContentFingerprint ||
			matchedCount != export.Ref.EventCount {
			return domain.NewError(domain.CodeExportMismatch, "export no longer matches its pinned read point", map[string]any{
				"state_revision": export.Ref.StateRevision,
			})
		}

		page.Meta.Limit = limit
		page.Meta.Order = Order
		page.Meta.Export = export.Ref
		if len(items) > limit {
			page.Items = append(page.Items, items[:limit]...)
			export.After = items[limit-1].Seq
			encoded, encodeErr := encodeExportToken(export)
			if encodeErr != nil {
				return domain.NewError(domain.CodeInternal, "could not encode export cursor", nil)
			}
			nextToken = encoded
		} else {
			page.Items = append(page.Items, items...)
		}
		page.Meta.NextCursor = nextToken
		page.Meta.ContentFingerprint = domain.AuditSetFingerprint(page.Items)
		return nil
	})
	return page, nextToken, err
}

func matches(event domain.AuditEvent, filter domain.AuditFilter) bool {
	if filter.EntityType != "" && event.EntityType != filter.EntityType {
		return false
	}
	if filter.EntityID != "" && event.EntityID != filter.EntityID {
		return false
	}
	if filter.Action != "" && event.Action != filter.Action {
		return false
	}
	if filter.RequestKey != "" && event.RequestKey != filter.RequestKey {
		return false
	}
	if !filter.From.IsZero() && event.At.Before(filter.From) {
		return false
	}
	if !filter.To.IsZero() && event.At.After(filter.To) {
		return false
	}
	return true
}

// queryCursor is the self-contained live-query cursor. It carries no server
// session state, so its interpretation is stable across restarts.
type queryCursor struct {
	Seq               uint64 `json:"seq"`
	FilterFingerprint string `json:"filter_fingerprint"`
}

const queryCursorPrefix = "zrc-audit-query-v1:"

func encodeQueryCursor(cursor queryCursor) string {
	payload, _ := json.Marshal(cursor)
	return platform.EncodeCursor(queryCursorPrefix + string(payload))
}

func decodeQueryCursor(value string) (queryCursor, error) {
	var cursor queryCursor
	if value == "" {
		return cursor, nil
	}
	raw, err := platform.DecodeCursor(value)
	if err != nil {
		return cursor, err
	}
	if len(raw) <= len(queryCursorPrefix) || raw[:len(queryCursorPrefix)] != queryCursorPrefix {
		return cursor, platform.ErrInvalidCursor
	}
	if err := json.Unmarshal([]byte(raw[len(queryCursorPrefix):]), &cursor); err != nil {
		return cursor, platform.ErrInvalidCursor
	}
	return cursor, nil
}

// exportToken is the self-contained export reference and page cursor. It
// embeds the frozen filter and complete-set fingerprint, so restart does not
// change how the export is read.
type exportToken struct {
	Ref   domain.AuditExportRef `json:"ref"`
	Query domain.AuditFilter    `json:"query"`
	After uint64                `json:"after"`
}

const exportTokenPrefix = "zrc-audit-export-v1:"

func encodeExportToken(token exportToken) (string, error) {
	payload, err := json.Marshal(token)
	if err != nil {
		return "", err
	}
	return platform.EncodeCursor(exportTokenPrefix + string(payload)), nil
}

func decodeExportToken(value string) (exportToken, error) {
	var token exportToken
	raw, err := platform.DecodeCursor(value)
	if err != nil {
		return token, err
	}
	if len(raw) <= len(exportTokenPrefix) || raw[:len(exportTokenPrefix)] != exportTokenPrefix {
		return token, platform.ErrInvalidCursor
	}
	if err := json.Unmarshal([]byte(raw[len(exportTokenPrefix):]), &token); err != nil {
		return token, platform.ErrInvalidCursor
	}
	if token.Ref.ContentFingerprint == "" || token.Ref.CreatedAt.IsZero() {
		return token, platform.ErrInvalidCursor
	}
	return token, nil
}
