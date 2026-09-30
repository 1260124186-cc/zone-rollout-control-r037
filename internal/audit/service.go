package audit

import (
	"context"
	"sync"
	"time"

	"solo-0014-zone-rollout-control/internal/domain"
	"solo-0014-zone-rollout-control/internal/platform"
	"solo-0014-zone-rollout-control/internal/store"
)

const (
	defaultQueryLimit  = 50
	maxQueryLimit      = 100
	defaultExportLimit = 100
	maxExportLimit     = 1000
	exportTTL          = time.Hour
)

// Service provides read-only audit queries and controlled exports. Reads never
// modify audit or business state. Exports capture a snapshot at creation time
// so every page of an export references the same read point.
type Service struct {
	store    *store.Store
	clock    platform.Clock
	ids      platform.IDGenerator
	registry *exportRegistry
}

// New creates an audit service.
func New(stateStore *store.Store, clock platform.Clock, ids platform.IDGenerator) *Service {
	return &Service{
		store:    stateStore,
		clock:    clock,
		ids:      ids,
		registry: &exportRegistry{exports: make(map[string]exportEntry)},
	}
}

// Query returns one page of audit events matching the filter. The read is
// performed under a single read lock, so the page is internally consistent.
// Query does not modify any state.
func (s *Service) Query(
	ctx context.Context,
	filter domain.AuditEventFilter,
	limit int,
	cursor string,
) (domain.AuditEventPage, error) {
	if limit < 1 || limit > maxQueryLimit {
		return domain.AuditEventPage{}, domain.Validation("limit must be between 1 and 100", map[string]any{
			"limit": limit,
		})
	}
	if !filter.From.IsZero() && !filter.To.IsZero() && filter.From.After(filter.To) {
		return domain.AuditEventPage{}, domain.Validation("from must not be after to", map[string]any{
			"from": filter.From,
			"to":   filter.To,
		})
	}
	afterAt, afterID, err := domain.DecodeAuditCursor(cursor)
	if err != nil {
		return domain.AuditEventPage{}, domain.Validation("cursor is invalid", nil)
	}
	var page domain.AuditEventPage
	err = s.store.Read(ctx, func(state *domain.State) error {
		events := copyAuditEvents(state.AuditEvents)
		events = domain.FilterAuditEvents(events, filter)
		domain.SortAuditEvents(events)
		events = domain.ApplyAuditCursor(events, afterAt, afterID)
		page.Meta.Limit = limit
		if len(events) > limit {
			page.Items = append(page.Items, events[:limit]...)
			last := events[limit-1]
			page.Meta.NextCursor = domain.EncodeAuditCursor(last.At, last.ID)
		} else {
			page.Items = append(page.Items, events...)
		}
		return nil
	})
	return page, err
}

// StartExport creates a controlled export. It captures a snapshot of the audit
// events at this read point, computes the content fingerprint over every
// matching event, and returns the first page plus an export identifier.
// Subsequent pages are served from the same snapshot.
func (s *Service) StartExport(
	ctx context.Context,
	filter domain.AuditEventFilter,
	limit int,
) (domain.AuditExport, error) {
	if limit < 1 || limit > maxExportLimit {
		return domain.AuditExport{}, domain.Validation("limit must be between 1 and 1000", map[string]any{
			"limit": limit,
		})
	}
	if !filter.From.IsZero() && !filter.To.IsZero() && filter.From.After(filter.To) {
		return domain.AuditExport{}, domain.Validation("from must not be after to", map[string]any{
			"from": filter.From,
			"to":   filter.To,
		})
	}
	var export domain.AuditExport
	err := s.store.Read(ctx, func(state *domain.State) error {
		events := copyAuditEvents(state.AuditEvents)
		events = domain.FilterAuditEvents(events, filter)
		domain.SortAuditEvents(events)
		fingerprint := domain.AuditFingerprint(events)
		exportID := s.ids.New("exp")
		s.registry.store(exportID, events, s.clock.Now())
		export = domain.AuditExport{
			Fingerprint: fingerprint,
			TotalCount:  len(events),
			Meta: domain.AuditPageMeta{
				Limit:    limit,
				ExportID: exportID,
			},
		}
		if len(events) > limit {
			export.Items = append(export.Items, events[:limit]...)
			last := events[limit-1]
			export.Meta.NextCursor = domain.EncodeAuditCursor(last.At, last.ID)
		} else {
			export.Items = append(export.Items, events...)
		}
		return nil
	})
	return export, err
}

// ExportPage returns a subsequent page of an export. The page is served from
// the snapshot captured when the export was started, so it references the same
// read point. The fingerprint is recomputed over the full snapshot and returned
// on every page so the client can verify consistency.
func (s *Service) ExportPage(
	ctx context.Context,
	exportID string,
	cursor string,
	limit int,
) (domain.AuditExport, error) {
	if err := ctx.Err(); err != nil {
		return domain.AuditExport{}, err
	}
	if limit < 1 || limit > maxExportLimit {
		return domain.AuditExport{}, domain.Validation("limit must be between 1 and 1000", map[string]any{
			"limit": limit,
		})
	}
	events, ok := s.registry.get(exportID)
	if !ok {
		return domain.AuditExport{}, domain.NotFound("export", exportID)
	}
	afterAt, afterID, err := domain.DecodeAuditCursor(cursor)
	if err != nil {
		return domain.AuditExport{}, domain.Validation("cursor is invalid", nil)
	}
	// The fingerprint and total count cover the full snapshot, not just the
	// current page, so the client can verify the complete export.
	fingerprint := domain.AuditFingerprint(events)
	totalCount := len(events)
	pageEvents := domain.ApplyAuditCursor(events, afterAt, afterID)
	export := domain.AuditExport{
		Fingerprint: fingerprint,
		TotalCount:  totalCount,
		Meta: domain.AuditPageMeta{
			Limit:    limit,
			ExportID: exportID,
		},
	}
	if len(pageEvents) > limit {
		export.Items = append(export.Items, pageEvents[:limit]...)
		last := pageEvents[limit-1]
		export.Meta.NextCursor = domain.EncodeAuditCursor(last.At, last.ID)
	} else {
		export.Items = append(export.Items, pageEvents...)
	}
	return export, nil
}

// copyAuditEvents returns a detached copy of the audit events slice so the
// caller can filter and sort without touching the stored state.
func copyAuditEvents(source []domain.AuditEvent) []domain.AuditEvent {
	events := make([]domain.AuditEvent, len(source))
	copy(events, source)
	return events
}

// exportEntry holds the snapshot for one export.
type exportEntry struct {
	events    []domain.AuditEvent
	createdAt time.Time
}

// exportRegistry stores export snapshots in memory. Exports are bounded in
// count by a TTL; after restart the registry is empty and in-progress exports
// cannot be resumed, though the cursor and fingerprint formats remain stable.
type exportRegistry struct {
	mu      sync.Mutex
	exports map[string]exportEntry
}

func (r *exportRegistry) store(id string, events []domain.AuditEvent, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.exports[id] = exportEntry{events: events, createdAt: now}
	r.cleanupLocked(now)
}

func (r *exportRegistry) get(id string) ([]domain.AuditEvent, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.exports[id]
	if !ok {
		return nil, false
	}
	return entry.events, true
}

func (r *exportRegistry) cleanupLocked(now time.Time) {
	cutoff := now.Add(-exportTTL)
	for id, entry := range r.exports {
		if entry.createdAt.Before(cutoff) {
			delete(r.exports, id)
		}
	}
}
