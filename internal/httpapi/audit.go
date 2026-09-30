package httpapi

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"solo-0014-zone-rollout-control/internal/domain"
)

// auditQueryParams are the only query parameters accepted by the audit query
// endpoint. Any other parameter is rejected so unknown filters fail explicitly.
var auditQueryParams = map[string]bool{
	"entity_type": true,
	"entity_id":   true,
	"action":      true,
	"request_key": true,
	"from":        true,
	"to":          true,
	"limit":       true,
	"cursor":      true,
}

// exportQueryParams are the only query parameters accepted by the export
// endpoint. The first request uses filters; subsequent requests use export_id
// and cursor.
var exportQueryParams = map[string]bool{
	"entity_type": true,
	"entity_id":   true,
	"action":      true,
	"request_key": true,
	"from":        true,
	"to":          true,
	"limit":       true,
	"cursor":      true,
	"export_id":   true,
}

func (s *Server) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	if err := rejectUnknownParams(r, auditQueryParams); err != nil {
		sendError(w, r, err)
		return
	}
	filter, err := parseAuditFilter(r)
	if err != nil {
		sendError(w, r, err)
		return
	}
	limit, err := parseAuditLimit(r, 50)
	if err != nil {
		sendError(w, r, err)
		return
	}
	page, err := s.audit.Query(r.Context(), filter, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		sendError(w, r, err)
		return
	}
	sendData(w, r, http.StatusOK, page)
}

func (s *Server) exportAuditEvents(w http.ResponseWriter, r *http.Request) {
	if err := rejectUnknownParams(r, exportQueryParams); err != nil {
		sendError(w, r, err)
		return
	}
	limit, err := parseAuditLimit(r, 100)
	if err != nil {
		sendError(w, r, err)
		return
	}
	exportID := strings.TrimSpace(r.URL.Query().Get("export_id"))
	if exportID == "" {
		filter, err := parseAuditFilter(r)
		if err != nil {
			sendError(w, r, err)
			return
		}
		export, err := s.audit.StartExport(r.Context(), filter, limit)
		if err != nil {
			sendError(w, r, err)
			return
		}
		sendData(w, r, http.StatusOK, export)
		return
	}
	cursor := r.URL.Query().Get("cursor")
	page, err := s.audit.ExportPage(r.Context(), exportID, cursor, limit)
	if err != nil {
		sendError(w, r, err)
		return
	}
	sendData(w, r, http.StatusOK, page)
}

// rejectUnknownParams returns a validation error if the request contains any
// query parameter not in the known set. This makes unknown filters fail
// explicitly instead of being silently ignored.
func rejectUnknownParams(r *http.Request, known map[string]bool) error {
	unknown := make([]string, 0)
	for param := range r.URL.Query() {
		if !known[param] {
			unknown = append(unknown, param)
		}
	}
	if len(unknown) > 0 {
		return domain.Validation("unknown query parameter is not supported", map[string]any{
			"unknown": unknown,
		})
	}
	return nil
}

// parseAuditFilter reads the filter fields from the query string. Time fields
// must be RFC3339 timestamps.
func parseAuditFilter(r *http.Request) (domain.AuditEventFilter, error) {
	query := r.URL.Query()
	filter := domain.AuditEventFilter{
		EntityType: strings.TrimSpace(query.Get("entity_type")),
		EntityID:   strings.TrimSpace(query.Get("entity_id")),
		Action:     strings.TrimSpace(query.Get("action")),
		RequestKey: strings.TrimSpace(query.Get("request_key")),
	}
	if raw := strings.TrimSpace(query.Get("from")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return filter, domain.Validation("from must be an RFC3339 timestamp", map[string]any{"from": raw})
		}
		filter.From = parsed.UTC()
	}
	if raw := strings.TrimSpace(query.Get("to")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return filter, domain.Validation("to must be an RFC3339 timestamp", map[string]any{"to": raw})
		}
		filter.To = parsed.UTC()
	}
	return filter, nil
}

// parseAuditLimit reads the limit parameter. If absent, defaultValue is used.
func parseAuditLimit(r *http.Request, defaultValue int) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if raw == "" {
		return defaultValue, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return 0, domain.Validation("limit must be an integer", map[string]any{"limit": raw})
	}
	return parsed, nil
}
