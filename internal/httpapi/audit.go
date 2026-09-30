package httpapi

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"solo-0014-zone-rollout-control/internal/domain"
)

// auditFilterParams is the explicit allow list of query dimensions. Any
// parameter outside this list is an unknown filter and must fail loudly
// rather than be silently ignored.
var auditFilterParams = map[string]struct{}{
	"entity_type": {},
	"entity_id":   {},
	"action":      {},
	"request_key": {},
	"from":        {},
	"to":          {},
}

const auditDefaultLimit = 50

func (s *Server) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	filter, err := parseAuditFilter(r.URL.Query())
	if err != nil {
		sendError(w, r, err)
		return
	}
	limit, err := parseAuditLimit(r.URL.Query())
	if err != nil {
		sendError(w, r, err)
		return
	}
	page, err := s.audit.Query(r.Context(), filter, limit, strings.TrimSpace(r.URL.Query().Get("cursor")))
	if err != nil {
		sendError(w, r, err)
		return
	}
	sendData(w, r, http.StatusOK, page)
}

func (s *Server) createAuditExport(w http.ResponseWriter, r *http.Request) {
	filter, err := parseAuditFilter(r.URL.Query())
	if err != nil {
		sendError(w, r, err)
		return
	}
	ref, token, err := s.audit.CreateExport(r.Context(), filter)
	if err != nil {
		sendError(w, r, err)
		return
	}
	// Read-only endpoint: the response carries the pinned read point and
	// the self-contained token used to page through the same export.
	sendData(w, r, http.StatusOK, auditExportManifest{
		Export: ref,
		Token:  token,
	})
}

func (s *Server) getAuditExportPage(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("export"))
	if token == "" {
		sendError(w, r, domain.Validation("export token is required", map[string]any{"export": ""}))
		return
	}
	if unknown := unknownAuditParams(r.URL.Query(), map[string]struct{}{
		"export": {},
		"limit":  {},
	}); len(unknown) > 0 {
		sendError(w, r, domain.Validation("unknown audit query parameters", map[string]any{
			"parameters": unknown,
		}))
		return
	}
	limit, err := parseAuditLimit(r.URL.Query())
	if err != nil {
		sendError(w, r, err)
		return
	}
	page, _, err := s.audit.ExportPage(r.Context(), token, limit)
	if err != nil {
		sendError(w, r, err)
		return
	}
	sendData(w, r, http.StatusOK, page)
}

type auditExportManifest struct {
	Export domain.AuditExportRef `json:"export"`
	Token  string                `json:"token"`
}

func parseAuditFilter(query url.Values) (domain.AuditFilter, error) {
	if unknown := unknownAuditParams(query, auditListAllowedParams); len(unknown) > 0 {
		return domain.AuditFilter{}, domain.Validation("unknown audit query parameters", map[string]any{
			"parameters": unknown,
		})
	}
	filter := domain.AuditFilter{
		EntityType: strings.TrimSpace(query.Get("entity_type")),
		EntityID:   strings.TrimSpace(query.Get("entity_id")),
		Action:     strings.TrimSpace(query.Get("action")),
		RequestKey: strings.TrimSpace(query.Get("request_key")),
	}
	if raw := strings.TrimSpace(query.Get("from")); raw != "" {
		from, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return domain.AuditFilter{}, domain.Validation("from must be an RFC3339 timestamp", map[string]any{"from": raw})
		}
		filter.From = from.UTC()
	}
	if raw := strings.TrimSpace(query.Get("to")); raw != "" {
		to, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return domain.AuditFilter{}, domain.Validation("to must be an RFC3339 timestamp", map[string]any{"to": raw})
		}
		filter.To = to.UTC()
	}
	if !filter.From.IsZero() && !filter.To.IsZero() && filter.From.After(filter.To) {
		return domain.AuditFilter{}, domain.Validation("from must not be after to", map[string]any{
			"from": query.Get("from"),
			"to":   query.Get("to"),
		})
	}
	return filter, nil
}

var auditListAllowedParams = func() map[string]struct{} {
	allowed := make(map[string]struct{}, len(auditFilterParams)+2)
	for name := range auditFilterParams {
		allowed[name] = struct{}{}
	}
	allowed["limit"] = struct{}{}
	allowed["cursor"] = struct{}{}
	return allowed
}()

func unknownAuditParams(query url.Values, allowed map[string]struct{}) []string {
	unknown := make([]string, 0)
	for name := range query {
		if _, ok := allowed[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	return unknown
}

func parseAuditLimit(query url.Values) (int, error) {
	limit := auditDefaultLimit
	if raw := strings.TrimSpace(query.Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return 0, domain.Validation("limit must be an integer", map[string]any{"limit": raw})
		}
		limit = parsed
	}
	if limit < 1 || limit > 100 {
		return 0, domain.Validation("limit must be between 1 and 100", map[string]any{"limit": limit})
	}
	return limit, nil
}
