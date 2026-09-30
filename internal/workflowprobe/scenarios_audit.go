package workflowprobe

import (
	"fmt"
	"net/http"
	"net/url"

	"solo-0014-zone-rollout-control/internal/domain"
)

// tamperToken flips one character of the opaque token while keeping it a
// syntactically possible base64 value.
func tamperToken(token string) string {
	if token == "" {
		return token
	}
	last := token[len(token)-1]
	replacement := byte('A')
	switch last {
	case 'A':
		replacement = 'B'
	case 'B':
		replacement = 'C'
	default:
		replacement = 'A'
	}
	return token[:len(token)-1] + string(replacement)
}

type auditPage struct {
	Items []domain.AuditEvent `json:"items"`
	Meta  struct {
		Limit              int    `json:"limit"`
		NextCursor         string `json:"next_cursor"`
		StateRevision      uint64 `json:"state_revision"`
		Order              string `json:"order"`
		ContentFingerprint string `json:"content_fingerprint"`
		Filter             struct {
			EntityType string `json:"entity_type"`
		} `json:"filter"`
	} `json:"meta"`
}

type auditExportManifestResponse struct {
	Export domain.AuditExportRef `json:"export"`
	Token  string                `json:"token"`
}

type auditExportPageResponse struct {
	Items []domain.AuditEvent        `json:"items"`
	Meta  domain.AuditExportPageMeta `json:"meta"`
}

func runAuditQueryExport() error {
	harness, err := newHarness()
	if err != nil {
		return err
	}
	defer harness.close()

	// Produce a known audit stream:
	// node enrolled, plan created, revision added, plan activated,
	// lease group created (request key), probe stored (request key),
	// assessment completed (request key).
	node, err := enrollNode(harness, "resolver-audit-01", "audit-region")
	if err != nil {
		return err
	}
	plan, revision, err := createActivePlan(harness, "audit.example", 2049, 1, 1, 50)
	if err != nil {
		return err
	}
	group, err := allocate(harness, plan.ID, "audit-lease-0001", "audit-region", 1)
	if err != nil {
		return err
	}
	leaseID := group.LeaseIDs[0]
	if _, err := submitProbe(harness, leaseID, "audit-probe-0001", true, revision.Serial, 9); err != nil {
		return err
	}
	var assessment domain.RolloutAssessment
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/assessments", domain.AssessmentInput{
		RequestKey: "audit-assess-0001",
	}, &assessment); err != nil {
		return err
	}
	// Finish the plan lifecycle so the plan object accumulates created,
	// activated and completed audit events.
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/complete", map[string]any{
		"expected_version": 4,
	}, &plan); err != nil {
		return err
	}

	// 1. Unfiltered read returns the full stream in fixed seq ascending
	// order with stable sequence numbers.
	var first auditPage
	if err := harness.call(http.MethodGet, "/v1/audit/events?limit=20", nil, &first); err != nil {
		return err
	}
	if err := ensure(len(first.Items) == 8, fmt.Sprintf("expected 8 audit events, got %d", len(first.Items))); err != nil {
		return err
	}
	for index, event := range first.Items {
		if err := ensure(event.Seq == uint64(index+1), "audit events must be ordered by ascending seq"); err != nil {
			return err
		}
		if err := ensure(event.RequestKey != "" || event.EntityType != "lease_group", "request key must be recorded for keyed writes"); err != nil {
			return err
		}
	}
	if first.Meta.Order != "seq" || first.Meta.NextCursor != "" {
		return ensure(false, "audit page must declare seq order and no cursor when fully contained")
	}
	if first.Meta.ContentFingerprint == "" {
		return ensure(false, "audit page must carry a content fingerprint")
	}

	// 2. Stable filters: object, action, request key, entity type.
	var byObject auditPage
	if err := harness.call(http.MethodGet, "/v1/audit/events?entity_id="+url.QueryEscape(plan.ID)+"&limit=20", nil, &byObject); err != nil {
		return err
	}
	if err := ensure(len(byObject.Items) == 3, "entity_id filter should return plan events"); err != nil {
		return err
	}
	for _, event := range byObject.Items {
		if event.EntityID != plan.ID {
			return ensure(false, "entity_id filter must be exact")
		}
	}
	var byAction auditPage
	if err := harness.call(http.MethodGet, "/v1/audit/events?action=stored&limit=20", nil, &byAction); err != nil {
		return err
	}
	if len(byAction.Items) != 1 || byAction.Items[0].EntityType != "probe" {
		return ensure(false, "action filter should return one probe event")
	}
	var byRequestKey auditPage
	if err := harness.call(http.MethodGet, "/v1/audit/events?request_key=audit-probe-0001&limit=20", nil, &byRequestKey); err != nil {
		return err
	}
	if len(byRequestKey.Items) != 1 || byRequestKey.Items[0].RequestKey != "audit-probe-0001" {
		return ensure(false, "request_key filter must be exact")
	}
	var byType auditPage
	if err := harness.call(http.MethodGet, "/v1/audit/events?entity_type=node&limit=20", nil, &byType); err != nil {
		return err
	}
	if len(byType.Items) != 1 || byType.Items[0].EntityID != node.ID {
		return ensure(false, "entity_type filter must be exact")
	}

	// 3. Time bounds. Everything happened at one fixed instant.
	at := first.Items[0].At
	instant := at.Format("2006-01-02T15:04:05Z")
	var within auditPage
	if err := harness.call(http.MethodGet, "/v1/audit/events?from="+url.QueryEscape(instant)+"&to="+url.QueryEscape(instant)+"&limit=20", nil, &within); err != nil {
		return err
	}
	if len(within.Items) != 8 {
		return ensure(false, "inclusive from/to bounds must contain all events at that instant")
	}
	later := at.Add(60 * 1e9).Format("2006-01-02T15:04:05Z")
	var before auditPage
	if err := harness.call(http.MethodGet, "/v1/audit/events?to="+url.QueryEscape(at.Add(-1*1e9).Format("2006-01-02T15:04:05Z"))+"&limit=20", nil, &before); err != nil {
		return err
	}
	if len(before.Items) != 0 {
		return ensure(false, "to bound must exclude later events")
	}
	// from strictly after to must be rejected.
	if err := harness.call(http.MethodGet, "/v1/audit/events?from="+url.QueryEscape(later)+"&to="+url.QueryEscape(instant)+"&limit=20", nil, &auditPage{}); err == nil {
		return ensure(false, "from after to must fail")
	} else if err := expectFailure(err, http.StatusBadRequest, string(domain.CodeValidationFailed)); err != nil {
		return err
	}
	if err := harness.call(http.MethodGet, "/v1/audit/events?from=not-a-time", nil, &auditPage{}); err == nil {
		return ensure(false, "malformed timestamp must fail")
	} else if err := expectFailure(err, http.StatusBadRequest, string(domain.CodeValidationFailed)); err != nil {
		return err
	}

	// 4. Unknown filter conditions fail explicitly instead of being ignored.
	if err := harness.call(http.MethodGet, "/v1/audit/events?bogus=1", nil, &auditPage{}); err == nil {
		return ensure(false, "unknown query parameter must fail")
	} else if err := expectFailure(err, http.StatusBadRequest, string(domain.CodeValidationFailed)); err != nil {
		return err
	}
	if err := harness.call(http.MethodGet, "/v1/audit/events?limit=0", nil, &auditPage{}); err == nil {
		return ensure(false, "limit below range must fail")
	} else if err := expectFailure(err, http.StatusBadRequest, string(domain.CodeValidationFailed)); err != nil {
		return err
	}
	if err := harness.call(http.MethodGet, "/v1/audit/events?limit=101", nil, &auditPage{}); err == nil {
		return ensure(false, "limit above range must fail")
	} else if err := expectFailure(err, http.StatusBadRequest, string(domain.CodeValidationFailed)); err != nil {
		return err
	}

	// 5. Cursor pagination never puts the whole stream in one response and
	// concatenates back to the full fixed-order stream.
	var collected []domain.AuditEvent
	var cursor string
	pageCount := 0
	for {
		path := "/v1/audit/events?limit=2"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		var page auditPage
		if err := harness.call(http.MethodGet, path, nil, &page); err != nil {
			return err
		}
		if len(page.Items) > 2 {
			return ensure(false, "page must not exceed its limit")
		}
		collected = append(collected, page.Items...)
		pageCount++
		cursor = page.Meta.NextCursor
		if cursor == "" {
			break
		}
		if pageCount > 6 {
			return ensure(false, "pagination did not terminate")
		}
	}
	if pageCount != 4 || len(collected) != 8 {
		return ensure(false, fmt.Sprintf("expected 4 pages covering 8 events, got %d pages and %d events", pageCount, len(collected)))
	}
	for index, event := range collected {
		if event.Seq != uint64(index+1) {
			return ensure(false, "paginated events must reconstruct seq order without gaps or duplicates")
		}
	}

	// A cursor must not be reused with a different filter.
	var paged auditPage
	if err := harness.call(http.MethodGet, "/v1/audit/events?limit=2", nil, &paged); err != nil {
		return err
	}
	if paged.Meta.NextCursor == "" {
		return ensure(false, "expected a next cursor")
	}
	if err := harness.call(http.MethodGet, "/v1/audit/events?limit=2&action=stored&cursor="+url.QueryEscape(paged.Meta.NextCursor), nil, &auditPage{}); err == nil {
		return ensure(false, "cursor reused with another filter must fail")
	} else if err := expectFailure(err, http.StatusBadRequest, string(domain.CodeValidationFailed)); err != nil {
		return err
	}
	if err := harness.call(http.MethodGet, "/v1/audit/events?cursor=***not-base64", nil, &auditPage{}); err == nil {
		return ensure(false, "malformed cursor must fail")
	} else if err := expectFailure(err, http.StatusBadRequest, string(domain.CodeValidationFailed)); err != nil {
		return err
	}

	// 6. Controlled export references one read point via a self-contained
	// token, and every page repeats that reference.
	var manifest auditExportManifestResponse
	if err := harness.call(http.MethodPut, "/v1/audit/exports?entity_type=plan", nil, &manifest); err != nil {
		return err
	}
	if manifest.Token == "" || manifest.Export.ContentFingerprint == "" {
		return ensure(false, "export must return a token and full-set fingerprint")
	}
	if manifest.Export.EventCount != 3 {
		return ensure(false, fmt.Sprintf("export manifest must pin the filtered count, got %d", manifest.Export.EventCount))
	}
	revisionAtExport := manifest.Export.StateRevision

	var exportEvents []domain.AuditEvent
	token := manifest.Token
	pageCount = 0
	for {
		var page auditExportPageResponse
		if err := harness.call(http.MethodGet, "/v1/audit/exports?export="+url.QueryEscape(token)+"&limit=2", nil, &page); err != nil {
			return err
		}
		if page.Meta.ContentFingerprint == "" {
			return ensure(false, "every export page must carry a content fingerprint")
		}
		if page.Meta.Export.StateRevision != revisionAtExport ||
			page.Meta.Export.ContentFingerprint != manifest.Export.ContentFingerprint ||
			page.Meta.Export.LastSeq != manifest.Export.LastSeq ||
			page.Meta.Export.EventCount != manifest.Export.EventCount {
			return ensure(false, "every export page must reference the same pinned read point")
		}
		exportEvents = append(exportEvents, page.Items...)
		token = page.Meta.NextCursor
		pageCount++
		if token == "" {
			break
		}
		if pageCount > 3 {
			return ensure(false, "export pagination did not terminate")
		}
	}
	if pageCount != 2 || len(exportEvents) != 3 {
		return ensure(false, "export pages must cover exactly the pinned plan events")
	}
	for _, event := range exportEvents {
		if event.EntityType != "plan" {
			return ensure(false, "export must honor its frozen filter")
		}
	}
	// Unknown parameters are rejected on export paging and creation.
	if err := harness.call(http.MethodGet, "/v1/audit/exports?export="+url.QueryEscape(manifest.Token)+"&entity_type=plan", nil, &auditExportPageResponse{}); err == nil {
		return ensure(false, "export paging must reject filter parameters")
	} else if err := expectFailure(err, http.StatusBadRequest, string(domain.CodeValidationFailed)); err != nil {
		return err
	}
	if err := harness.call(http.MethodPut, "/v1/audit/exports?surprise=1", nil, &auditExportManifestResponse{}); err == nil {
		return ensure(false, "export creation must reject unknown parameters")
	} else if err := expectFailure(err, http.StatusBadRequest, string(domain.CodeValidationFailed)); err != nil {
		return err
	}
	if err := harness.call(http.MethodGet, "/v1/audit/exports", nil, &auditExportPageResponse{}); err == nil {
		return ensure(false, "export paging without a token must fail")
	} else if err := expectFailure(err, http.StatusBadRequest, string(domain.CodeValidationFailed)); err != nil {
		return err
	}

	// 7. Mutations after export do not change the pinned export: new events
	// land past last_seq, and later pages still verify the pinned set.
	node2, err := enrollNode(harness, "resolver-audit-02", "audit-region")
	if err != nil {
		return err
	}
	if node2.ID == "" {
		return ensure(false, "second node should be created after export")
	}
	var exportAfter auditExportPageResponse
	if err := harness.call(http.MethodGet, "/v1/audit/exports?export="+url.QueryEscape(manifest.Token)+"&limit=20", nil, &exportAfter); err != nil {
		return err
	}
	if len(exportAfter.Items) != 3 || exportAfter.Meta.Export.EventCount != 3 {
		return ensure(false, "later writes must not appear in the pinned export")
	}

	// 8. Reads are strictly read-only. The live revision seen before the
	// export equals the export revision and the mutation is the only new
	// revision afterward.
	if first.Meta.StateRevision != revisionAtExport {
		return ensure(false, "export must pin the revision observed by live reads")
	}
	var liveAfter auditPage
	if err := harness.call(http.MethodGet, "/v1/audit/events?limit=20", nil, &liveAfter); err != nil {
		return err
	}
	if liveAfter.Meta.StateRevision != revisionAtExport+1 || len(liveAfter.Items) != 9 {
		return ensure(false, "only the node enrollment may advance state; queries and exports must not")
	}

	// 9. A tampered export token must be rejected.
	tampered := tamperToken(manifest.Token)
	if err := harness.call(http.MethodGet, "/v1/audit/exports?export="+url.QueryEscape(tampered)+"&limit=20", nil, &auditExportPageResponse{}); err == nil {
		return ensure(false, "tampered export token must fail")
	} else if failure, ok := err.(*apiFailure); !ok || (failure.Status != http.StatusBadRequest && failure.Status != http.StatusConflict) {
		return fmt.Errorf("tampered export token must be rejected, got %v", err)
	}

	// 10. Restart: the same live cursor and export token keep their meaning
	// against the persisted snapshot.
	liveCursor := paged.Meta.NextCursor
	if err := harness.restart(); err != nil {
		return err
	}
	var restartedPage auditPage
	if err := harness.call(http.MethodGet, "/v1/audit/events?limit=2&cursor="+url.QueryEscape(liveCursor), nil, &restartedPage); err != nil {
		return fmt.Errorf("live cursor must survive restart: %w", err)
	}
	if len(restartedPage.Items) == 0 {
		return ensure(false, "cursor should still return events after restart")
	}
	var restartedExport auditExportPageResponse
	if err := harness.call(http.MethodGet, "/v1/audit/exports?export="+url.QueryEscape(manifest.Token)+"&limit=20", nil, &restartedExport); err != nil {
		return fmt.Errorf("export token must survive restart: %w", err)
	}
	if len(restartedExport.Items) != 3 ||
		restartedExport.Meta.Export.ContentFingerprint != manifest.Export.ContentFingerprint {
		return ensure(false, "export must reproduce the same pinned set and fingerprint after restart")
	}
	var restartedAll auditPage
	if err := harness.call(http.MethodGet, "/v1/audit/events?limit=20", nil, &restartedAll); err != nil {
		return err
	}
	if len(restartedAll.Items) != 9 || restartedAll.Items[0].Seq != 1 || restartedAll.Items[8].Seq != 9 {
		return ensure(false, "seq ordering must remain stable after restart")
	}
	return nil
}
