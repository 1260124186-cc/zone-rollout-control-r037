package store

import "solo-0014-zone-rollout-control/internal/domain"

const schemaVersion = 1

func blankState() domain.State {
	return normalize(domain.State{})
}

func normalize(state domain.State) domain.State {
	if state.SchemaVersion == 0 {
		state.SchemaVersion = schemaVersion
	}
	if state.Plans == nil {
		state.Plans = make(map[string]domain.RolloutPlan)
	}
	if state.Revisions == nil {
		state.Revisions = make(map[string]domain.ZoneRevision)
	}
	if state.Nodes == nil {
		state.Nodes = make(map[string]domain.ResolverNode)
	}
	if state.Leases == nil {
		state.Leases = make(map[string]domain.NodeLease)
	}
	if state.LeaseGroups == nil {
		state.LeaseGroups = make(map[string]domain.LeaseGroup)
	}
	if state.Probes == nil {
		state.Probes = make(map[string]domain.Probe)
	}
	if state.Assessments == nil {
		state.Assessments = make(map[string]domain.RolloutAssessment)
	}
	if state.LeaseRequestKeys == nil {
		state.LeaseRequestKeys = make(map[string]string)
	}
	if state.AssessmentRequestKeys == nil {
		state.AssessmentRequestKeys = make(map[string]string)
	}
	if state.AuditEvents == nil {
		state.AuditEvents = []domain.AuditEvent{}
	}
	// Backfill stable sequence numbers for snapshots written before the
	// audit stream carried seq. The on-disk slice order is append order, so
	// positional numbers reproduce the same fixed ordering after restart.
	if len(state.AuditEvents) > 0 && state.AuditEvents[0].Seq == 0 {
		for index := range state.AuditEvents {
			if state.AuditEvents[index].Seq == 0 {
				state.AuditEvents[index].Seq = uint64(index + 1)
			}
		}
	}
	return state
}
