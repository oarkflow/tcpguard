package tcpguard

func buildEvidence(sec *Context, results []RuleResult, findings []Finding) []Evidence {
	var out []Evidence
	seen := map[string]bool{}
	for _, result := range results {
		if result.Rule != nil {
			out = appendEvidence(out, seen, Evidence{Type: "matched_rule", ID: result.Rule.ID, Message: ruleDisplayName(result.Rule)})
		}
		if result.Authz != nil {
			out = appendEvidence(out, seen, Evidence{
				Type:    "authz",
				ID:      firstNonEmpty(result.Rule.AuthzPolicy, result.Rule.ID),
				Message: firstNonEmpty(result.Authz.Reason, result.Authz.MatchedBy),
				Fields: map[string]any{
					"provider":   result.Authz.Provider,
					"allowed":    result.Authz.Allowed,
					"matched_by": result.Authz.MatchedBy,
					"trace":      result.Authz.Trace,
				},
			})
		}
	}
	for _, finding := range findings {
		out = appendEvidence(out, seen, Evidence{Type: "finding", ID: finding.ID, Message: finding.Message, Fields: finding.Fields})
	}
	if sec != nil {
		if value, ok := sec.Facts.Get("network.ip.blacklisted"); ok && value == true {
			fields := map[string]any{"ip": sec.Network.IP}
			if source, ok := sec.Facts.Get("threat.intel.source"); ok {
				fields["source"] = source
			}
			if matchType, ok := sec.Facts.Get("threat.intel.match_type"); ok {
				fields["match_type"] = matchType
			}
			if confidence, ok := sec.Facts.Get("threat.intel.confidence"); ok {
				fields["confidence"] = confidence
			}
			out = appendEvidence(out, seen, Evidence{Type: "threat_intel", ID: "network.ip.blacklisted", Message: "IP matched threat intelligence", Fields: fields})
		}
		if sec.lookup != nil {
			sec.lookup.mu.Lock()
			failures := append([]LookupFailure(nil), sec.lookup.failures...)
			sec.lookup.mu.Unlock()
			for _, failure := range failures {
				fields := map[string]any{"source": failure.Lookup.Source, "policy": failure.Lookup.Fallback.Policy}
				if failure.Err != nil {
					fields["error"] = failure.Err.Error()
				}
				out = appendEvidence(out, seen, Evidence{Type: "lookup", ID: failure.Lookup.ID, Message: "datasource lookup fallback applied", Fields: fields})
			}
		}
		for entity, raw := range sec.Rate {
			if values, ok := raw.(map[string]any); ok && values["requests"] != nil {
				out = appendEvidence(out, seen, Evidence{Type: "rate", ID: entity, Message: "rate counter updated", Fields: values})
			}
		}
	}
	return out
}

func appendEvidence(out []Evidence, seen map[string]bool, evidence Evidence) []Evidence {
	key := evidence.Type + "\x00" + evidence.ID + "\x00" + evidence.Message
	if seen[key] {
		return out
	}
	seen[key] = true
	return append(out, evidence)
}

func evidenceIDs(evidence []Evidence) []string {
	out := make([]string, 0, len(evidence))
	for _, item := range evidence {
		if item.ID != "" {
			out = append(out, item.Type+":"+item.ID)
		} else if item.Message != "" {
			out = append(out, item.Type+":"+item.Message)
		}
	}
	return out
}
