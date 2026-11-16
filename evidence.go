package tcpguard

import "hash/maphash"

var evidenceHashSeed = maphash.MakeSeed()

func buildEvidence(sec *Context, results []RuleResult, findings []Finding) []Evidence {
	// Most evidence items come directly from matched rules and findings. Reserve
	// that common-case capacity up front to avoid repeated slice growth and
	// copying on policies with many matches.
	out := make([]Evidence, 0, len(results)+len(findings))
	seen := newEvidenceSet(len(results) + len(findings))
	for _, result := range results {
		if result.Rule != nil {
			out = appendEvidenceUnique(out, seen, Evidence{Type: "matched_rule", ID: result.Rule.ID, Message: ruleDisplayName(result.Rule)})
		}
		if result.Authz != nil {
			out = appendEvidenceUnique(out, seen, Evidence{
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
		out = appendEvidenceUnique(out, seen, Evidence{Type: "finding", ID: finding.ID, Message: finding.Message, Fields: finding.Fields})
	}
	if sec != nil {
		if sec.Facts != nil {
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
				out = appendEvidenceUnique(out, seen, Evidence{Type: "threat_intel", ID: "network.ip.blacklisted", Message: "IP matched threat intelligence", Fields: fields})
			}
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
				out = appendEvidenceUnique(out, seen, Evidence{Type: "lookup", ID: failure.Lookup.ID, Message: "datasource lookup fallback applied", Fields: fields})
			}
		}
		for entity, raw := range sec.Rate {
			if values, ok := raw.(map[string]any); ok && values["requests"] != nil {
				out = appendEvidenceUnique(out, seen, Evidence{Type: "rate", ID: entity, Message: "rate counter updated", Fields: values})
			}
		}
	}
	return out
}

type evidenceSlot struct {
	hash  uint64
	index int
}

type evidenceSet struct {
	slots []evidenceSlot
	used  int
}

func newEvidenceSet(expected int) *evidenceSet {
	size := 8
	for size < expected*2 {
		size <<= 1
	}
	return &evidenceSet{slots: make([]evidenceSlot, size)}
}

func (s *evidenceSet) add(out []Evidence, evidence Evidence) bool {
	hash := hashEvidence(evidence)
	for {
		mask := len(s.slots) - 1
		position := int(hash & uint64(mask))
		for {
			slot := &s.slots[position]
			if slot.index == 0 {
				if (s.used+1)*10 >= len(s.slots)*7 {
					s.grow()
					break
				}
				slot.hash = hash
				slot.index = len(out) + 1
				s.used++
				return true
			}
			if slot.hash == hash && sameEvidenceKey(out[slot.index-1], evidence) {
				return false
			}
			position = (position + 1) & mask
		}
	}
}

func (s *evidenceSet) grow() {
	old := s.slots
	s.slots = make([]evidenceSlot, len(old)*2)
	mask := len(s.slots) - 1
	for _, slot := range old {
		if slot.index == 0 {
			continue
		}
		position := int(slot.hash & uint64(mask))
		for s.slots[position].index != 0 {
			position = (position + 1) & mask
		}
		s.slots[position] = slot
	}
}

func hashEvidence(evidence Evidence) uint64 {
	var hash maphash.Hash
	hash.SetSeed(evidenceHashSeed)
	_, _ = hash.WriteString(evidence.Type)
	_, _ = hash.WriteString("\x00")
	_, _ = hash.WriteString(evidence.ID)
	_, _ = hash.WriteString("\x00")
	_, _ = hash.WriteString(evidence.Message)
	return hash.Sum64()
}

func sameEvidenceKey(left, right Evidence) bool {
	return left.Type == right.Type && left.ID == right.ID && left.Message == right.Message
}

func appendEvidenceUnique(out []Evidence, seen *evidenceSet, evidence Evidence) []Evidence {
	if seen.add(out, evidence) {
		return append(out, evidence)
	}
	return out
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
