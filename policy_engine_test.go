package tcpguard

import "testing"

func TestDefaultPolicyEngineNestedDSL(t *testing.T) {
	engine := NewDefaultPolicyEngine()
	err := engine.LoadPolicies([]Policy{
		{
			ID:       "admin-risk-deny",
			Name:     "Admin High Risk Deny",
			Schema:   "tcpguard.policy/v1",
			Layer:    PolicyEmergency,
			Priority: 100,
			Enabled:  true,
			Decision: Deny,
			Condition: &PolicyCondition{All: []PolicyCondition{
				{Field: "path", Operator: "glob", Value: "/admin/*"},
				{Field: "risk_score", Operator: "gte", Value: 0.8},
				{Any: []PolicyCondition{
					{Field: "signal.bruteForce", Operator: "gte", Value: 0.7},
					{Field: "client_ip", Operator: "cidr", Value: "10.0.0.0/8"},
				}},
				{Not: &PolicyCondition{Field: "header.X-Break-Glass", Operator: "eq", Value: "approved"}},
			}},
		},
	})
	if err != nil {
		t.Fatalf("LoadPolicies() error = %v", err)
	}

	verdict, err := engine.Evaluate(nil, &RiskRequest{
		IP:       "10.1.2.3",
		Endpoint: "/admin/users",
		Method:   "GET",
		Headers:  map[string]string{"X-Break-Glass": "missing"},
	}, []RiskSignal{{Name: "bruteForce", Score: 0.9}}, 0.91)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if verdict.Decision != Deny {
		t.Fatalf("Decision = %v, want Deny", verdict.Decision)
	}
	if verdict.MatchedPolicyID != "admin-risk-deny" {
		t.Fatalf("MatchedPolicyID = %q", verdict.MatchedPolicyID)
	}
	if len(verdict.Explanation) == 0 {
		t.Fatal("expected explainable verdict")
	}
}

func TestDefaultPolicyEngineDryRunAllowsButExplainsMatch(t *testing.T) {
	engine := NewDefaultPolicyEngine()
	err := engine.LoadPolicies([]Policy{
		{
			ID:       "shadow-deny",
			Name:     "Shadow Deny",
			Layer:    PolicyEmergency,
			Priority: 100,
			Enabled:  true,
			Decision: Deny,
			Mode:     "dry_run",
			Condition: &PolicyCondition{
				Field:    "risk_score",
				Operator: "gte",
				Value:    0.1,
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadPolicies() error = %v", err)
	}

	verdict, err := engine.Evaluate(nil, &RiskRequest{Endpoint: "/api", RouteTier: 0}, nil, 0.9)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if verdict.Decision != Allow {
		t.Fatalf("dry-run Decision = %v, want Allow", verdict.Decision)
	}
	if verdict.Mode != "dry_run" || verdict.Enforced {
		t.Fatalf("Mode/Enforced = %q/%v, want dry_run/false", verdict.Mode, verdict.Enforced)
	}
	if verdict.MatchedPolicyID != "shadow-deny" {
		t.Fatalf("MatchedPolicyID = %q", verdict.MatchedPolicyID)
	}
}

func TestDefaultPolicyEngineRejectsInvalidPolicies(t *testing.T) {
	tests := []struct {
		name     string
		policies []Policy
	}{
		{
			name: "duplicate ids",
			policies: []Policy{
				{ID: "dup", Enabled: true},
				{ID: "dup", Enabled: true},
			},
		},
		{
			name: "invalid regex",
			policies: []Policy{
				{
					ID:      "bad-regex",
					Enabled: true,
					Condition: &PolicyCondition{
						Field:    "path",
						Operator: "regex",
						Value:    "[",
					},
				},
			},
		},
		{
			name: "invalid cidr",
			policies: []Policy{
				{
					ID:      "bad-cidr",
					Enabled: true,
					Condition: &PolicyCondition{
						Field:    "client_ip",
						Operator: "cidr",
						Value:    "10.0.0.0/not-a-mask",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewDefaultPolicyEngine()
			if err := engine.LoadPolicies(tt.policies); err == nil {
				t.Fatal("LoadPolicies() error = nil, want error")
			}
		})
	}
}
