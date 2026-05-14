package tcpguard

import "time"

type RetentionPolicy struct {
	IncidentsTTL time.Duration
	AuditTTL     time.Duration
	ApprovalsTTL time.Duration
	MaxIncidents int64
	MaxAudit     int64
	MaxApprovals int64
}

func DefaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{
		IncidentsTTL: 30 * 24 * time.Hour,
		AuditTTL:     30 * 24 * time.Hour,
		ApprovalsTTL: 30 * 24 * time.Hour,
		MaxIncidents: 10000,
		MaxAudit:     10000,
		MaxApprovals: 10000,
	}
}
