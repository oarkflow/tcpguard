package tcpguard

import (
	"net/http"
	"strconv"
	"time"
)

type PaginationQuery struct {
	Cursor string
	Limit  int
	After  time.Time
	Before time.Time
}

type paginatedResponse[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

func parsePaginationQuery(r *http.Request, maxLimit int) PaginationQuery {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	if maxLimit > 0 && limit > maxLimit {
		limit = maxLimit
	}
	after := parseUnixOrRFC3339(q.Get("after"))
	before := parseUnixOrRFC3339(q.Get("before"))
	return PaginationQuery{
		Cursor: q.Get("cursor"),
		Limit:  limit,
		After:  after,
		Before: before,
	}
}

func parseUnixOrRFC3339(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return time.Unix(n, 0).UTC()
	}
	t, _ := time.Parse(time.RFC3339, raw)
	return t
}

func paginateItems[T any](in []T, q PaginationQuery, ts func(T) time.Time) paginatedResponse[T] {
	start := 0
	if q.Cursor != "" {
		if n, err := strconv.Atoi(q.Cursor); err == nil && n >= 0 && n < len(in) {
			start = n
		}
	}
	filtered := make([]T, 0, len(in))
	for _, item := range in {
		at := ts(item)
		if !q.After.IsZero() && !at.IsZero() && at.Before(q.After) {
			continue
		}
		if !q.Before.IsZero() && !at.IsZero() && at.After(q.Before) {
			continue
		}
		filtered = append(filtered, item)
	}
	if start >= len(filtered) {
		return paginatedResponse[T]{Items: []T{}}
	}
	end := start + q.Limit
	if end > len(filtered) {
		end = len(filtered)
	}
	out := paginatedResponse[T]{Items: filtered[start:end]}
	if end < len(filtered) {
		out.NextCursor = strconv.Itoa(end)
	}
	return out
}
