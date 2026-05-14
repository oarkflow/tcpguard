package tcpguard

import "strings"

const refArgSep = "\x1f"

func encodeRefArgs(args []string) string {
	return strings.Join(args, refArgSep)
}

func decodeRefArgs(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, refArgSep)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, strings.TrimSpace(part))
	}
	return out
}
