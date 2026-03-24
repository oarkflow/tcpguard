package tcpguard

import (
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"strings"
)

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

// InjectionFinding represents a single injection detection result.
type InjectionFinding struct {
	Type           string `json:"type"`            // sql_injection, xss, command_injection, path_traversal, ldap_injection, nosql_injection, template_injection, header_injection
	Severity       string `json:"severity"`         // info, low, medium, high, critical
	Reason         string `json:"reason"`
	Location       string `json:"location"`         // query, body, header, path, cookie
	MatchedPattern string `json:"matched_pattern"`
	Field          string `json:"field,omitempty"`
}

// InjectionDetectionVerdict contains all detections for a single request evaluation.
type InjectionDetectionVerdict struct {
	Triggered bool               `json:"triggered"`
	Findings  []InjectionFinding `json:"findings"`
}

// injectionRuleParams holds JSON-configurable parameters for injection detection.
type injectionRuleParams struct {
	Types       map[string]InjectionTypeConfig `json:"types"`
	ScanTargets []string                       `json:"scanTargets"` // "query", "body", "headers", "path", "cookies"
	MaxBodyScan int                            `json:"maxBodyScan"`
	Allowlist   []string                       `json:"allowlist"`
	CustomRules []CustomInjectionRule          `json:"customRules"`
}

// InjectionTypeConfig allows per-type enable/disable/severity/custom patterns.
type InjectionTypeConfig struct {
	Enabled  *bool    `json:"enabled,omitempty"`
	Severity string   `json:"severity,omitempty"`
	Patterns []string `json:"patterns,omitempty"`
}

// CustomInjectionRule defines a user-supplied injection pattern.
type CustomInjectionRule struct {
	Name     string `json:"name"`
	Pattern  string `json:"pattern"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Location string `json:"location"`
}

// injectionPattern is an individual detection pattern.
type injectionPattern struct {
	Pattern  string
	Severity string
	Reason   string
}

// injectionTypeDefinition groups patterns for a given injection category.
type injectionTypeDefinition struct {
	DefaultSeverity string
	Patterns        []injectionPattern
}

// injectionMatch is an intermediate match result.
type injectionMatch struct {
	Pattern  string
	Severity string
	Reason   string
}

// ---------------------------------------------------------------------------
// Pattern definitions
// ---------------------------------------------------------------------------

var injectionDefinitions = map[string]injectionTypeDefinition{
	"sql_injection":       {DefaultSeverity: "critical", Patterns: sqlInjectionPatterns},
	"xss":                 {DefaultSeverity: "high", Patterns: xssPatterns},
	"command_injection":   {DefaultSeverity: "critical", Patterns: commandInjectionPatterns},
	"path_traversal":      {DefaultSeverity: "high", Patterns: pathTraversalPatterns},
	"ldap_injection":      {DefaultSeverity: "high", Patterns: ldapInjectionPatterns},
	"nosql_injection":     {DefaultSeverity: "high", Patterns: nosqlInjectionPatterns},
	"template_injection":  {DefaultSeverity: "high", Patterns: templateInjectionPatterns},
	"header_injection":    {DefaultSeverity: "critical", Patterns: headerInjectionPatterns},
}

var sqlInjectionPatterns = []injectionPattern{
	{Pattern: "union select", Severity: "critical", Reason: "UNION SELECT injection attempt"},
	{Pattern: "union all select", Severity: "critical", Reason: "UNION ALL SELECT injection attempt"},
	{Pattern: "' or '1'='1", Severity: "critical", Reason: "classic OR 1=1 injection attempt"},
	{Pattern: "' or 1=1", Severity: "critical", Reason: "OR 1=1 injection attempt"},
	{Pattern: "\" or 1=1", Severity: "critical", Reason: "OR 1=1 double-quote injection attempt"},
	{Pattern: "or 1=1--", Severity: "critical", Reason: "OR 1=1 with comment injection"},
	{Pattern: "' or ''='", Severity: "critical", Reason: "empty string tautology injection"},
	{Pattern: "1'; drop", Severity: "critical", Reason: "DROP statement injection attempt"},
	{Pattern: "'; drop", Severity: "critical", Reason: "DROP statement injection attempt"},
	{Pattern: "drop table", Severity: "critical", Reason: "DROP TABLE injection attempt"},
	{Pattern: "drop database", Severity: "critical", Reason: "DROP DATABASE injection attempt"},
	{Pattern: "alter table", Severity: "critical", Reason: "ALTER TABLE injection attempt"},
	{Pattern: "insert into", Severity: "high", Reason: "INSERT INTO injection attempt"},
	{Pattern: "delete from", Severity: "critical", Reason: "DELETE FROM injection attempt"},
	{Pattern: "update ", Severity: "medium", Reason: "UPDATE statement injection attempt"},
	{Pattern: "--", Severity: "medium", Reason: "SQL comment sequence detected"},
	{Pattern: "/*", Severity: "medium", Reason: "SQL block comment open detected"},
	{Pattern: "*/", Severity: "medium", Reason: "SQL block comment close detected"},
	{Pattern: "char(", Severity: "high", Reason: "CHAR() function injection attempt"},
	{Pattern: "chr(", Severity: "high", Reason: "CHR() function injection attempt"},
	{Pattern: "concat(", Severity: "medium", Reason: "CONCAT() function injection attempt"},
	{Pattern: "0x", Severity: "low", Reason: "hex encoding detected in input"},
	{Pattern: "waitfor delay", Severity: "critical", Reason: "WAITFOR DELAY time-based injection attempt"},
	{Pattern: "benchmark(", Severity: "critical", Reason: "BENCHMARK() time-based injection attempt"},
	{Pattern: "pg_sleep", Severity: "critical", Reason: "pg_sleep time-based injection attempt"},
	{Pattern: "sleep(", Severity: "high", Reason: "SLEEP() time-based injection attempt"},
	{Pattern: "exec ", Severity: "critical", Reason: "EXEC statement injection attempt"},
	{Pattern: "execute ", Severity: "critical", Reason: "EXECUTE statement injection attempt"},
	{Pattern: "xp_cmdshell", Severity: "critical", Reason: "xp_cmdshell execution attempt"},
	{Pattern: "xp_regread", Severity: "critical", Reason: "xp_regread registry access attempt"},
	{Pattern: "information_schema", Severity: "high", Reason: "information_schema enumeration attempt"},
	{Pattern: "sys.objects", Severity: "high", Reason: "sys.objects enumeration attempt"},
	{Pattern: "sys.columns", Severity: "high", Reason: "sys.columns enumeration attempt"},
	{Pattern: "sysobjects", Severity: "high", Reason: "sysobjects enumeration attempt"},
	{Pattern: "syscolumns", Severity: "high", Reason: "syscolumns enumeration attempt"},
	{Pattern: "load_file(", Severity: "critical", Reason: "LOAD_FILE() file read injection attempt"},
	{Pattern: "into outfile", Severity: "critical", Reason: "INTO OUTFILE file write injection attempt"},
	{Pattern: "into dumpfile", Severity: "critical", Reason: "INTO DUMPFILE file write injection attempt"},
	{Pattern: "group_concat(", Severity: "high", Reason: "GROUP_CONCAT() data extraction attempt"},
	{Pattern: "having ", Severity: "medium", Reason: "HAVING clause injection attempt"},
	{Pattern: "order by ", Severity: "low", Reason: "ORDER BY injection attempt"},
	{Pattern: "extractvalue(", Severity: "high", Reason: "EXTRACTVALUE() XML injection attempt"},
	{Pattern: "updatexml(", Severity: "high", Reason: "UPDATEXML() XML injection attempt"},
	{Pattern: "ascii(", Severity: "medium", Reason: "ASCII() blind injection attempt"},
	{Pattern: "substring(", Severity: "medium", Reason: "SUBSTRING() data extraction attempt"},
	{Pattern: "@@version", Severity: "high", Reason: "@@version server info disclosure attempt"},
}

var xssPatterns = []injectionPattern{
	{Pattern: "<script", Severity: "critical", Reason: "script tag injection attempt"},
	{Pattern: "</script>", Severity: "critical", Reason: "script closing tag injection"},
	{Pattern: "javascript:", Severity: "critical", Reason: "javascript: URI scheme injection"},
	{Pattern: "vbscript:", Severity: "critical", Reason: "vbscript: URI scheme injection"},
	{Pattern: "onerror=", Severity: "high", Reason: "onerror event handler injection"},
	{Pattern: "onload=", Severity: "high", Reason: "onload event handler injection"},
	{Pattern: "onclick=", Severity: "high", Reason: "onclick event handler injection"},
	{Pattern: "onmouseover=", Severity: "high", Reason: "onmouseover event handler injection"},
	{Pattern: "onfocus=", Severity: "high", Reason: "onfocus event handler injection"},
	{Pattern: "onblur=", Severity: "high", Reason: "onblur event handler injection"},
	{Pattern: "onsubmit=", Severity: "high", Reason: "onsubmit event handler injection"},
	{Pattern: "onchange=", Severity: "high", Reason: "onchange event handler injection"},
	{Pattern: "<img ", Severity: "medium", Reason: "img tag injection attempt"},
	{Pattern: "<svg", Severity: "high", Reason: "SVG tag injection attempt"},
	{Pattern: "<iframe", Severity: "critical", Reason: "iframe injection attempt"},
	{Pattern: "<object", Severity: "high", Reason: "object tag injection attempt"},
	{Pattern: "<embed", Severity: "high", Reason: "embed tag injection attempt"},
	{Pattern: "<form", Severity: "high", Reason: "form tag injection attempt"},
	{Pattern: "<body", Severity: "high", Reason: "body tag injection attempt"},
	{Pattern: "<input", Severity: "medium", Reason: "input tag injection attempt"},
	{Pattern: "expression(", Severity: "high", Reason: "CSS expression() injection attempt"},
	{Pattern: "eval(", Severity: "critical", Reason: "eval() code execution attempt"},
	{Pattern: "document.cookie", Severity: "critical", Reason: "document.cookie access attempt"},
	{Pattern: "document.write", Severity: "high", Reason: "document.write injection attempt"},
	{Pattern: "document.domain", Severity: "high", Reason: "document.domain manipulation attempt"},
	{Pattern: "window.location", Severity: "high", Reason: "window.location manipulation attempt"},
	{Pattern: "innerhtml", Severity: "high", Reason: "innerHTML manipulation attempt"},
	{Pattern: "outerhtml", Severity: "high", Reason: "outerHTML manipulation attempt"},
	{Pattern: "alert(", Severity: "high", Reason: "alert() call injection attempt"},
	{Pattern: "prompt(", Severity: "high", Reason: "prompt() call injection attempt"},
	{Pattern: "confirm(", Severity: "high", Reason: "confirm() call injection attempt"},
	{Pattern: "fromcharcode", Severity: "medium", Reason: "String.fromCharCode() obfuscation attempt"},
	{Pattern: "settimeout(", Severity: "medium", Reason: "setTimeout() injection attempt"},
	{Pattern: "setinterval(", Severity: "medium", Reason: "setInterval() injection attempt"},
	{Pattern: "atob(", Severity: "medium", Reason: "atob() base64 decode injection attempt"},
	{Pattern: "data:", Severity: "medium", Reason: "data: URI scheme injection attempt"},
	{Pattern: "constructor[", Severity: "high", Reason: "constructor property access (sandbox escape)"},
}

var commandInjectionPatterns = []injectionPattern{
	{Pattern: "|", Severity: "high", Reason: "pipe operator detected"},
	{Pattern: "`", Severity: "high", Reason: "backtick command substitution detected"},
	{Pattern: "$(", Severity: "high", Reason: "dollar-paren command substitution detected"},
	{Pattern: "; ", Severity: "medium", Reason: "semicolon command chaining detected"},
	{Pattern: "&&", Severity: "medium", Reason: "AND command chaining detected"},
	{Pattern: "||", Severity: "medium", Reason: "OR command chaining detected"},
	{Pattern: "/etc/passwd", Severity: "critical", Reason: "attempt to access /etc/passwd"},
	{Pattern: "/etc/shadow", Severity: "critical", Reason: "attempt to access /etc/shadow"},
	{Pattern: "/bin/sh", Severity: "critical", Reason: "attempt to invoke /bin/sh"},
	{Pattern: "/bin/bash", Severity: "critical", Reason: "attempt to invoke /bin/bash"},
	{Pattern: "cmd.exe", Severity: "critical", Reason: "attempt to invoke cmd.exe"},
	{Pattern: "powershell", Severity: "critical", Reason: "attempt to invoke PowerShell"},
	{Pattern: "curl ", Severity: "high", Reason: "curl command injection attempt"},
	{Pattern: "wget ", Severity: "high", Reason: "wget command injection attempt"},
	{Pattern: "> /", Severity: "high", Reason: "output redirection to absolute path"},
	{Pattern: ">> /", Severity: "high", Reason: "append redirection to absolute path"},
	{Pattern: "< /", Severity: "high", Reason: "input redirection from absolute path"},
	{Pattern: "2>&1", Severity: "medium", Reason: "stderr redirect detected"},
	{Pattern: "/dev/null", Severity: "medium", Reason: "redirect to /dev/null detected"},
	{Pattern: "nc ", Severity: "high", Reason: "netcat command injection attempt"},
	{Pattern: "ncat ", Severity: "high", Reason: "ncat command injection attempt"},
	{Pattern: "python ", Severity: "high", Reason: "python command injection attempt"},
	{Pattern: "perl ", Severity: "high", Reason: "perl command injection attempt"},
	{Pattern: "ruby ", Severity: "high", Reason: "ruby command injection attempt"},
	{Pattern: "chmod ", Severity: "high", Reason: "chmod command injection attempt"},
	{Pattern: "chown ", Severity: "high", Reason: "chown command injection attempt"},
	{Pattern: "cat /", Severity: "high", Reason: "cat with absolute path injection attempt"},
	{Pattern: "rm -", Severity: "critical", Reason: "rm command injection attempt"},
}

var pathTraversalPatterns = []injectionPattern{
	{Pattern: "../", Severity: "high", Reason: "relative path traversal (../) detected"},
	{Pattern: "..\\", Severity: "high", Reason: "relative path traversal (..\\ ) detected"},
	{Pattern: "%2e%2e%2f", Severity: "high", Reason: "URL-encoded path traversal (%2e%2e%2f) detected"},
	{Pattern: "%2e%2e/", Severity: "high", Reason: "partially URL-encoded path traversal detected"},
	{Pattern: "..%2f", Severity: "high", Reason: "partially URL-encoded path traversal (..%2f) detected"},
	{Pattern: "%2e%2e%5c", Severity: "high", Reason: "URL-encoded backslash traversal detected"},
	{Pattern: "%252e%252e", Severity: "high", Reason: "double URL-encoded path traversal detected"},
	{Pattern: "....//", Severity: "high", Reason: "double-dot-slash filter bypass traversal detected"},
	{Pattern: "/etc/passwd", Severity: "critical", Reason: "direct /etc/passwd access attempt"},
	{Pattern: "/etc/shadow", Severity: "critical", Reason: "direct /etc/shadow access attempt"},
	{Pattern: "/proc/self", Severity: "critical", Reason: "/proc/self access attempt"},
	{Pattern: "/proc/version", Severity: "high", Reason: "/proc/version access attempt"},
	{Pattern: "%00", Severity: "critical", Reason: "null byte injection detected"},
	{Pattern: "\\x00", Severity: "critical", Reason: "null byte (hex notation) injection detected"},
	{Pattern: "c:\\", Severity: "high", Reason: "Windows drive path traversal detected"},
	{Pattern: "c:/", Severity: "high", Reason: "Windows drive forward-slash path traversal detected"},
	{Pattern: "/var/log", Severity: "high", Reason: "attempt to access /var/log"},
	{Pattern: "boot.ini", Severity: "high", Reason: "Windows boot.ini access attempt"},
	{Pattern: "win.ini", Severity: "high", Reason: "Windows win.ini access attempt"},
}

var ldapInjectionPatterns = []injectionPattern{
	{Pattern: ")(", Severity: "high", Reason: "LDAP filter closing/opening injection"},
	{Pattern: "*)(", Severity: "high", Reason: "LDAP wildcard filter injection"},
	{Pattern: "*(|", Severity: "high", Reason: "LDAP wildcard OR injection"},
	{Pattern: "|(", Severity: "high", Reason: "LDAP OR filter injection"},
	{Pattern: "&(", Severity: "high", Reason: "LDAP AND filter injection"},
	{Pattern: "*)(objectclass=*", Severity: "critical", Reason: "LDAP objectClass wildcard enumeration"},
	{Pattern: "*(objectclass=*)", Severity: "critical", Reason: "LDAP full objectClass wildcard enumeration"},
	{Pattern: "*)(uid=*))(|(uid=*", Severity: "critical", Reason: "LDAP uid filter bypass injection"},
	{Pattern: ")(cn=", Severity: "high", Reason: "LDAP common name filter injection"},
	{Pattern: ")(sn=", Severity: "high", Reason: "LDAP surname filter injection"},
	{Pattern: ")(mail=", Severity: "high", Reason: "LDAP mail filter injection"},
}

var nosqlInjectionPatterns = []injectionPattern{
	{Pattern: "$gt", Severity: "high", Reason: "NoSQL $gt operator injection"},
	{Pattern: "$gte", Severity: "high", Reason: "NoSQL $gte operator injection"},
	{Pattern: "$lt", Severity: "high", Reason: "NoSQL $lt operator injection"},
	{Pattern: "$lte", Severity: "high", Reason: "NoSQL $lte operator injection"},
	{Pattern: "$ne", Severity: "high", Reason: "NoSQL $ne operator injection"},
	{Pattern: "$nin", Severity: "high", Reason: "NoSQL $nin operator injection"},
	{Pattern: "$in", Severity: "high", Reason: "NoSQL $in operator injection"},
	{Pattern: "$regex", Severity: "high", Reason: "NoSQL $regex operator injection"},
	{Pattern: "$where", Severity: "critical", Reason: "NoSQL $where operator injection (code execution)"},
	{Pattern: "$or", Severity: "high", Reason: "NoSQL $or operator injection"},
	{Pattern: "$and", Severity: "high", Reason: "NoSQL $and operator injection"},
	{Pattern: "$not", Severity: "high", Reason: "NoSQL $not operator injection"},
	{Pattern: "$exists", Severity: "medium", Reason: "NoSQL $exists operator injection"},
	{Pattern: "$type", Severity: "medium", Reason: "NoSQL $type operator injection"},
	{Pattern: ".find(", Severity: "critical", Reason: "NoSQL .find() method injection"},
	{Pattern: ".findone(", Severity: "critical", Reason: "NoSQL .findOne() method injection"},
	{Pattern: ".aggregate(", Severity: "critical", Reason: "NoSQL .aggregate() method injection"},
	{Pattern: ".update(", Severity: "critical", Reason: "NoSQL .update() method injection"},
	{Pattern: ".delete(", Severity: "critical", Reason: "NoSQL .delete() method injection"},
	{Pattern: ".drop(", Severity: "critical", Reason: "NoSQL .drop() method injection"},
	{Pattern: "db.collection", Severity: "high", Reason: "NoSQL db.collection access attempt"},
}

var templateInjectionPatterns = []injectionPattern{
	{Pattern: "{{", Severity: "high", Reason: "template double-brace injection (Go/Handlebars/Jinja2)"},
	{Pattern: "}}", Severity: "medium", Reason: "template double-brace closing detected"},
	{Pattern: "${", Severity: "high", Reason: "template dollar-brace injection (EL/JS template literals)"},
	{Pattern: "<%", Severity: "high", Reason: "template angle-bracket-percent injection (JSP/ERB/ASP)"},
	{Pattern: "%>", Severity: "medium", Reason: "template angle-bracket-percent closing detected"},
	{Pattern: "#{", Severity: "high", Reason: "template hash-brace injection (Ruby/Thymeleaf)"},
	{Pattern: "{%", Severity: "high", Reason: "template brace-percent injection (Jinja2/Django/Twig)"},
	{Pattern: "%}", Severity: "medium", Reason: "template brace-percent closing detected"},
	{Pattern: "__class__", Severity: "critical", Reason: "Python __class__ attribute access attempt"},
	{Pattern: "__import__", Severity: "critical", Reason: "Python __import__() call attempt"},
	{Pattern: "__builtins__", Severity: "critical", Reason: "Python __builtins__ access attempt"},
	{Pattern: "__subclasses__", Severity: "critical", Reason: "Python __subclasses__() traversal attempt"},
	{Pattern: "__globals__", Severity: "critical", Reason: "Python __globals__ access attempt"},
	{Pattern: "__mro__", Severity: "critical", Reason: "Python __mro__ access attempt"},
	{Pattern: "lipsum.__globals__", Severity: "critical", Reason: "Jinja2 lipsum globals access attempt"},
	{Pattern: "config.items()", Severity: "high", Reason: "Flask config.items() access attempt"},
	{Pattern: "request.application", Severity: "high", Reason: "template engine application object access attempt"},
	{Pattern: "{{constructor", Severity: "critical", Reason: "AngularJS sandbox escape attempt"},
}

var headerInjectionPatterns = []injectionPattern{
	{Pattern: "\r\n", Severity: "critical", Reason: "CRLF header injection detected"},
	{Pattern: "\r", Severity: "high", Reason: "CR header injection detected"},
	{Pattern: "\n", Severity: "high", Reason: "LF header injection detected"},
	{Pattern: "%0d%0a", Severity: "critical", Reason: "URL-encoded CRLF header injection detected"},
	{Pattern: "%0d", Severity: "high", Reason: "URL-encoded CR header injection detected"},
	{Pattern: "%0a", Severity: "high", Reason: "URL-encoded LF header injection detected"},
	{Pattern: "%e5%98%8a%e5%98%8d", Severity: "critical", Reason: "UTF-8 encoded CRLF injection detected"},
	{Pattern: "set-cookie:", Severity: "critical", Reason: "Set-Cookie header injection attempt"},
	{Pattern: "content-type:", Severity: "high", Reason: "Content-Type header injection attempt"},
	{Pattern: "location:", Severity: "high", Reason: "Location header injection attempt (open redirect)"},
	{Pattern: "x-forwarded-for:", Severity: "medium", Reason: "X-Forwarded-For header injection attempt"},
	{Pattern: "transfer-encoding:", Severity: "critical", Reason: "Transfer-Encoding header injection attempt (smuggling)"},
}

// ---------------------------------------------------------------------------
// Default scan targets and limits
// ---------------------------------------------------------------------------

var defaultScanTargets = []string{"query", "body", "headers", "path", "cookies"}

const defaultMaxBodyScan = 64 * 1024 // 64 KB

// ---------------------------------------------------------------------------
// Pipeline function
// ---------------------------------------------------------------------------

// InjectionDetectionCondition evaluates request content against all enabled
// injection detection patterns. It follows the same pipeline function pattern
// used by AdvancedDDoSCondition.
func InjectionDetectionCondition(ctx *Context) any {
	if ctx == nil || ctx.RuleEngine == nil || ctx.FiberCtx == nil {
		return false
	}

	params, err := parseInjectionRuleParams(ctx.Results)
	if err != nil {
		fmt.Printf("injection: failed to parse params: %v\n", err)
		return false
	}

	if params == nil {
		params = &injectionRuleParams{}
	}

	path := ctx.FiberCtx.Path()
	if injectionIsAllowlisted(path, params.Allowlist) {
		ctx.Results["injectionVerdict"] = InjectionDetectionVerdict{}
		return false
	}

	scanTargets := params.ScanTargets
	if len(scanTargets) == 0 {
		scanTargets = defaultScanTargets
	}

	maxBody := params.MaxBodyScan
	if maxBody <= 0 {
		maxBody = defaultMaxBodyScan
	}

	// Build the effective pattern sets per injection type.
	effectivePatterns := buildEffectivePatterns(params)

	var findings []InjectionFinding

	for _, target := range scanTargets {
		switch strings.ToLower(target) {
		case "query":
			findings = append(findings, scanQueryParams(ctx, effectivePatterns)...)
		case "body":
			findings = append(findings, scanBody(ctx, effectivePatterns, maxBody)...)
		case "headers":
			findings = append(findings, scanHeaders(ctx, effectivePatterns)...)
		case "path":
			findings = append(findings, scanPath(ctx, effectivePatterns)...)
		case "cookies":
			findings = append(findings, scanCookies(ctx, effectivePatterns)...)
		}
	}

	// Evaluate custom rules.
	findings = append(findings, evaluateCustomRules(ctx, params.CustomRules, scanTargets, maxBody)...)

	verdict := InjectionDetectionVerdict{
		Triggered: len(findings) > 0,
		Findings:  findings,
	}

	ctx.Results["injectionVerdict"] = verdict

	if verdict.Triggered && ctx.RuleEngine != nil && ctx.RuleEngine.metrics != nil {
		for _, f := range verdict.Findings {
			ctx.RuleEngine.metrics.IncrementCounter("injection_detection_total", map[string]string{
				"type":     f.Type,
				"severity": f.Severity,
				"location": f.Location,
			})
		}
	}

	return verdict.Triggered
}

// ---------------------------------------------------------------------------
// Parameter parsing
// ---------------------------------------------------------------------------

func parseInjectionRuleParams(results map[string]any) (*injectionRuleParams, error) {
	if results == nil {
		return &injectionRuleParams{}, nil
	}
	raw, err := json.Marshal(results)
	if err != nil {
		return nil, err
	}
	var params injectionRuleParams
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, err
	}
	return &params, nil
}

// ---------------------------------------------------------------------------
// Pattern building
// ---------------------------------------------------------------------------

type effectiveInjectionType struct {
	Severity string
	Patterns []injectionPattern
}

func buildEffectivePatterns(params *injectionRuleParams) map[string]effectiveInjectionType {
	effective := make(map[string]effectiveInjectionType, len(injectionDefinitions))

	for typeName, def := range injectionDefinitions {
		severity := def.DefaultSeverity
		patterns := make([]injectionPattern, len(def.Patterns))
		copy(patterns, def.Patterns)
		enabled := true

		if params != nil && params.Types != nil {
			if cfg, ok := params.Types[typeName]; ok {
				if cfg.Enabled != nil {
					enabled = *cfg.Enabled
				}
				if cfg.Severity != "" {
					severity = cfg.Severity
				}
				// Append additional user-supplied patterns.
				for _, p := range cfg.Patterns {
					if p == "" {
						continue
					}
					patterns = append(patterns, injectionPattern{
						Pattern:  p,
						Severity: severity,
						Reason:   fmt.Sprintf("custom pattern matched: %s", p),
					})
				}
			}
		}

		if !enabled {
			continue
		}

		effective[typeName] = effectiveInjectionType{
			Severity: severity,
			Patterns: patterns,
		}
	}

	return effective
}

// ---------------------------------------------------------------------------
// Scan functions
// ---------------------------------------------------------------------------

func scanQueryParams(ctx *Context, effectiveTypes map[string]effectiveInjectionType) []InjectionFinding {
	if ctx == nil || ctx.FiberCtx == nil {
		return nil
	}
	queries := ctx.FiberCtx.Queries()
	if len(queries) == 0 {
		return nil
	}
	var findings []InjectionFinding
	for field, value := range queries {
		if value == "" {
			continue
		}
		normalized := injectionNormalizeInput(value)
		for typeName, etype := range effectiveTypes {
			matches := injectionScanInput(normalized, etype.Patterns)
			for _, m := range matches {
				findings = append(findings, InjectionFinding{
					Type:           typeName,
					Severity:       injectionResolveSeverity(m.Severity, etype.Severity),
					Reason:         m.Reason,
					Location:       "query",
					MatchedPattern: m.Pattern,
					Field:          field,
				})
			}
		}
	}
	return findings
}

func scanBody(ctx *Context, effectiveTypes map[string]effectiveInjectionType, maxBytes int) []InjectionFinding {
	if ctx == nil || ctx.FiberCtx == nil {
		return nil
	}
	body := ctx.FiberCtx.Body()
	if len(body) == 0 {
		return nil
	}
	if maxBytes > 0 && len(body) > maxBytes {
		body = body[:maxBytes]
	}
	bodyStr := string(body)
	normalized := injectionNormalizeInput(bodyStr)
	var findings []InjectionFinding
	for typeName, etype := range effectiveTypes {
		matches := injectionScanInput(normalized, etype.Patterns)
		for _, m := range matches {
			findings = append(findings, InjectionFinding{
				Type:           typeName,
				Severity:       injectionResolveSeverity(m.Severity, etype.Severity),
				Reason:         m.Reason,
				Location:       "body",
				MatchedPattern: m.Pattern,
				Field:          "",
			})
		}
	}
	return findings
}

func scanHeaders(ctx *Context, effectiveTypes map[string]effectiveInjectionType) []InjectionFinding {
	if ctx == nil || ctx.FiberCtx == nil {
		return nil
	}
	headers := ctx.FiberCtx.GetReqHeaders()
	if len(headers) == 0 {
		return nil
	}

	// Skip scanning well-known safe headers to reduce false positives.
	skipHeaders := map[string]bool{
		"host":            true,
		"content-length":  true,
		"content-type":    true,
		"accept":          true,
		"accept-encoding": true,
		"accept-language": true,
		"connection":      true,
	}

	var findings []InjectionFinding
	for name, values := range headers {
		if skipHeaders[strings.ToLower(name)] {
			continue
		}
		for _, value := range values {
			if value == "" {
				continue
			}
			normalized := injectionNormalizeInput(value)
			for typeName, etype := range effectiveTypes {
				matches := injectionScanInput(normalized, etype.Patterns)
				for _, m := range matches {
					findings = append(findings, InjectionFinding{
						Type:           typeName,
						Severity:       injectionResolveSeverity(m.Severity, etype.Severity),
						Reason:         m.Reason,
						Location:       "header",
						MatchedPattern: m.Pattern,
						Field:          name,
					})
				}
			}
		}
	}
	return findings
}

func scanPath(ctx *Context, effectiveTypes map[string]effectiveInjectionType) []InjectionFinding {
	if ctx == nil || ctx.FiberCtx == nil {
		return nil
	}
	path := ctx.FiberCtx.Path()
	if path == "" || path == "/" {
		return nil
	}
	normalized := injectionNormalizeInput(path)
	var findings []InjectionFinding
	for typeName, etype := range effectiveTypes {
		matches := injectionScanInput(normalized, etype.Patterns)
		for _, m := range matches {
			findings = append(findings, InjectionFinding{
				Type:           typeName,
				Severity:       injectionResolveSeverity(m.Severity, etype.Severity),
				Reason:         m.Reason,
				Location:       "path",
				MatchedPattern: m.Pattern,
				Field:          path,
			})
		}
	}
	return findings
}

func scanCookies(ctx *Context, effectiveTypes map[string]effectiveInjectionType) []InjectionFinding {
	if ctx == nil || ctx.FiberCtx == nil {
		return nil
	}
	cookieHeader := ctx.FiberCtx.Get("Cookie")
	if cookieHeader == "" {
		return nil
	}
	cookies := injectionParseCookieHeader(cookieHeader)
	var findings []InjectionFinding
	for name, value := range cookies {
		if value == "" {
			continue
		}
		normalized := injectionNormalizeInput(value)
		for typeName, etype := range effectiveTypes {
			matches := injectionScanInput(normalized, etype.Patterns)
			for _, m := range matches {
				findings = append(findings, InjectionFinding{
					Type:           typeName,
					Severity:       injectionResolveSeverity(m.Severity, etype.Severity),
					Reason:         m.Reason,
					Location:       "cookie",
					MatchedPattern: m.Pattern,
					Field:          name,
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Custom rule evaluation
// ---------------------------------------------------------------------------

func evaluateCustomRules(ctx *Context, rules []CustomInjectionRule, scanTargets []string, maxBody int) []InjectionFinding {
	if ctx == nil || ctx.FiberCtx == nil || len(rules) == 0 {
		return nil
	}

	var findings []InjectionFinding

	for _, rule := range rules {
		if rule.Pattern == "" {
			continue
		}
		severity := rule.Severity
		if severity == "" {
			severity = "medium"
		}
		ruleType := rule.Type
		if ruleType == "" {
			ruleType = "custom"
		}

		pat := injectionPattern{
			Pattern:  rule.Pattern,
			Severity: severity,
			Reason:   fmt.Sprintf("custom rule '%s' matched", rule.Name),
		}
		pats := []injectionPattern{pat}

		locations := resolveCustomRuleLocations(rule.Location, scanTargets)
		for _, loc := range locations {
			var inputs map[string]string
			switch loc {
			case "query":
				inputs = ctx.FiberCtx.Queries()
			case "body":
				body := ctx.FiberCtx.Body()
				if maxBody > 0 && len(body) > maxBody {
					body = body[:maxBody]
				}
				if len(body) > 0 {
					inputs = map[string]string{"": string(body)}
				}
			case "headers":
				headerMap := ctx.FiberCtx.GetReqHeaders()
				inputs = make(map[string]string, len(headerMap))
				for k, v := range headerMap {
					if len(v) > 0 {
						inputs[k] = v[0]
					}
				}
			case "path":
				inputs = map[string]string{"": ctx.FiberCtx.Path()}
			case "cookies":
				inputs = injectionParseCookieHeader(ctx.FiberCtx.Get("Cookie"))
			}

			for field, value := range inputs {
				if value == "" {
					continue
				}
				normalized := injectionNormalizeInput(value)
				matches := injectionScanInput(normalized, pats)
				for _, m := range matches {
					findings = append(findings, InjectionFinding{
						Type:           ruleType,
						Severity:       m.Severity,
						Reason:         m.Reason,
						Location:       loc,
						MatchedPattern: m.Pattern,
						Field:          field,
					})
				}
			}
		}
	}

	return findings
}

func resolveCustomRuleLocations(location string, scanTargets []string) []string {
	if location == "" || location == "*" || location == "all" {
		return scanTargets
	}
	return []string{strings.ToLower(location)}
}

// ---------------------------------------------------------------------------
// Core scanning helpers
// ---------------------------------------------------------------------------

// injectionScanInput checks the normalized input against each pattern and returns all matches.
func injectionScanInput(input string, patterns []injectionPattern) []injectionMatch {
	if input == "" || len(patterns) == 0 {
		return nil
	}
	var matches []injectionMatch
	lower := strings.ToLower(input)
	for _, p := range patterns {
		if p.Pattern == "" {
			continue
		}
		patLower := strings.ToLower(p.Pattern)
		if strings.Contains(lower, patLower) {
			matches = append(matches, injectionMatch{
				Pattern:  p.Pattern,
				Severity: p.Severity,
				Reason:   p.Reason,
			})
		}
	}
	return matches
}

// injectionNormalizeInput decodes URL encoding and HTML entities, then returns the
// result for case-insensitive matching. Multiple decoding passes handle
// double-encoding attacks.
func injectionNormalizeInput(input string) string {
	if input == "" {
		return ""
	}

	// First pass: URL decode.
	decoded, err := url.QueryUnescape(input)
	if err != nil {
		decoded = input
	}

	// Second pass: catch double-encoding.
	if decoded2, err := url.QueryUnescape(decoded); err == nil && decoded2 != decoded {
		decoded = decoded2
	}

	// Decode HTML entities.
	decoded = html.UnescapeString(decoded)

	// Collapse excessive whitespace to catch evasion.
	decoded = injectionCollapseWhitespace(decoded)

	return decoded
}

// injectionCollapseWhitespace reduces runs of multiple spaces/tabs into a single space.
func injectionCollapseWhitespace(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	prevSpace := false
	for _, r := range input {
		if r == ' ' || r == '\t' {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		prevSpace = false
		b.WriteRune(r)
	}
	return b.String()
}

// injectionIsAllowlisted checks whether the request path matches any entry in the allowlist.
func injectionIsAllowlisted(path string, allowlist []string) bool {
	if path == "" || len(allowlist) == 0 {
		return false
	}
	for _, entry := range allowlist {
		if entry == "" {
			continue
		}
		if strings.HasSuffix(entry, "*") {
			prefix := strings.TrimSuffix(entry, "*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
		} else if path == entry {
			return true
		}
	}
	return false
}

// injectionResolveSeverity returns the pattern-level severity if set, otherwise falls
// back to the type-level severity.
func injectionResolveSeverity(patternSeverity, typeSeverity string) string {
	if patternSeverity != "" {
		return patternSeverity
	}
	return typeSeverity
}

// injectionParseCookieHeader splits a raw Cookie header into name/value pairs.
func injectionParseCookieHeader(header string) map[string]string {
	cookies := make(map[string]string)
	if header == "" {
		return cookies
	}
	pairs := strings.Split(header, ";")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		idx := strings.IndexByte(pair, '=')
		if idx < 0 {
			cookies[pair] = ""
			continue
		}
		name := strings.TrimSpace(pair[:idx])
		value := strings.TrimSpace(pair[idx+1:])
		if name != "" {
			cookies[name] = value
		}
	}
	return cookies
}
