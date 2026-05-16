package bcl

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var (
	benchSmallRuleBundle = []byte(`
guard "bench" {
  mode enforce
}

rule "small" {
  trigger {
    on request.received
  }
  when {
    request.path matches "/admin/*"
  }
  risk {
    base 90
  }
}
`)

	benchActionBundle = []byte(`
action "notify" {
  type webhook
  request {
    endpoint env("SOC_WEBHOOK_URL", "https://fallback.example/hook")
    method POST
    headers {
      "Content-Type" "application/json"
      "X-Tenant" "{{tenant.id}}"
    }
    body {
      request "{{request.id}}"
      token env("SOC_TOKEN", "missing")
      include tenant.id
      field source "tcpguard"
    }
  }
}
`)
)

func TestTCPGuardZeroAllocHelpers(t *testing.T) {
	tests := []struct {
		name string
		fn   func()
	}{
		{name: "quoted bare name", fn: func() { _ = quotedTCPGuardName("rule small {") }},
		{name: "call args", fn: func() { _, _, _ = parseTCPGuardCallArgs(`env("SOC_TOKEN", "missing")`, "env") }},
		{name: "split args", fn: func() {
			var args [2]string
			_, _ = splitTCPGuardArgs(`"SOC_TOKEN", "missing"`, &args)
		}},
		{name: "pair", fn: func() { _, _, _ = parseTCPGuardPair(`source tcpguard`) }},
		{name: "wildcard false path", fn: func() { _, _ = normalizeTCPGuardWildcardMatch(`risk.score greater_or_equal 75`) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if allocs := testing.AllocsPerRun(1000, tc.fn); allocs != 0 {
				t.Fatalf("allocs=%v want 0", allocs)
			}
		})
	}
}

func TestTCPGuardParserAvoidsStringsHasPrefix(t *testing.T) {
	data, err := os.ReadFile("tcpguard.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "strings.HasPrefix") {
		t.Fatal("bcl/tcpguard.go should use first-token/local prefix helpers instead of strings.HasPrefix")
	}
}

func TestParseTCPGuardMalformedInputIsRobust(t *testing.T) {
	cases := [][]byte{
		[]byte(`rule "unterminated {`),
		[]byte("rule bad {\n  scope {\n    roles [\n"),
		[]byte("action \"bad\" {\n  request {\n    endpoint env(\n"),
		[]byte("detector \"bad\" {\n  finding \"x\" when {\n    request.path matches\n"),
	}
	for _, data := range cases {
		if _, err := ParseTCPGuardBundle(data); err != nil {
			t.Fatalf("ParseTCPGuardBundle(%q) returned unexpected error: %v", data, err)
		}
	}
}

func BenchmarkParseTCPGuardBundleSmallRule(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ParseTCPGuardBundle(benchSmallRuleBundle); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseTCPGuardBundleActionRequestBody(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ParseTCPGuardBundle(benchActionBundle); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLoadTCPGuardBundleDirMultiFileExample(b *testing.B) {
	dir := filepath.Join("..", "examples", "tcpguard_multi_file_policy_pack")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := LoadTCPGuardBundleDir(context.Background(), dir); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseTCPGuardBundleLargeRulePack(b *testing.B) {
	data := largeTCPGuardRulePack(1000)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		if _, err := ParseTCPGuardBundle(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTCPGuardHelperList(b *testing.B) {
	line := `roles ["admin", "analyst", "auditor", "operator"]`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = parseTCPGuardList(line)
	}
}

func BenchmarkTCPGuardHelperCallArgs(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _ = parseTCPGuardCallArgs(`env("SOC_TOKEN", "missing")`, "env")
	}
}

func BenchmarkTCPGuardHelperCondition(b *testing.B) {
	lines := scanTCPGuardLines([]byte(`
when {
  any {
    request.path matches "/admin/*"
    risk.score greater_or_equal 75
  }
}
`))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p := tcpGuardParser{lines: lines, i: 1}
		_ = p.parseConditionGroup("all")
	}
}

func BenchmarkTCPGuardHelperScanLines(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = scanTCPGuardLines(benchActionBundle)
	}
}

func largeTCPGuardRulePack(n int) []byte {
	var b strings.Builder
	b.Grow(n * 220)
	b.WriteString("guard \"large\" {\n  mode enforce\n}\n")
	for i := 0; i < n; i++ {
		id := strconv.Itoa(i)
		b.WriteString("rule \"rule-")
		b.WriteString(id)
		b.WriteString("\" {\n  trigger {\n    on request.received\n  }\n  when {\n    request.path matches \"/api/")
		b.WriteString(id)
		b.WriteString("/*\"\n  }\n  risk {\n    base 50\n    add 10 when tenant.id equals \"tenant-")
		b.WriteString(id)
		b.WriteString("\"\n  }\n}\n")
	}
	return []byte(b.String())
}

func BenchmarkLoadTCPGuardBundleFileWithIncludes(b *testing.B) {
	dir := b.TempDir()
	mustWriteBenchFile(b, filepath.Join(dir, "tcpguard.bcl"), `
guard "bench" {
  mode enforce
}
include "rules/*.bcl"
`)
	mustWriteBenchFile(b, filepath.Join(dir, "rules", "one.bcl"), string(benchSmallRuleBundle))
	path := filepath.Join(dir, "tcpguard.bcl")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := LoadTCPGuardBundleFile(context.Background(), path); err != nil {
			b.Fatal(err)
		}
	}
}

func mustWriteBenchFile(b *testing.B, path, content string) {
	b.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		b.Fatal(err)
	}
}
