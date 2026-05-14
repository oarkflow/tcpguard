package tcpguard

import "testing"

func TestRenderEnvStringDefault(t *testing.T) {
	t.Setenv("TCPGUARD_ENV_TEST", "")
	if rendered := renderEnvString(`env("TCPGUARD_ENV_TEST", "fallback")`); rendered != "fallback" {
		t.Fatalf("rendered=%q want fallback", rendered)
	}
	if rendered := renderEnvString(`{{env("TCPGUARD_ENV_TEST", "fallback")}}`); rendered != "fallback" {
		t.Fatalf("template rendered=%q want fallback", rendered)
	}
}
