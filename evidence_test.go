package tcpguard

import "testing"

func TestEvidenceSetDeduplicatesByDecisionKeyAndPreservesOrder(t *testing.T) {
	seen := newEvidenceSet(2)
	var got []Evidence
	got = appendEvidenceUnique(got, seen, Evidence{Type: "finding", ID: "same", Message: "first", Fields: map[string]any{"n": 1}})
	got = appendEvidenceUnique(got, seen, Evidence{Type: "finding", ID: "same", Message: "first", Fields: map[string]any{"n": 2}})
	got = appendEvidenceUnique(got, seen, Evidence{Type: "finding", ID: "same", Message: "second"})

	if len(got) != 2 {
		t.Fatalf("got %d evidence items, want 2: %#v", len(got), got)
	}
	if got[0].Message != "first" || got[1].Message != "second" {
		t.Fatalf("evidence order or dedupe changed: %#v", got)
	}
}

func TestEvidenceSetResizesWithoutLosingEntries(t *testing.T) {
	seen := newEvidenceSet(1)
	var got []Evidence
	for i := 0; i < 100; i++ {
		item := Evidence{Type: "rule", ID: string(rune(i + 1)), Message: "matched"}
		got = appendEvidenceUnique(got, seen, item)
	}
	if len(got) != 100 {
		t.Fatalf("got %d evidence items after resize, want 100", len(got))
	}
	got = appendEvidenceUnique(got, seen, got[50])
	if len(got) != 100 {
		t.Fatalf("duplicate after resize increased evidence count to %d", len(got))
	}
}
