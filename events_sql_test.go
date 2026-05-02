package tcpguard

import (
	"context"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

func TestSQLEventEmitterEmitQuerySubscribe(t *testing.T) {
	db, err := sqlx.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	emitter, err := NewSQLEventEmitter(db)
	if err != nil {
		t.Fatalf("NewSQLEventEmitter() error = %v", err)
	}

	ch := make(chan SecurityEvent, 1)
	unsubscribe := emitter.Subscribe(ch)
	defer unsubscribe()

	event := NewSecurityEvent("config_mutation", "high")
	event.UserID = "admin"
	event.ClientIP = "127.0.0.1"
	if err := emitter.Emit(context.Background(), event); err != nil {
		t.Fatalf("Emit() error = %v", err)
	}

	select {
	case got := <-ch:
		if got.ID != event.ID {
			t.Fatalf("subscriber event ID = %q, want %q", got.ID, event.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber did not receive event")
	}

	events, err := emitter.Query(context.Background(), EventFilter{
		Types:  []string{"config_mutation"},
		UserID: "admin",
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("Query() returned %d events, want 1", len(events))
	}
	if events[0].ID != event.ID {
		t.Fatalf("Query() event ID = %q, want %q", events[0].ID, event.ID)
	}
}
