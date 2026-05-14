package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"runtime"

	"github.com/oarkflow/tcpguard"
	"github.com/oarkflow/tcpguard/bcl"
)

func main() {
	bundle, err := bcl.LoadTCPGuardBundleFile(context.Background(), filepath.Join(exampleDir(), "tcpguard.bcl"))
	must("load tcpguard bcl bundle", err)

	guard, err := tcpguard.New(
		tcpguard.WithBundle(bundle),
		tcpguard.WithContextBuilder(tcpguard.HTTPContextBuilder{
			IdentityExtractor: func(_ *http.Request, sec *tcpguard.Context) {
				sec.Identity.ID = "admin-1"
				sec.Identity.Role = "admin"
				sec.Tenant.ID = "bank"
				sec.Session.ID = "sess-admin-1"
				sec.Session.NewDevice = true
			},
			BusinessExtractor: func(_ *http.Request, sec *tcpguard.Context) {
				sec.Business.Action = "admin.user.update"
				sec.Business.OutsideHours = true
			},
		}),
	)
	must("create tcpguard", err)

	req, err := http.NewRequest(http.MethodPost, "http://api.local/admin/users", nil)
	must("create request", err)
	req.Header.Set("User-Agent", "tcpguard-example")
	sec, err := tcpguard.HTTPContextBuilder{
		IdentityExtractor: func(_ *http.Request, sec *tcpguard.Context) {
			sec.Identity.ID = "admin-1"
			sec.Identity.Role = "admin"
			sec.Tenant.ID = "bank"
			sec.Session.ID = "sess-admin-1"
			sec.Session.NewDevice = true
		},
		BusinessExtractor: func(_ *http.Request, sec *tcpguard.Context) {
			sec.Business.Action = "admin.user.update"
			sec.Business.OutsideHours = true
		},
	}.BuildHTTP(context.Background(), req)
	must("build context", err)

	decision := guard.Evaluate(context.Background(), tcpguard.Event{Type: "request.received"}, sec)
	out, err := json.MarshalIndent(decision, "", "  ")
	must("marshal decision", err)
	fmt.Println(string(out))
}

func exampleDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		log.Fatal("resolve example directory")
	}
	return filepath.Dir(file)
}

func must(label string, err error) {
	if err != nil {
		log.Fatalf("%s: %v", label, err)
	}
}
