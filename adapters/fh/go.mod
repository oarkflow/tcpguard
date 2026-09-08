module github.com/oarkflow/tcpguard/adapters/fh

go 1.26.5

require (
	github.com/oarkflow/fh v0.0.23
	github.com/oarkflow/tcpguard v0.0.16
)

require (
	github.com/oarkflow/authz v0.0.5 // indirect
	github.com/oarkflow/bcl v0.0.31 // indirect
	github.com/oarkflow/convert v0.0.6 // indirect
	github.com/oarkflow/ip v0.0.11 // indirect
	github.com/oarkflow/rules v0.0.5 // indirect
	github.com/oarkflow/wuid v0.0.1 // indirect
	golang.org/x/crypto v0.56.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)

replace github.com/oarkflow/tcpguard => ../..
replace github.com/oarkflow/authz => ../../authz
