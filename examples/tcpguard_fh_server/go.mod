module github.com/oarkflow/tcpguard/examples/tcpguard_fh_server

go 1.26.2

require (
	github.com/oarkflow/fh v0.0.8
	github.com/oarkflow/tcpguard v0.0.13
	github.com/oarkflow/tcpguard/adapters/fh v0.0.0-00010101000000-000000000000
	modernc.org/sqlite v1.53.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/oarkflow/authz v0.0.5 // indirect
	github.com/oarkflow/bcl v0.0.30 // indirect
	github.com/oarkflow/ip v0.0.11 // indirect
	github.com/oarkflow/rules v0.0.2 // indirect
	github.com/oarkflow/wuid v0.0.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	modernc.org/libc v1.74.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

replace github.com/oarkflow/tcpguard => ../../

replace github.com/oarkflow/tcpguard/adapters/fh => ../../adapters/fh
replace github.com/oarkflow/authz => ../../../authz
