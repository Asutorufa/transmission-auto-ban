module transmission-auto-ban

go 1.23.0

require (
	github.com/coreos/go-iptables v0.7.0
	github.com/google/nftables v0.2.0
	github.com/hekmon/cunits/v2 v2.1.0
	github.com/hekmon/transmissionrpc/v3 v3.0.0
	go.etcd.io/bbolt v1.3.8
)

require (
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.5.0 // indirect
	golang.org/x/net v0.23.0 // indirect
	golang.org/x/sync v0.6.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
)

replace github.com/google/nftables => github.com/Asutorufa/nftables v0.0.0-20240830093935-6695ecd0897c
