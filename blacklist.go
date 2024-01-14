package main

import "regexp"

// from https://github.com/c0re100/qBittorrent-Enhanced-Edition/blob/v4_6_x/src/base/bittorrent/peer_blacklist.hpp

var blocklist = []string{
	"-(XL|SD|XF|QD|BN|DL|TS)(\\d+)-",
	`cacao_torrent`,

	// Offline Downloader filter
	"-LT(1220|2070)-",

	// BitTorrent Media Player Peer
	"StellarPlayer",
	"Elementum",
	"-(UW\\w{4}|SP(([0-2]\\d{3})|(3[0-5]\\d{2})))-",

	// others
	"xunlei",
	"thunder",
	`gt[[:digit:]]{4}`,
	`GT[[:digit:]]{4}`,
	"xl0012",
	"xf",
	"dandanplay",
	"dl3760",
	"qq",
	"libtorrent",
}

var regexps Regexps

func init() {
	for _, v := range blocklist {
		regexps = append(regexps, regexp.MustCompile(v))
	}
}

type Regexps []*regexp.Regexp

func (r Regexps) MatchString(s ...string) bool {
	for _, v := range r {
		for _, v2 := range s {
			if v.MatchString(v2) {
				return true
			}
		}
	}
	return false
}
