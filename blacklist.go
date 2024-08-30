package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// from https://github.com/c0re100/qBittorrent-Enhanced-Edition/blob/v4_6_x/src/base/bittorrent/peer_blacklist.hpp

var blocklist = []string{
	"-(XL|SD|XF|QD|BN|DL|TS|FG|TT|NX|XP|FD6)(\\d+)-",
	`cacao_torrent`,

	// Offline Downloader filter
	"-LT(1220|2070)-",

	// BitTorrent Media Player Peer
	"Elementum",
	"^-UW\\w{4}-",                                          // uTorrent Web.
	"^-SP(([0-2]\\d{3})|(3[0-5]\\d{2}))-", "StellarPlayer", // 恒星播放器.

	// others
	"^-XL", "Xunlei",
	"xunlei",
	"thunder",
	"-.*0001.*-",
	`HP[[:digit:]]{4}`,
	`hp[[:digit:]]{4}`,
	`gt[[:digit:]]{4}`,
	`GT[[:digit:]]{4}`,
	`dt[[:digit:]]{4}`,
	`DT[[:digit:]]{4}`,
	"^-DT", "dt[ /]torrent", "^-HP", "hp[ /]torrent", "^-XM", "xm[ /]torrent",
	"-TT", "-tt",
	"xl0012",
	"xf",
	"dandanplay",
	"dl3760",
	"qq",
	// "libtorrent",

	"anacrolix[ /]torrent v?([0-1]\\.(([0-9]|[0-4][0-9]|[0-5][0-2])\\.[0-9]+|(53\\.[0-2]( |$)))|unknown)",
	"trafficConsume", "\u07ad__",
	"go[ \\.]torrent",
	"Taipei-Torrent dev",
	"qBittorrent[ /]3\\.3\\.15",
	"gobind", "offline-download",
	"ljyun.cn",
}

// from https://raw.githubusercontent.com/PBH-BTN/			/main/combine/all.txt
//
//go:embed all.txt
var pbhRule []byte

var othersRules = []string{
	"1.180.24.0/23",
	"36.102.218.0/24",
	"101.69.63.0/24",
	"112.45.16.0/24",
	"112.45.20.0/24",
	"115.231.84.120/29",
	"115.231.84.128/28",
	"122.224.33.0/24",
	"123.184.152.0/24",
	"218.7.138.0/24",
	"221.11.96.0/24",
	"221.203.3.0/24",
	"221.203.6.0/24",
	"223.78.79.0/24",
	"223.78.80.0/24",
	"2002:df4e:4f00::/48",
	"2002:df4e:5000::/48",
	"2408:862e:ff:ff0d::/60",
	"2408:8631:2e09:d05::/60",
	"2408:8738:6000:d::/60",
	"2409:873c:f03:6000::/56",
	"240e:90c:2000:301::/60",
	"240e:90e:2000:2006::/60",
	"240e:918:8008::/48",
}

var ips = filter(append(strings.Split(string(pbhRule), "\n"), othersRules...))

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

func filter(ips []string) []string {
	var ret []string
	for _, v := range ips {
		x, err := netip.ParsePrefix(v)
		if err == nil {
			x = x.Masked()
			ret = append(ret, x.String())
			continue
		}

		y, err := netip.ParseAddr(v)
		if err == nil {
			ret = append(ret, y.String())
			continue
		}
	}
	return ret
}

func initRule(path string) {
	b, err := os.ReadFile(filepath.Join(path, "all.txt"))
	if err != nil {
		log.Println(err)
		refreshRule(path)
		return
	}

	z, err := os.ReadFile(filepath.Join(path, "custom.txt"))
	if err != nil {
		log.Println(err)
	}

	ips = filter(append(strings.Split(string(b)+"\n"+string(z), "\n"), othersRules...))
}

func refreshRule(path string) {
	resp, err := http.Get("https://raw.githubusercontent.com/PBH-BTN/BTN-Collected-Rules/main/combine/all.txt")
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		data, _ := io.ReadAll(resp.Body)
		log.Println(resp.StatusCode, string(data))
		return
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return
	}

	z, err := os.ReadFile(filepath.Join(path, "custom.txt"))
	if err != nil {
		log.Println(err)
	}
	ips = filter(append(strings.Split(string(b)+"\n"+string(z), "\n"), othersRules...))

	sh256 := sha256.Sum256(b)
	log.Println("refreshRule", len(ips), hex.EncodeToString(sh256[:]))

	err = os.WriteFile(filepath.Join(path, "all.txt"), b, 0644)
	if err != nil {
		log.Println(err)
		return
	}
}
