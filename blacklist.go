package main

import (
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
	"StellarPlayer",
	"Elementum",
	"-(UW\\w{4}|SP(([0-2]\\d{3})|(3[0-5]\\d{2})))-",

	// others
	"xunlei",
	"thunder",
	`gt[[:digit:]]{4}`,
	`GT[[:digit:]]{4}`,
	`dt[[:digit:]]{4}`,
	`DT[[:digit:]]{4}`,
	"-TT", "-tt",
	"xl0012",
	"xf",
	"dandanplay",
	"dl3760",
	"qq",
	"libtorrent",
}

var ips = strings.Split(`1.69.138.0/24
1.180.24.0/21
27.153.128.0/24
27.156.139.0/24
27.156.176.0/24
27.159.173.0/24
27.223.182.0/24
27.223.183.0/24
36.5.4.0/24
36.5.10.0/24
36.5.11.0/24
36.102.218.0/24
36.143.132.0/24
36.248.181.0/24
36.250.161.0/24
39.67.55.0/24
39.67.224.0/24
39.67.225.0/24
39.67.227.0/24
39.67.228.0/24
39.67.229.0/24
39.67.230.0/24
39.67.231.0/24
39.67.234.0/24
39.67.235.0/24
39.67.237.0/24
39.67.239.0/24
39.75.210.0/24
39.76.36.0/24
39.76.43.0/24
39.76.51.0/24
39.76.53.0/24
39.76.55.0/24
39.171.34.0/24
39.171.61.0/24
39.172.52.0/24
42.229.177.0/24
42.229.184.0/24
42.242.128.0/19
42.242.248.0/24
59.47.224.0/20
59.58.42.0/24
59.58.117.0/24
59.60.76.0/22
59.60.84.0/22
60.213.104.0/24
60.213.108.0/22
106.58.40.0/21
110.83.135.0/24
110.85.89.0/24
110.85.135.0/24
110.187.212.0/23
111.170.149.0/24
111.175.86.0/24
111.175.87.0/24
112.42.7.0/24
112.45.16.0/24
112.114.32.0/20
112.194.131.0/24
112.228.240.0/21
112.233.105.0/24
112.233.106.0/24
112.233.109.0/24
112.251.203.0/24
114.100.140.0/24
114.100.141.0/24
117.26.235.0/24
117.26.238.0/24
117.64.160.0/22
117.183.53.0/24
119.7.136.0/24 
119.7.166.0/24
119.7.169.0/24
119.7.175.0/24
119.177.130.0/24
119.177.195.0/24
120.33.247.0/24
120.40.132.0/22
120.43.45.0/24
120.43.54.0/24
121.18.90.0/24 
121.205.254.0/24
123.174.79.0/24
123.184.152.0/24
124.114.56.0/24
124.161.217.0/24
153.0.122.0/24
153.0.123.0/24
153.0.125.0/24
182.243.14.0/24
182.243.15.0/24
182.243.16.0/24
182.243.24.0/24
182.243.25.0/24
182.243.36.0/22
182.243.58.0/24
183.160.217.0/24
183.160.218.0/24
183.162.220.0/24
183.208.134.0/23
218.7.138.0/24
218.62.195.0/24
218.104.106.0/24
220.164.208.0/24
220.164.209.0/24
220.164.213.0/24
220.164.214.0/24
220.164.215.0/24
220.164.240.0/21
221.203.3.0/24
221.203.6.0/24
222.134.126.0/24
222.214.187.0/24
222.220.135.0/24
222.220.144.0/22
222.220.149.0/24
222.220.184.0/24
222.220.185.0/24
223.65.186.0/24
2408:8214:1500::/40
2408:8215:154c:8910::/64
2408:8220:1510:50e0::/64
2408:8221:2f10::/48
2408:8256:968f:7a3::/64
2408:8262:8486:4ba3::/64
2408:8270::/32
2408:8352::/32
2408:8360:6451::/48
2408:8361:6451::/48
2408:8361:6451::/48
2409:8a04:1627::/48
2409:8a04:1628::/48
2409:8a20::/32
2409:8a28:7130:1210::/64
2409:8a34:a618:5660::/64
2409:8a3c:ec8:3940::/64
2409:8a5e::/32
240e:314::/32
240e:345::/32
240e:34c::/32
240e:35f:9d8:a000::/64
240e:362::/32
240e:364::/32
240e:385::/32
240e:388::/32
240e:388::/32
240e:398::/32
240e:3b2::/32
240e:3b4::/32
240e:3b7::/32`, "\n")

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
