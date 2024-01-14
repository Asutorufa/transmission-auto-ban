package main

import "testing"

func TestBlacklist(t *testing.T) {
	t.Log(regexps.MatchString("-gt10003-"))
	t.Log(regexps.MatchString("-XL111-"))
	t.Log(regexps.MatchString("cacao_torrent v1.2.3"))
	t.Log(regexps.MatchString("StellarPlayer xxx"))
	t.Log(regexps.MatchString("Elementum xxx"))
}
