package main

import (
	"regexp"
	"strings"
	"testing"
)

func TestRegexp(t *testing.T) {
	r := regexp.MustCompile(`gt[[:digit:]]{4}`)

	t.Log(r.MatchString("-gt10003-"))
	t.Log(r.MatchString("-GT10003-"))
}

func TestIptables(t *testing.T) {
	v := "-A transmission_auto_block -d 182.32.205.143/32 -j DROP"

	if !strings.HasPrefix(v, "-A") || !strings.Contains(v, "-j DROP") {
		t.FailNow()
	}

	pi := strings.Index(v, "-d ")
	if pi == -1 {
		t.FailNow()
	}

	ei := strings.Index(v[pi+3:], " ")
	if ei == -1 {
		t.FailNow()
	}

	t.Log(v[pi+3:][:ei])

	v = strings.TrimSuffix(v[pi+3:][:ei], "/32")
	v = strings.TrimSuffix(v, "/128")

	t.Log(v)
}
