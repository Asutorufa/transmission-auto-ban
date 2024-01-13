package main

import (
	"regexp"
	"testing"
)

func TestRegexp(t *testing.T) {
	r := regexp.MustCompile(`gt[[:digit:]]{4}`)

	t.Log(r.MatchString("-gt10003-"))
	t.Log(r.MatchString("-GT10003-"))
}
