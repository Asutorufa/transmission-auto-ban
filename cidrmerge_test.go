package main

import (
	"net"
	"testing"
)

func TestMerge(t *testing.T) {
	t.Log(Merge([]string{
		"237.84.2.178/24",
		"237.84.2.179/32",
		"237.84.2.178/24",
		"237.84.2.178/16",
		"240e:314:b81f:7b00::/64",
		"240e:314:b81f:7b00::2",
		"240e:314:b81f:7b00::/128",
	}))
}

func TestAddOne(t *testing.T) {
	t.Log(addOne(net.ParseIP("237.84.2.178")))
	t.Log(addOne(net.ParseIP("127.0.0.255")))
	t.Log(addOne(net.ParseIP("ff::ffff")))
}

func TestSubOne(t *testing.T) {
	t.Log(subOne(net.ParseIP("237.84.2.178")))
	t.Log(subOne(net.ParseIP("127.0.0.255")))
	t.Log(subOne(net.ParseIP("ff::ffff")))
	t.Log(subOne(net.ParseIP("240e:314:b81f:7b00::")))
	t.Log(subOne(subOne(net.ParseIP("240e:314:b81f:7b00::"))))
	t.Log(subOne(net.ParseIP("240e:314:b81f:7b00::2")))
	t.Log(subOne(net.ParseIP("127.1.0.0")))
}

func TestLastIP(t *testing.T) {
	_, x, _ := net.ParseCIDR("237.84.2.178/24")
	t.Log(addOne(lastIp(x)))
}
