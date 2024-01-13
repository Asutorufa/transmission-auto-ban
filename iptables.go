package main

import (
	"errors"
	"log"
	"net"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

var iptEnabled bool
var ipt *iptables.IPTables
var ipt6 *iptables.IPTables

var iptablesChain = "transmission_auto_block"

func it(addresses []string) error {
	if !iptEnabled {
		return nil
	}
	if ipt == nil {
		var err error
		ipt, err = iptables.New()
		if err != nil {
			return err
		}
	}

	if ipt6 == nil {
		var err error
		ipt6, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return err
		}
	}

	ip4 := []string{}
	ip6 := []string{}

	for _, v := range addresses {
		if ip := net.ParseIP(v); ip != nil {
			if ip.To4() != nil {
				ip4 = append(ip4, v)
			} else {
				ip6 = append(ip6, v)
			}
		}
	}

	var err error

	er := itApply(ipt, ip4)
	if er != nil {
		err = errors.Join(err, er)
	}

	er = itApply(ipt6, ip6)
	if er != nil {
		err = errors.Join(err, er)
	}

	return err
}

func itApply(ipt *iptables.IPTables, addresses []string) error {
	ok, err := ipt.ChainExists("filter", iptablesChain)
	if err != nil {
		return err
	}

	if len(addresses) == 0 || !ok {
		return nil
	}

	if !ok {
		err = ipt.NewChain("filter", iptablesChain)
		if err != nil {
			return err
		}
	}

	ok, err = ipt.Exists("filter", "OUTPUT", "-j", iptablesChain)
	if err != nil {
		return err
	}

	if !ok {
		err = ipt.Append("filter", "OUTPUT", "-j", iptablesChain)
		if err != nil {
			return err
		}
	}

	rules, err := ipt.List("filter", iptablesChain)
	if err != nil {
		return err
	}

	addressMap := toMap(addresses)
	deleteAddress := []string{}

	for _, v := range rules {
		if !strings.HasPrefix(v, "-A") || !strings.Contains(v, "-j DROP") {
			continue
		}

		pi := strings.Index(v, "-d ")
		ei := strings.Index(v, "/32")
		if ei == -1 {
			ei = strings.Index(v, "/128")
		}

		if pi == -1 || ei == -1 {
			continue
		}

		v = v[pi+3 : ei]

		if addressMap[v] {
			delete(addressMap, v)
		} else {
			deleteAddress = append(deleteAddress, v)
		}
	}

	if len(addressMap) > 0 {
		log.Println("drop", addressMap)
	}

	if len(deleteAddress) > 0 {
		log.Println("remove drop", deleteAddress)
	}

	for v := range addressMap {
		err = ipt.AppendUnique("filter", iptablesChain, "-d", v, "-j", "DROP")
		if err != nil {
			log.Println(err)
		}
	}

	for _, v := range deleteAddress {
		err = ipt.Delete("filter", iptablesChain, "-d", v, "-j", "DROP")
		if err != nil {
			log.Println(err)
		}
	}

	return nil
}

func toMap(s []string) map[string]bool {
	m := map[string]bool{}
	for _, v := range s {
		m[v] = true
	}
	return m
}
