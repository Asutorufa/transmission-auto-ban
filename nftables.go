package main

import (
	"log/slog"
	"net"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

var initNftTable bool

func nft(addrress []string) error {
	c, err := NewNftables()
	if err != nil {
		return err
	}
	defer c.conn.CloseLasting()

	if !initNftTable {
		if err := initTable(c); err != nil {
			return err
		}
		initNftTable = true
	}

	return addElement(c.conn, addrress)
}

var (
	IPv6_l3OffsetSrc   = 8
	IPv6_l3OffsetDst   = 24
	IPv6_l3AddrLen     = 16
	IPv6_l4ProtoOffset = 6
	IPv4_l3OffsetSrc   = 12
	IPv4_l3OffsetDst   = 16
	IPv4_l3AddrLen     = 4
	IPv4_l4ProtoOffset = 9
)

var TABLENAME = "transmission-auto-ban"

func initTable(c *Nftables) error {
	tableExist, err := c.TableExist()
	if err != nil {
		return err
	}

	chainExist, err := c.ChainExist()
	if err != nil {
		return err
	}
	var setMap map[string]bool = make(map[string]bool)
	var setRuleMap map[string]bool = make(map[string]bool)

	if tableExist {
		setMap, err = c.SetsMap()
		if err != nil {
			return err
		}
	}

	if chainExist {
		setRuleMap, err = c.SetRuleMap()
		if err != nil {
			return err
		}
	}

	if !tableExist {
		c.conn.CreateTable(c.table)
	}

	if !chainExist {
		c.conn.AddChain(c.chain)
	}

	if !setMap["ip4set"] {
		err = c.AddSet("ip4set", false)
		if err != nil {
			return err
		}
	}

	if !setMap["ip6set"] {
		err = c.AddSet("ip6set", true)
		if err != nil {
			return err
		}
	}

	if !setRuleMap["ip4set"] {
		c.AddDropMatchSetRule("ip4set", false, false)
		c.AddDropMatchSetRule("ip4set", false, true)
	}

	if !setRuleMap["ip6set"] {
		c.AddDropMatchSetRule("ip6set", true, false)
		c.AddDropMatchSetRule("ip6set", true, true)
	}

	return c.conn.Flush()
}

func addElement(c *nftables.Conn, addrs []string) error {
	resp := Merge(addrs)

	oldSets := getExistSet(c)
	newSets := rangeToMap(resp)

	addSets, deleteSets := diff(oldSets, newSets)

	slog.Info("apply elements", "add", len(addSets), "delete", len(deleteSets))

	table := &nftables.Table{
		Name:   "transmission-auto-ban",
		Family: nftables.TableFamilyINet,
	}

	v4set := &nftables.Set{Name: "ip4set", Table: table}
	v6set := &nftables.Set{Name: "ip6set", Table: table}

	// c.FlushSet(v4set)
	// c.FlushSet(v6set)

	rangeSet := func(sets []NftableElement, operate func(set *nftables.Set, elements []nftables.SetElement) error) {
		for _, v := range sets {
			set := v4set
			if v.Is6 {
				set = v6set
			}

			er := operate(set, []nftables.SetElement{v.Start, v.End})
			if er != nil {
				slog.Error("addElement", "err", er)
			}

			if err := c.Flush(); err != nil {
				slog.Warn("flush", "err", err)
			}
		}
	}

	rangeSet(deleteSets, c.SetDeleteElements)
	rangeSet(addSets, c.SetAddElements)

	return nil
}

func rangeTwo[T any](x []T) func(f func(T, T) bool) {
	return func(f func(T, T) bool) {
		for i := 0; i < len(x); i += 2 {
			if !f(x[i], x[i+1]) {
				return
			}
		}
	}
}

func getExistSet(c *nftables.Conn) map[RangeKey]NftableElement {
	var resp = map[RangeKey]NftableElement{}

	for _, setName := range []string{"ip4set", "ip6set"} {
		ss, err := c.GetSetElements(&nftables.Set{
			Table: &nftables.Table{Family: nftables.TableFamilyINet, Name: TABLENAME},
			Name:  setName,
		})
		if err != nil {
			slog.Error("get set elements", "set", setName, "err", err)
			continue
		}

		for a, b := range rangeTwo(ss) {
			var start, end nftables.SetElement = b, a
			if b.IntervalEnd {
				start, end = a, b
			}

			resp[RangeKey{}.FromRanage(start.Key, end.Key)] = NftableElement{
				Start: start,
				End:   end,
				Is6:   net.IP(start.Key).To4() == nil,
			}
		}
	}

	return resp
}

type NftableElement struct {
	Start nftables.SetElement
	End   nftables.SetElement
	Is6   bool
}

func rangeToMap(x []IRange) map[RangeKey]NftableElement {
	var resp = map[RangeKey]NftableElement{}

	for _, v := range x {
		for _, v := range v.ToIpNets() {

			if v.IP.IsPrivate() || v.IP.IsLoopback() {
				continue
			}

			last := addOne(lastIp(v))

			resp[RangeKey{}.FromRanage(v.IP, last)] = NftableElement{
				Start: nftables.SetElement{Key: v.IP},
				End:   nftables.SetElement{Key: last, IntervalEnd: true},
				Is6:   v.IP.To4() == nil,
			}
		}
	}

	return resp
}

type RangeKey struct {
	Start netip.Addr
	End   netip.Addr
}

func (r RangeKey) FromRanage(start, end net.IP) RangeKey {
	s, _ := netip.AddrFromSlice(start)
	e, _ := netip.AddrFromSlice(end)

	return RangeKey{Start: s.Unmap(), End: e.Unmap()}
}

func diff(oldPrefixs, newPrefixs map[RangeKey]NftableElement) (newPrefix, deletedPrefix []NftableElement) {
	for p, v := range oldPrefixs {
		if _, ok := newPrefixs[p]; !ok {
			deletedPrefix = append(deletedPrefix, v)
		}
	}

	for p, v := range newPrefixs {
		if _, ok := oldPrefixs[p]; !ok {
			newPrefix = append(newPrefix, v)
		}
	}

	return
}

type Nftables struct {
	conn  *nftables.Conn
	table *nftables.Table
	chain *nftables.Chain
}

func NewNftables() (*Nftables, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, err
	}

	table := &nftables.Table{
		Name:   TABLENAME,
		Family: nftables.TableFamilyINet,
	}

	return &Nftables{
		conn:  c,
		table: table,
		chain: &nftables.Chain{
			Name:     "prerouting",
			Table:    table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookPrerouting,
			Priority: nftables.ChainPriorityFilter,
		},
	}, nil
}

func (n *Nftables) AddSet(name string, ipv6 bool) error {
	keyType := nftables.TypeIPAddr
	if ipv6 {
		keyType = nftables.TypeIP6Addr
	}

	return n.conn.AddSet(&nftables.Set{
		Name:      name,
		Table:     n.table,
		Interval:  true,
		AutoMerge: true,
		Counter:   true,
		KeyType:   keyType,
	}, []nftables.SetElement{})
}

func (n *Nftables) AddDropMatchSetRule(setName string, v6, dst bool) {
	family := nftables.TableFamilyIPv4
	offset := IPv4_l3OffsetDst
	plen := IPv4_l3AddrLen

	if v6 {
		family = nftables.TableFamilyIPv6
		plen = IPv6_l3AddrLen

		if dst {
			offset = IPv6_l3OffsetDst
		} else {
			offset = IPv6_l3OffsetSrc
		}
	} else if !dst {
		offset = IPv4_l3OffsetSrc
	}

	n.conn.AddRule(&nftables.Rule{
		Table: n.table,
		Chain: n.chain,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyNFPROTO,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{byte(family)},
			},
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				DestRegister:  1,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        uint32(offset),
				Len:           uint32(plen),
			},
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        setName,
			},
			&expr.Counter{},
			&expr.Reject{
				Type: unix.NFT_REJECT_ICMP_UNREACH,
				// Network Unreachable  0
				// Host Unreachable     1
				// Protocol Unreachable 2
				// Port Unreachable     3
				Code: 0,
			},
			// &expr.Verdict{Kind: expr.VerdictDrop},
		},
	})
}

func (n *Nftables) TableExist() (bool, error) {
	tbs, err := n.conn.ListTables()
	if err != nil {
		return false, err
	}

	for _, v := range tbs {
		if v.Name == n.table.Name {
			return true, nil
		}
	}

	return false, nil

}

func (n *Nftables) ChainExist() (bool, error) {
	cs, err := n.conn.ListChains()
	if err != nil {
		return false, err
	}

	for _, v := range cs {
		if v.Table.Name == n.table.Name && v.Name == n.chain.Name {
			return true, nil
		}
	}

	return false, nil
}

func (n *Nftables) SetsMap() (map[string]bool, error) {
	setss, err := n.conn.GetSets(n.table)
	if err != nil {
		return map[string]bool{}, err
	}

	setMap := map[string]bool{}
	for _, v := range setss {
		setMap[v.Name] = true
	}

	return setMap, nil
}

func (n *Nftables) SetRuleMap() (map[string]bool, error) {
	rs, err := n.conn.GetRules(n.table, n.chain)
	if err != nil {
		return map[string]bool{}, err
	}

	setMap := map[string]bool{}

	for _, r := range rs {
		for _, v := range r.Exprs {
			x, ok := v.(*expr.Lookup)
			if !ok {
				continue
			}

			setMap[x.SetName] = true
		}
	}

	return setMap, nil
}
