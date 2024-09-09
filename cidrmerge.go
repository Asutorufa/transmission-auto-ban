package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"math/bits"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

type NftSet struct {
	Start net.IP
	End   net.IP
	Is6   bool
}

func Merge(text []string) []IRange {
	var arr []IRange

	for _, v := range text {
		r, err := parse(v)
		if err != nil {
			slog.Error("parse", "err", err)
			continue
		}

		arr = append(arr, r)
	}

	arr = sortAndMerge(arr)

	return arr
	// var resp []NftSet
	// for _, v := range arr {
	// 	resp = append(resp, NftSet{
	// 		Start: v.ToRange().start,
	// 		End:   addrNext(v.ToRange().end),
	// 		Is6:   v.ToRange().start.To4() == nil,
	// 	})
	// }

	// return resp
}

// maybe IpWrapper, Range or IpNetWrapper is returned
func parse(text string) (IRange, error) {
	if index := strings.IndexByte(text, '/'); index != -1 {
		if _, network, err := net.ParseCIDR(text); err == nil {
			return IpNetWrapper{network}, nil
		} else {
			return nil, err
		}
	}
	if ip := parseIp(text); ip != nil {
		return IpWrapper{ip}, nil
	}
	if index := strings.IndexByte(text, '-'); index != -1 {
		if start, end := parseIp(text[:index]), parseIp(text[index+1:]); start != nil && end != nil {
			if len(start) == len(end) && !lessThan(end, start) {
				return &Range{start: start, end: end}, nil
			}
		}
		return nil, &net.ParseError{Type: "range", Text: text}
	}
	return nil, &net.ParseError{Type: "ip/CIDR address/range", Text: text}
}

func parseIp(str string) net.IP {
	for _, b := range str {
		switch b {
		case '.':
			return net.ParseIP(str).To4()
		case ':':
			return net.ParseIP(str).To16()
		}
	}
	return nil
}

func ipToString(ip net.IP) string {
	if len(ip) == net.IPv6len {
		if ipv4 := ip.To4(); len(ipv4) == net.IPv4len {
			return "::ffff:" + ipv4.String()
		}
	}
	return ip.String()
}

type IRange interface {
	ToIp() net.IP // return nil if it can't be represented as a single ip
	ToIpNets() []*net.IPNet
	ToRange() *Range
	String() string
}

type Range struct {
	start net.IP
	end   net.IP
}

func (r *Range) familyLength() int {
	return len(r.start)
}
func (r *Range) ToIp() net.IP {
	if r.start.Equal(r.end) {
		return r.start
	}
	return nil
}
func (r *Range) ToIpNets() []*net.IPNet {
	s, end := r.start, r.end
	ipBits := len(s) * 8
	assert(ipBits == len(end)*8, "len(r.start) == len(r.end)")
	var result []*net.IPNet
	for {
		assert(bytes.Compare(s, end) <= 0, "s <= end")
		cidr := max(prefixLength(xor(addOne(end), s)), ipBits-trailingZeros(s))
		ipNet := &net.IPNet{IP: s, Mask: net.CIDRMask(cidr, ipBits)}
		result = append(result, ipNet)
		tmp := lastIp(ipNet)
		if !lessThan(tmp, end) {
			return result
		}
		s = addOne(tmp)
	}
}
func (r *Range) ToRange() *Range {
	return r
}
func (r *Range) String() string {
	return ipToString(r.start) + "-" + ipToString(r.end)
}

type IpWrapper struct {
	net.IP
}

func (r IpWrapper) ToIp() net.IP {
	return r.IP
}
func (r IpWrapper) ToIpNets() []*net.IPNet {
	ipBits := len(r.IP) * 8
	return []*net.IPNet{
		{IP: r.IP, Mask: net.CIDRMask(ipBits, ipBits)},
	}
}
func (r IpWrapper) ToRange() *Range {
	return &Range{start: r.IP, end: r.IP}
}
func (r IpWrapper) String() string {
	return ipToString(r.IP)
}

type IpNetWrapper struct {
	*net.IPNet
}

func (r IpNetWrapper) ToIp() net.IP {
	if allFF(r.IPNet.Mask) {
		return r.IPNet.IP
	}
	return nil
}
func (r IpNetWrapper) ToIpNets() []*net.IPNet {
	return []*net.IPNet{r.IPNet}
}
func (r IpNetWrapper) ToRange() *Range {
	ipNet := r.IPNet
	return &Range{start: ipNet.IP, end: lastIp(ipNet)}
}
func (r IpNetWrapper) String() string {
	ip, mask := r.IP, r.Mask
	if ones, bitCount := mask.Size(); bitCount != 0 {
		return ipToString(ip) + "/" + strconv.Itoa(ones)
	}
	return ipToString(ip) + "/" + mask.String()
}

func lessThan(a, b net.IP) bool {
	if lenA, lenB := len(a), len(b); lenA != lenB {
		return lenA < lenB
	}
	return bytes.Compare(a, b) < 0
}

func max(a, b int) int {
	if a < b {
		return b
	}
	return a
}

func allFF(ip []byte) bool {
	for _, c := range ip {
		if c != 0xff {
			return false
		}
	}
	return true
}

func prefixLength(ip net.IP) int {
	for index, c := range ip {
		if c != 0 {
			return index*8 + bits.LeadingZeros8(c) + 1
		}
	}
	// special case for overflow
	return 0
}

func trailingZeros(ip net.IP) int {
	ipLen := len(ip)
	for i := ipLen - 1; i >= 0; i-- {
		if c := ip[i]; c != 0 {
			return (ipLen-i-1)*8 + bits.TrailingZeros8(c)
		}
	}
	return ipLen * 8
}

func lastIp(ipNet *net.IPNet) net.IP {
	ip, mask := ipNet.IP, ipNet.Mask
	ipLen := len(ip)
	assert(len(mask) == ipLen, "unexpected IPNet %v", ipNet)
	res := make(net.IP, ipLen)
	for i := 0; i < ipLen; i++ {
		res[i] = ip[i] | ^mask[i]
	}
	return res
}

func addOne(ip net.IP) net.IP {
	ipLen := len(ip)
	res := make(net.IP, ipLen)
	for i := ipLen - 1; i >= 0; i-- {
		if t := ip[i]; t != 0xFF {
			res[i] = t + 1
			copy(res, ip[0:i])
			break
		}
	}
	return res
}

func subOne(ip net.IP) net.IP {
	x := make(net.IP, len(ip))
	copy(x, ip)

	for i := len(x) - 1; i >= 0; i-- {
		if x[i] != 0 {
			x[i]--
			break
		} else {
			x[i] = 0xff
		}
	}
	return x
}

func xor(a, b net.IP) net.IP {
	ipLen := len(a)
	assert(ipLen == len(b), "a=%v, b=%v", a, b)
	res := make(net.IP, ipLen)
	for i := ipLen - 1; i >= 0; i-- {
		res[i] = a[i] ^ b[i]
	}
	return res
}

type OutputType byte

const (
	OutputTypeCidr OutputType = iota + 1
	OutputTypeRange
	OutputTypeSum = OutputTypeCidr + OutputTypeRange
)

func convertBatch(wrappers []IRange, outputType OutputType) []IRange {
	result := make([]IRange, 0, len(wrappers))
	if outputType == OutputTypeRange {
		for _, r := range wrappers {
			result = append(result, r.ToRange())
		}
	} else {
		for _, r := range wrappers {
			for _, ipNet := range r.ToIpNets() {
				// can't use range iterator, for operator address of is taken
				// it seems a trick of golang here
				result = append(result, IpNetWrapper{ipNet})
			}
		}
	}
	return result
}

type Ranges []*Range

func (s Ranges) Len() int { return len(s) }
func (s Ranges) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s Ranges) Less(i, j int) bool {
	return lessThan(s[i].start, s[j].start)
}

func sortAndMerge(wrappers []IRange) []IRange {
	if len(wrappers) < 2 {
		return wrappers
	}
	ranges := make([]*Range, 0, len(wrappers))
	for _, e := range wrappers {
		ranges = append(ranges, e.ToRange())
	}
	sort.Sort(Ranges(ranges))

	res := make([]IRange, 0, len(ranges))
	now := ranges[0]
	familyLength := now.familyLength()
	start, end := now.start, now.end
	for i, count := 1, len(ranges); i < count; i++ {
		now := ranges[i]
		if fl := now.familyLength(); fl != familyLength {
			res = append(res, &Range{start, end})
			familyLength = fl
			start, end = now.start, now.end
			continue
		}
		if allFF(end) || !lessThan(addOne(end), now.start) {
			if lessThan(end, now.end) {
				end = now.end
			}
		} else {
			res = append(res, &Range{start, end})
			start, end = now.start, now.end
		}
	}
	return append(res, &Range{start, end})
}

func singleOrSelf(r IRange) IRange {
	if ip := r.ToIp(); ip != nil {
		return IpWrapper{ip}
	}
	return r
}

func returnSelf(r IRange) IRange {
	return r
}

func assert(condition bool, format string, args ...interface{}) {
	if !condition {
		panic(fmt.Sprintf("assert failed: "+format, args...))
	}
}

func ToCidr(start, end net.IP) (netip.Prefix, error) {
	if !((start.To4() != nil && end.To4() != nil) || (start.To16() != nil && end.To16() != nil)) {
		return netip.Prefix{}, fmt.Errorf(`invalid IP address(es)`)
	}

	if start.To4() != nil {
		start = start.To4()
	} else {
		start = start.To16()
	}

	if end.To4() != nil {
		end = end.To4()
	} else {
		end = end.To16()
	}

	mask := make([]byte, len(start))

	for idx := range start {
		mask[idx] = 255 - (start[idx] ^ end[idx])
	}

	ones, _ := net.IPMask(mask).Size()

	x, _ := netip.AddrFromSlice(start)
	return netip.PrefixFrom(x, ones), nil
}
