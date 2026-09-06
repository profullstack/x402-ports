package x402gateway

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// CIDR is a compiled IPv4 range.
type CIDR struct {
	Base uint32
	Mask uint32
	Text string
}

var octet = regexp.MustCompile(`^\d{1,3}$`)

func ipv4ToInt(ip string) (uint32, bool) {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0, false
	}
	var n uint32
	for _, p := range parts {
		if !octet.MatchString(p) {
			return 0, false
		}
		v, _ := strconv.Atoi(p)
		if v > 255 {
			return 0, false
		}
		n = n*256 + uint32(v)
	}
	return n, true
}

// ParseCIDR parses "a.b.c.d/len" or a bare address. Nil if unreadable.
func ParseCIDR(cidr string) *CIDR {
	s := strings.TrimSpace(cidr)
	ip, lenRaw, hasLen := strings.Cut(s, "/")
	base, ok := ipv4ToInt(ip)
	if !ok {
		return nil
	}
	length := 32
	if hasLen {
		n, err := strconv.Atoi(lenRaw)
		if err != nil || n < 0 || n > 32 || !regexp.MustCompile(`^\d+$`).MatchString(lenRaw) {
			return nil
		}
		length = n
	}
	var mask uint32
	if length > 0 {
		mask = 0xffffffff << (32 - length)
	}
	return &CIDR{Base: base & mask, Mask: mask, Text: ip + "/" + strconv.Itoa(length)}
}

// CompileCIDRs compiles a denylist once. Unreadable entries are dropped.
func CompileCIDRs(list []string) []CIDR {
	out := make([]CIDR, 0, len(list))
	for _, s := range list {
		if c := ParseCIDR(s); c != nil {
			out = append(out, *c)
		}
	}
	return out
}

// InCIDRs reports whether an IPv4 address falls inside any compiled range.
func InCIDRs(ip string, compiled []CIDR) bool {
	n, ok := ipv4ToInt(strings.TrimSpace(ip))
	if !ok {
		return false
	}
	for _, c := range compiled {
		if n&c.Mask == c.Base {
			return true
		}
	}
	return false
}

// header joins every value of a header with ", ", the way Fetch reads it. Empty if absent.
func header(h http.Header, name string) string {
	return strings.Join(h.Values(name), ", ")
}

func hasHeader(h http.Header, name string) bool {
	_, ok := h[http.CanonicalHeaderKey(name)]
	return ok
}

// ClientIP is the caller's address as the edge reported it: x-real-ip, else the LAST x-forwarded-for hop.
func ClientIP(r *http.Request) string {
	if real := strings.TrimSpace(header(r.Header, "x-real-ip")); real != "" {
		return real
	}
	xff := header(r.Header, "x-forwarded-for")
	if xff == "" {
		return ""
	}
	last := ""
	for _, h := range strings.Split(xff, ",") {
		if t := strings.TrimSpace(h); t != "" {
			last = t
		}
	}
	return last
}

var claimsChromium = regexp.MustCompile(`\bChrome/\d+`)
var declaresItself = regexp.MustCompile(`(?i)compatible;|\bbot\b|bot/|crawler|spider|slurp`)

// IsSpoofedBrowser: claims Chromium, declares no crawler, sends no Sec-Fetch-Mode.
func IsSpoofedBrowser(r *http.Request) bool {
	ua := header(r.Header, "user-agent")
	if !claimsChromium.MatchString(ua) || declaresItself.MatchString(ua) {
		return false
	}
	return !hasHeader(r.Header, "sec-fetch-mode")
}
