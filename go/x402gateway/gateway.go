package x402gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Options configure a Gateway. Zero values take the reference defaults.
type Options struct {
	SiteURL               string // required; canonical origin, no trailing slash
	SiteName              string // for the page; defaults to the hostname
	CoinPayAPIKey         string // a SCOPED CoinPay key (cp_live_…) with payments:create
	CoinPayBaseURL        string // default https://coinpayportal.com
	PayTo                 string // EVM address that receives the USDC
	PriceCents            float64
	Currency              string // default USD
	PassMinutes           int    // default 1440
	MaxDays               int    // default 30
	Header                string // default x-crawl-pass
	Path                  string // default /crawl
	OpenPaths             []string
	IsPaidAgent           func(userAgent string) bool
	DenyCIDRs             []string
	ChargeSpoofedBrowsers bool
	Exempt                func(*http.Request) bool
	Secret                string
	Training              []string
	Retrieval             []string
	Page                  func(PageContext) string
	Contact               string
	OnSale                func(Sale)
	HTTPClient            *http.Client
	Now                   func() int64 // unix seconds, for tests
}

// Sale is what OnSale receives.
type Sale struct {
	Payer      string
	Ref        string
	Token      string
	ExpiresAt  string
	UserAgent  string
	PriceCents float64
	Days       int
	TotalCents float64
	Currency   string
}

// Answer is a response the gateway wants sent instead of the site's.
type Answer struct {
	Status  int
	Headers http.Header
	Body    []byte
}

// Gateway sells crawl access to training crawlers, by the day, over x402.
type Gateway struct {
	o       Options
	Enabled bool
	secret  string
	open    []string
	denied  []CIDR
	buyURL  string
	coinpay CoinPay
}

// New builds a Gateway.
func New(o Options) (*Gateway, error) {
	o.SiteURL = strings.TrimRight(o.SiteURL, "/")
	if o.SiteURL == "" {
		return nil, errors.New("x402gateway: SiteURL is required")
	}
	if o.SiteName == "" {
		if u, err := url.Parse(o.SiteURL); err == nil && u.Hostname() != "" {
			o.SiteName = u.Hostname()
		} else {
			o.SiteName = o.SiteURL
		}
	}
	if o.CoinPayBaseURL == "" {
		o.CoinPayBaseURL = "https://coinpayportal.com"
	}
	o.CoinPayBaseURL = strings.TrimRight(o.CoinPayBaseURL, "/")
	if o.PriceCents == 0 || math.IsNaN(o.PriceCents) || math.IsInf(o.PriceCents, 0) {
		o.PriceCents = 100
	}
	if o.Currency == "" {
		o.Currency = "USD"
	}
	if o.PassMinutes <= 0 {
		o.PassMinutes = 1440
	}
	if o.MaxDays < 1 {
		o.MaxDays = 30
	}
	if o.Header == "" {
		o.Header = "x-crawl-pass"
	}
	o.Header = strings.ToLower(o.Header)
	if o.Path == "" {
		o.Path = "/crawl"
	}
	if o.Training == nil {
		o.Training = TrainingAgents
	}
	if o.Retrieval == nil {
		o.Retrieval = RetrievalAgents
	}
	if o.IsPaidAgent == nil {
		training := o.Training
		o.IsPaidAgent = func(ua string) bool { return IsTrainingAgent(ua, training) }
	}
	if o.Page == nil {
		o.Page = RenderPage
	}
	if o.Now == nil {
		o.Now = func() int64 { return time.Now().Unix() }
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 20 * time.Second}
	}
	g := &Gateway{o: o}
	g.Enabled = o.CoinPayAPIKey != "" && o.PayTo != ""
	g.secret = o.Secret
	if g.secret == "" {
		g.secret = o.CoinPayAPIKey
	}
	g.open = append([]string{"/robots.txt", o.Path, "/security.txt", "/.well-known/"}, o.OpenPaths...)
	g.denied = CompileCIDRs(o.DenyCIDRs)
	g.buyURL = o.SiteURL + o.Path
	g.coinpay = CoinPay{APIKey: o.CoinPayAPIKey, BaseURL: o.CoinPayBaseURL, Client: o.HTTPClient}
	return g, nil
}

// Options returns the normalised options.
func (g *Gateway) Options() Options { return g.o }

func (g *Gateway) money(cents float64) string {
	return strconv.FormatFloat(cents/100, 'f', 2, 64) + " " + g.o.Currency
}

func (g *Gateway) isOpen(path string) bool {
	for _, p := range g.open {
		if strings.HasSuffix(p, "/") {
			if strings.HasPrefix(path, p) {
				return true
			}
		} else if path == p {
			return true
		}
	}
	return false
}

var leadingInt = regexp.MustCompile(`^\s*([+-]?\d+)`)

func (g *Gateway) daysFrom(r *http.Request) int {
	m := leadingInt.FindStringSubmatch(r.URL.Query().Get("days"))
	if m == nil {
		return 1
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n < 1 {
		return 1
	}
	if n > g.o.MaxDays {
		return g.o.MaxDays
	}
	return n
}

// Offer is the offer for days terms: the same entries, days times the price.
func (g *Gateway) Offer(days int) Offer {
	if !g.Enabled {
		return Offer{X402Version: 2, Accepts: []Accept{}}
	}
	extra := ""
	if days > 1 {
		extra = fmt.Sprintf(" (%d × %d)", days, g.o.PassMinutes)
	}
	o, _ := BuildOffer(OfferOptions{
		PayTo: g.o.PayTo, PriceCents: g.o.PriceCents * float64(days), Resource: g.buyURL,
		Description: fmt.Sprintf("%d minutes of crawl access to %s%s", days*g.o.PassMinutes, g.o.SiteURL, extra),
	})
	return o
}

// PassInfo is the human half of a 402 body.
type PassInfo struct {
	Price   string `json:"price"`
	Minutes int    `json:"minutes"`
	Days    int    `json:"days"`
	Total   string `json:"total"`
	MaxDays int    `json:"maxDays"`
	Header  string `json:"header"`
	Buy     string `json:"buy"`
	BuyDays string `json:"buyDays"`
}

// Receipt is a 402 body: the offer, the pass terms, and why.
type Receipt struct {
	X402Version int      `json:"x402Version"`
	Accepts     []Accept `json:"accepts"`
	Pass        PassInfo `json:"pass"`
	Error       string   `json:"error,omitempty"`
}

func (g *Gateway) receipt(days int, errText string) Receipt {
	o := g.Offer(days)
	buy := g.buyURL
	if days > 1 {
		buy = fmt.Sprintf("%s?days=%d", g.buyURL, days)
	}
	return Receipt{
		X402Version: o.X402Version, Accepts: o.Accepts,
		Pass: PassInfo{
			Price: g.money(g.o.PriceCents), Minutes: g.o.PassMinutes, Days: days, Total: g.money(g.o.PriceCents * float64(days)),
			MaxDays: g.o.MaxDays, Header: g.o.Header, Buy: buy, BuyDays: g.buyURL + "?days=<n>",
		},
		Error: errText,
	}
}

func noStore(h http.Header) http.Header {
	h.Set("cache-control", "no-store")
	h.Set("vary", "Accept, User-Agent, X-Payment")
	return h
}

func (g *Gateway) jsonAnswer(body any, status int, extra map[string]string) *Answer {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
	h := noStore(http.Header{})
	h.Set("content-type", "application/json; charset=utf-8")
	for k, v := range extra {
		h.Set(k, v)
	}
	return &Answer{Status: status, Headers: h, Body: bytes.TrimRight(buf.Bytes(), "\n")}
}

func (g *Gateway) htmlAnswer(body string, status int) *Answer {
	h := noStore(http.Header{})
	h.Set("content-type", "text/html; charset=utf-8")
	return &Answer{Status: status, Headers: h, Body: []byte(body)}
}

func (g *Gateway) pageCtx(days int) PageContext {
	return PageContext{
		Days: days, Total: g.money(g.o.PriceCents * float64(days)), SiteName: g.o.SiteName, SiteURL: g.o.SiteURL,
		BuyURL: g.buyURL, Price: g.money(g.o.PriceCents), Minutes: g.o.PassMinutes, MaxDays: g.o.MaxDays,
		Header: g.o.Header, Enabled: g.Enabled, Offer: g.Offer(1), Training: g.o.Training, Retrieval: g.o.Retrieval, Contact: g.o.Contact,
	}
}

// RobotsTxt is robots.txt with this gateway's lists and sales path. Zero fields of extra take the gateway's.
func (g *Gateway) RobotsTxt(extra RobotsOptions) string {
	if extra.SiteURL == "" {
		extra.SiteURL = g.o.SiteURL
	}
	if extra.Path == "" {
		extra.Path = g.o.Path
	}
	if extra.Training == nil {
		extra.Training = g.o.Training
	}
	if extra.Retrieval == nil {
		extra.Retrieval = g.o.Retrieval
	}
	return RobotsTxt(extra)
}

// Page is the sales page as HTML, for a site that mounts it on a route of its own.
func (g *Gateway) Page() string { return g.o.Page(g.pageCtx(1)) }

var bearer = regexp.MustCompile(`(?i)^Bearer\s+(cp_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$`)

func (g *Gateway) passFrom(r *http.Request) string {
	if direct := header(r.Header, g.o.Header); direct != "" {
		return strings.TrimSpace(direct)
	}
	if m := bearer.FindStringSubmatch(header(r.Header, "authorization")); m != nil {
		return m[1]
	}
	return ""
}

func wantsHTML(accept string) bool { return strings.Contains(strings.ToLower(accept), "text/html") }

func iso(ts int64) string { return time.Unix(ts, 0).UTC().Format("2006-01-02T15:04:05.000Z") }

// Sell answers one request with the sale: a pass as the body of a 200, or a 402 with the offer.
func (g *Gateway) Sell(r *http.Request) *Answer {
	ua := header(r.Header, "user-agent")
	proofHeader := header(r.Header, "x-payment")
	asked := g.daysFrom(r)

	if proofHeader != "" {
		if !g.Enabled {
			return g.jsonAnswer(g.receipt(asked, "Payments are not switched on here."), 402, nil)
		}
		payment := DecodePayment(proofHeader)
		if payment == nil {
			return g.jsonAnswer(g.receipt(asked, "X-PAYMENT is not base64 JSON."), 402, nil)
		}
		unit := ExpectedFor(payment, g.Offer(1))
		if unit == nil {
			return g.jsonAnswer(g.receipt(asked, "Proof does not match an offered network."), 402, nil)
		}
		days := DaysPaid(PaidValueOf(payment), unit.Amount, g.o.MaxDays)
		if days == 0 {
			return g.jsonAnswer(g.receipt(asked, fmt.Sprintf("Pay a whole number of days: %s per day in the token's smallest unit, up to %d days. Add ?days=<n> to %s for the offer.", unit.Amount, g.o.MaxDays, g.buyURL)), 402, nil)
		}
		expected := ExpectedFor(payment, g.Offer(days))
		if expected == nil {
			expected = unit
		}
		term := int64(days) * int64(g.o.PassMinutes) * 60
		now := g.o.Now()
		result := g.coinpay.VerifyAndSettle(r.Context(), payment, *expected)

		var expiresAt int64
		replayed := false
		if result.OK {
			expiresAt = now + term
		} else if result.Replay {
			paid := g.coinpay.SettleAgain(r.Context(), payment)
			validBefore := ValidBeforeOf(payment)
			if paid && validBefore > 0 {
				expiresAt = now + term
				if validBefore+term < expiresAt {
					expiresAt = validBefore + term
				}
				replayed = true
			}
		}
		if expiresAt == 0 || expiresAt <= now {
			reason := result.Reason
			if reason == "" {
				reason = "Payment could not be settled."
			}
			return g.jsonAnswer(g.receipt(days, reason), 402, nil)
		}

		ref := NonceOf(payment)
		if ref == "" {
			ref = result.Ref
		}
		pass, err := MintPass(g.secret, ref, expiresAt, now)
		if err != nil {
			return g.jsonAnswer(g.receipt(days, "Payment could not be settled."), 402, nil)
		}
		expires := iso(pass.ExpiresAt)
		if g.o.OnSale != nil && !replayed {
			func() {
				defer func() { _ = recover() }() // accounting must never cost a buyer the pass
				g.o.OnSale(Sale{Payer: result.Payer, Ref: ref, Token: pass.Token, ExpiresAt: expires, UserAgent: ua,
					PriceCents: g.o.PriceCents, Days: days, TotalCents: g.o.PriceCents * float64(days), Currency: g.o.Currency})
			}()
		}
		body := struct {
			OK        bool   `json:"ok"`
			Pass      string `json:"pass"`
			ExpiresAt string `json:"expires_at"`
			Days      int    `json:"days"`
			Minutes   int    `json:"minutes"`
			Header    string `json:"header"`
			Replayed  bool   `json:"replayed"`
			Use       string `json:"use"`
		}{true, pass.Token, expires, days, days * g.o.PassMinutes, g.o.Header, replayed, fmt.Sprintf(`curl -H "%s: %s" %s/`, g.o.Header, pass.Token, g.o.SiteURL)}
		return g.jsonAnswer(body, 200, map[string]string{g.o.Header: pass.Token, g.o.Header + "-expires": expires})
	}

	if wantsHTML(header(r.Header, "accept")) {
		return g.htmlAnswer(g.o.Page(g.pageCtx(asked)), 402)
	}
	return g.jsonAnswer(g.receipt(asked, fmt.Sprintf("Payment required for training crawlers. Read %s for how.", g.buyURL)), 402, nil)
}

// Handle is the gate. Nil means "not for me, carry on".
func (g *Gateway) Handle(r *http.Request) *Answer {
	if len(g.denied) > 0 && InCIDRs(ClientIP(r), g.denied) {
		h := noStore(http.Header{})
		h.Set("content-type", "text/plain; charset=utf-8")
		return &Answer{Status: 403, Headers: h, Body: []byte("Not available from this network.\n")}
	}
	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	if path == g.o.Path {
		return g.Sell(r)
	}
	if g.o.Exempt != nil && g.o.Exempt(r) {
		return nil
	}
	pays := g.o.IsPaidAgent(header(r.Header, "user-agent")) || (g.o.ChargeSpoofedBrowsers && IsSpoofedBrowser(r))
	if !pays {
		return nil
	}
	if g.isOpen(path) {
		return nil
	}
	if token := g.passFrom(r); token != "" && ReadPass(token, g.secret, g.o.Now()) != nil {
		return nil
	}
	return g.Sell(r)
}

// Write sends an Answer.
func (a *Answer) Write(w http.ResponseWriter) {
	for k, vs := range a.Headers {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("content-length", strconv.Itoa(len(a.Body)))
	w.WriteHeader(a.Status)
	_, _ = w.Write(a.Body)
}

// Middleware wraps a handler: the gateway answers, or next does.
func (g *Gateway) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := g.Handle(r); a != nil {
			a.Write(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RobotsHandler serves robots.txt.
func (g *Gateway) RobotsHandler(extra RobotsOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(g.RobotsTxt(extra)))
	})
}
