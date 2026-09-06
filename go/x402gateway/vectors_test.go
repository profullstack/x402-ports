package x402gateway

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type vectors struct {
	Constants struct {
		NOW    int64
		SECRET string
		PAYTO  string `json:"PAY_TO"`
		SITE   string
	}
	Passes []struct {
		Secret string
		Ref    *string
		Iat    int64
		Exp    int64
		Token  string
	}
	ReadPass []struct {
		Token  string
		Now    int64
		Secret *string
		OK     bool `json:"ok"`
		Claims map[string]any
		Why    string
	}
	Offers []struct {
		In  map[string]any
		Out json.RawMessage
	}
	Payments []struct {
		Header   string
		Decodes  bool
		Expected *Expected
		HasExp   bool
		Why      string
	}
	DaysPaid []struct {
		Value   *string
		Unit    string
		MaxDays int
		Days    int
		Why     string
	}
	Agents []struct {
		UA       string `json:"ua"`
		Training bool
	}
	Cidrs struct {
		List     []string
		Compiled []string
		Cases    []struct {
			IP  string `json:"ip"`
			Hit bool
		}
		Narrow struct {
			List  []string
			Cases []struct {
				IP  string `json:"ip"`
				Hit bool
			}
		}
	}
	ClientIP []struct {
		Headers map[string]string
		IP      string `json:"ip"`
	}
	Spoofs []struct {
		UA      string `json:"ua"`
		Headers map[string]string
		Spoofed bool
	}
	Robots []struct {
		In  map[string]any
		Out string
	}
	Gateway struct {
		SiteURL string `json:"siteUrl"`
		Coinpay struct {
			APIKey string `json:"apiKey"`
		}
		PayTo                 string   `json:"payTo"`
		DenyCidrs             []string `json:"denyCidrs"`
		ChargeSpoofedBrowsers bool     `json:"chargeSpoofedBrowsers"`
		OpenPaths             []string `json:"openPaths"`
		Exempt                string
	}
	Handle   []handleCase
	Disabled []handleCase
	Coinpay  struct {
		Paid []struct {
			Name        string
			Proof       map[string]any
			Verify      map[string]any
			Settle      map[string]any
			SettleAgain map[string]any
			Status      int
			Days        int
			Minutes     int
			Replayed    bool
			Ref         string
			ExpiresAt   int64
			Error       string
		}
	}
}

type handleCase struct {
	Name            string
	URL             string `json:"url"`
	Headers         map[string]string
	Pass            bool
	Status          int
	ContentType     string
	Body            json.RawMessage
	Text            string
	HTMLContains    []string `json:"htmlContains"`
	ResponseHeaders map[string]string
}

func load(t *testing.T) vectors {
	t.Helper()
	p := os.Getenv("X402_VECTORS")
	if p == "" {
		p = filepath.Join("..", "..", "spec", "vectors.json")
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	// payments.expected is optional: mark presence
	var probe struct {
		Payments []map[string]json.RawMessage
	}
	_ = json.Unmarshal(raw, &probe)
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	for i := range v.Payments {
		_, v.Payments[i].HasExp = probe.Payments[i]["expected"]
	}
	return v
}

func sameJSON(t *testing.T, name string, got []byte, want json.RawMessage) {
	t.Helper()
	var a, b any
	if err := json.Unmarshal(got, &a); err != nil {
		t.Fatalf("%s: got is not JSON: %v\n%s", name, err, got)
	}
	_ = json.Unmarshal(want, &b)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("%s:\n got %s\nwant %s", name, got, want)
	}
}

func request(site, path string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, site+path, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func gateway(t *testing.T, v vectors, base string) *Gateway {
	t.Helper()
	sub := v.Gateway.Exempt
	g, err := New(Options{
		SiteURL: v.Gateway.SiteURL, CoinPayAPIKey: v.Gateway.Coinpay.APIKey, CoinPayBaseURL: base, PayTo: v.Gateway.PayTo,
		DenyCIDRs: v.Gateway.DenyCidrs, ChargeSpoofedBrowsers: v.Gateway.ChargeSpoofedBrowsers, OpenPaths: v.Gateway.OpenPaths,
		Exempt: func(r *http.Request) bool { return sub != "" && strings.Contains(r.Header.Get("cookie"), sub) },
		Now:    func() int64 { return v.Constants.NOW },
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestPasses(t *testing.T) {
	v := load(t)
	for _, p := range v.Passes {
		ref := ""
		if p.Ref != nil {
			ref = *p.Ref
		}
		got, err := MintPass(p.Secret, ref, p.Exp, p.Iat)
		if err != nil || got.Token != p.Token {
			t.Errorf("mint ref=%q: got %q err=%v want %q", ref, got.Token, err, p.Token)
		}
	}
	for _, c := range v.ReadPass {
		secret := v.Constants.SECRET
		if c.Secret != nil {
			secret = *c.Secret
		}
		got := ReadPass(c.Token, secret, c.Now)
		if (got != nil) != c.OK {
			t.Errorf("read %q (%s): ok=%v want %v", c.Token, c.Why, got != nil, c.OK)
		}
		if got != nil && got.Exp != c.Claims["exp"].(float64) {
			t.Errorf("read %q: exp %v want %v", c.Token, got.Exp, c.Claims["exp"])
		}
	}
}

func TestOffers(t *testing.T) {
	v := load(t)
	for _, o := range v.Offers {
		opts := OfferOptions{PayTo: o.In["payTo"].(string), PriceCents: o.In["priceCents"].(float64), Resource: o.In["resource"].(string), Description: o.In["description"].(string)}
		if m, ok := o.In["maxTimeoutSeconds"].(float64); ok {
			opts.MaxTimeoutSeconds = int(m)
		}
		got, err := BuildOffer(opts)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(got)
		sameJSON(t, "offer", raw, o.Out)
	}
}

func TestPayments(t *testing.T) {
	v := load(t)
	var offer Offer
	_ = json.Unmarshal(v.Offers[0].Out, &offer)
	for _, p := range v.Payments {
		d := DecodePayment(p.Header)
		if (d != nil) != p.Decodes {
			t.Errorf("decode %q (%s): %v want %v", p.Header, p.Why, d != nil, p.Decodes)
		}
		if p.HasExp && !reflect.DeepEqual(ExpectedFor(d, offer), p.Expected) {
			t.Errorf("expectedFor (%s): got %+v want %+v", p.Why, ExpectedFor(d, offer), p.Expected)
		}
	}
	for _, d := range v.DaysPaid {
		var val *big.Int
		if d.Value != nil {
			val = bigInt(*d.Value)
			if val != nil && val.Sign() <= 0 {
				val = nil
			}
		}
		if got := DaysPaid(val, d.Unit, d.MaxDays); got != d.Days {
			t.Errorf("daysPaid %v/%s (%s): %d want %d", d.Value, d.Unit, d.Why, got, d.Days)
		}
	}
}

func TestAgentsAndEdge(t *testing.T) {
	v := load(t)
	for _, a := range v.Agents {
		if IsTrainingAgent(a.UA, nil) != a.Training {
			t.Errorf("agent %q", a.UA)
		}
	}
	c := CompileCIDRs(v.Cidrs.List)
	var texts []string
	for _, x := range c {
		texts = append(texts, x.Text)
	}
	if !reflect.DeepEqual(texts, v.Cidrs.Compiled) {
		t.Errorf("compiled %v want %v", texts, v.Cidrs.Compiled)
	}
	for _, k := range v.Cidrs.Cases {
		if InCIDRs(k.IP, c) != k.Hit {
			t.Errorf("cidr %q", k.IP)
		}
	}
	n := CompileCIDRs(v.Cidrs.Narrow.List)
	for _, k := range v.Cidrs.Narrow.Cases {
		if InCIDRs(k.IP, n) != k.Hit {
			t.Errorf("narrow cidr %q", k.IP)
		}
	}
	for _, k := range v.ClientIP {
		if got := ClientIP(request(v.Constants.SITE, "/", k.Headers)); got != k.IP {
			t.Errorf("clientIp %v: %q want %q", k.Headers, got, k.IP)
		}
	}
	for _, s := range v.Spoofs {
		h := map[string]string{"user-agent": s.UA}
		for k, val := range s.Headers {
			h[k] = val
		}
		if IsSpoofedBrowser(request(v.Constants.SITE, "/", h)) != s.Spoofed {
			t.Errorf("spoof %q", s.UA)
		}
	}
}

func TestRobots(t *testing.T) {
	v := load(t)
	for i, r := range v.Robots {
		o := RobotsOptions{SiteURL: r.In["siteUrl"].(string)}
		strs := func(k string) []string {
			raw, ok := r.In[k].([]any)
			if !ok {
				return nil
			}
			out := make([]string, len(raw))
			for j, s := range raw {
				out[j] = s.(string)
			}
			return out
		}
		o.Disallow, o.Allow, o.Refused, o.Comments = strs("disallow"), strs("allow"), strs("refused"), strs("comments")
		o.Training, o.Retrieval = strs("training"), strs("retrieval")
		if s, ok := r.In["sitemap"].(string); ok {
			o.Sitemap = &s
		}
		if p, ok := r.In["path"].(string); ok {
			o.Path = p
		}
		if got := RobotsTxt(o); got != r.Out {
			t.Errorf("robots %d:\n got %q\nwant %q", i, got, r.Out)
		}
	}
}

func check(t *testing.T, g *Gateway, site string, c handleCase) {
	t.Helper()
	a := g.Handle(request(site, c.URL, c.Headers))
	if c.Pass {
		if a != nil {
			t.Errorf("%s: expected pass-through, got %d", c.Name, a.Status)
		}
		return
	}
	if a == nil {
		t.Errorf("%s: expected %d, passed through", c.Name, c.Status)
		return
	}
	if a.Status != c.Status {
		t.Errorf("%s: status %d want %d", c.Name, a.Status, c.Status)
	}
	if ct := strings.Split(a.Headers.Get("content-type"), ";")[0]; c.ContentType != "" && ct != c.ContentType {
		t.Errorf("%s: content-type %q want %q", c.Name, ct, c.ContentType)
	}
	if c.Body != nil {
		sameJSON(t, c.Name, a.Body, c.Body)
	}
	if c.Text != "" && string(a.Body) != c.Text {
		t.Errorf("%s: text %q", c.Name, a.Body)
	}
	for _, s := range c.HTMLContains {
		if !strings.Contains(string(a.Body), s) {
			t.Errorf("%s: html lacks %q", c.Name, s)
		}
	}
	for k, val := range c.ResponseHeaders {
		if a.Headers.Get(k) != val {
			t.Errorf("%s: header %s=%q want %q", c.Name, k, a.Headers.Get(k), val)
		}
	}
}

func TestHandle(t *testing.T) {
	v := load(t)
	g := gateway(t, v, "http://127.0.0.1:9") // any CoinPay call here is a bug
	for _, c := range v.Handle {
		check(t, g, v.Constants.SITE, c)
	}
	d, _ := New(Options{SiteURL: v.Constants.SITE, Now: func() int64 { return v.Constants.NOW }})
	for _, c := range v.Disabled {
		check(t, d, v.Constants.SITE, c)
	}
	if g.RobotsTxt(RobotsOptions{}) != RobotsTxt(RobotsOptions{SiteURL: v.Constants.SITE}) {
		t.Error("gateway robots differs")
	}
	if !strings.Contains(g.Page(), "1.00 USD") {
		t.Error("page lacks price")
	}
}

func TestPaid(t *testing.T) {
	v := load(t)
	for _, c := range v.Coinpay.Paid {
		t.Run(c.Name, func(t *testing.T) {
			settles := 0
			var verifyBody map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("x-api-key") != v.Constants.SECRET {
					t.Errorf("api key %q", r.Header.Get("x-api-key"))
				}
				var out map[string]any
				switch r.URL.Path {
				case "/api/x402/verify":
					_ = json.NewDecoder(r.Body).Decode(&verifyBody)
					out = c.Verify
				case "/api/x402/settle":
					settles++
					if settles == 1 && c.Settle != nil {
						out = c.Settle
					} else if c.SettleAgain != nil {
						out = c.SettleAgain
					} else {
						out = c.Settle
					}
				default:
					t.Errorf("unexpected %s", r.URL.Path)
				}
				_ = json.NewEncoder(w).Encode(out)
			}))
			defer srv.Close()
			sales := 0
			g := gateway(t, v, srv.URL)
			g.o.OnSale = func(Sale) { sales++ }
			raw, _ := json.Marshal(c.Proof)
			a := g.Handle(request(v.Constants.SITE, "/crawl", map[string]string{"x-payment": base64.StdEncoding.EncodeToString(raw), "user-agent": "curl/8"}))
			if a == nil || a.Status != c.Status {
				t.Fatalf("status %v want %d", a, c.Status)
			}
			var body map[string]any
			_ = json.Unmarshal(a.Body, &body)
			if c.Status == 200 {
				if body["ok"] != true || int(body["days"].(float64)) != c.Days || body["replayed"] != c.Replayed {
					t.Errorf("body %s", a.Body)
				}
				if c.Minutes != 0 && int(body["minutes"].(float64)) != c.Minutes {
					t.Errorf("minutes %v", body["minutes"])
				}
				claims := ReadPass(body["pass"].(string), v.Constants.SECRET, v.Constants.NOW)
				if claims == nil {
					t.Fatal("pass does not read back")
				}
				if c.Ref != "" && claims.Ref != c.Ref {
					t.Errorf("ref %v want %s", claims.Ref, c.Ref)
				}
				if c.ExpiresAt != 0 && int64(claims.Exp) != c.ExpiresAt {
					t.Errorf("exp %v want %d", claims.Exp, c.ExpiresAt)
				}
				if a.Headers.Get("x-crawl-pass") != body["pass"] {
					t.Error("pass header missing")
				}
				want := 1
				if c.Replayed {
					want = 0
				}
				if sales != want {
					t.Errorf("sales %d want %d", sales, want)
				}
				exp := verifyBody["expected"].(map[string]any)
				if exp["amount"] != big.NewInt(int64(1000000*c.Days)).String() {
					t.Errorf("verify expected amount %v", exp["amount"])
				}
			} else {
				if c.Error != "" && body["error"] != c.Error {
					t.Errorf("error %v want %q", body["error"], c.Error)
				}
				if sales != 0 {
					t.Error("sale recorded on failure")
				}
			}
		})
	}
}
