package x402gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Method is one way CoinPay can settle under the exact scheme: USDC on one chain.
type Method struct {
	Key     string
	Network string
	Asset   string
	Label   string
}

// Methods lists USDC on Base, Polygon and Ethereum, Base first.
var Methods = []Method{
	{"usdc_base", "eip155:8453", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "USDC on Base"},
	{"usdc_polygon", "eip155:137", "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", "USDC on Polygon"},
	{"usdc_eth", "eip155:1", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "USDC on Ethereum"},
}

const decimals = 6

// Domain is the token's EIP-712 domain, the same for all three USDC deployments.
type Domain struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Accept is one entry of an x402 v2 offer.
type Accept struct {
	Scheme            string `json:"scheme"`
	Network           string `json:"network"`
	Amount            string `json:"amount"`
	Asset             string `json:"asset"`
	PayTo             string `json:"payTo"`
	Resource          string `json:"resource"`
	Description       string `json:"description"`
	MimeType          string `json:"mimeType"`
	MaxTimeoutSeconds int    `json:"maxTimeoutSeconds"`
	Extra             Domain `json:"extra"`
}

// Offer is an x402 v2 402 body.
type Offer struct {
	X402Version int      `json:"x402Version"`
	Accepts     []Accept `json:"accepts"`
}

// OfferOptions builds an Offer.
type OfferOptions struct {
	PayTo             string
	PriceCents        float64
	Resource          string
	Description       string
	MaxTimeoutSeconds int // default 300
	Methods           []Method
}

// BuildOffer builds a v2 402 body. Amount is the price in the token's smallest unit, rounded up.
func BuildOffer(o OfferOptions) (Offer, error) {
	if o.PayTo == "" {
		return Offer{}, errors.New("an offer needs a payTo address")
	}
	if o.Description == "" {
		o.Description = "Payment required"
	}
	if o.MaxTimeoutSeconds == 0 {
		o.MaxTimeoutSeconds = 300
	}
	if o.Methods == nil {
		o.Methods = Methods
	}
	amount := strconv.FormatInt(int64(math.Ceil((o.PriceCents/100)*math.Pow10(decimals))), 10)
	out := Offer{X402Version: 2, Accepts: make([]Accept, 0, len(o.Methods))}
	for _, m := range o.Methods {
		out.Accepts = append(out.Accepts, Accept{
			Scheme: "exact", Network: m.Network, Amount: amount, Asset: m.Asset, PayTo: o.PayTo,
			Resource: o.Resource, Description: o.Description, MimeType: "application/json",
			MaxTimeoutSeconds: o.MaxTimeoutSeconds, Extra: Domain{"USD Coin", "2"},
		})
	}
	return out, nil
}

var b64ok = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
var spaces = regexp.MustCompile(`\s+`)

// fromBase64 reads base64 or base64url the forgiving way atob does.
func fromBase64(s string) ([]byte, error) {
	t := spaces.ReplaceAllString(s, "")
	t = strings.NewReplacer("-", "+", "_", "/").Replace(t)
	if len(t)%4 == 0 {
		t = strings.TrimRight(t, "=")
	}
	if len(t)%4 == 1 || !b64ok.MatchString(t) {
		return nil, errors.New("not base64")
	}
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(t, "="))
}

// DecodePayment reads the proof out of an X-PAYMENT header: a JSON object or array, else nil.
func DecodePayment(header string) any {
	if header == "" {
		return nil
	}
	raw, err := fromBase64(header)
	if err != nil {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	switch v.(type) {
	case map[string]any, []any:
		return v
	}
	return nil
}

// Expected is what CoinPay must hold a proof to, taken from the offered entry for its network.
type Expected struct {
	Amount   string `json:"amount"`
	Resource string `json:"resource"`
	PayTo    string `json:"payTo"`
	Asset    string `json:"asset"`
}

func get(v any, path ...string) any {
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func str(v any) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "true"
		}
		return "false"
	}
	return ""
}

// ExpectedFor finds the offered entry for the proof's network, case-insensitively. Nil if none.
func ExpectedFor(payment any, offer Offer) *Expected {
	network := strings.ToLower(str(get(payment, "network")))
	for _, a := range offer.Accepts {
		if strings.ToLower(a.Network) == network {
			return &Expected{a.Amount, a.Resource, a.PayTo, a.Asset}
		}
	}
	return nil
}

// NonceOf is the single-use nonce CoinPay keys replay detection on.
func NonceOf(payment any) string { return str(get(payment, "payload", "authorization", "nonce")) }

// ValidBeforeOf is when the payer's signature stops being valid, unix seconds; 0 if unreadable.
func ValidBeforeOf(payment any) int64 {
	f, err := strconv.ParseFloat(strings.TrimSpace(str(get(payment, "payload", "authorization", "validBefore"))), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) || f <= 0 {
		return 0
	}
	return int64(f)
}

var decimalRe = regexp.MustCompile(`^[+-]?\d+$`)
var hexRe = regexp.MustCompile(`^0[xX][0-9a-fA-F]+$`)

// bigInt reads what BigInt(raw) would: decimal or 0x strings, whole numbers. Nil otherwise.
func bigInt(raw any) *big.Int {
	switch t := raw.(type) {
	case float64:
		if t != math.Trunc(t) {
			return nil
		}
		b, _ := new(big.Float).SetFloat64(t).Int(nil)
		return b
	case string:
		s := strings.TrimSpace(t)
		n := new(big.Int)
		if decimalRe.MatchString(s) {
			n.SetString(strings.TrimPrefix(s, "+"), 10)
			return n
		}
		if hexRe.MatchString(s) {
			n.SetString(s[2:], 16)
			return n
		}
	}
	return nil
}

// PaidValueOf is the value a proof authorizes, in the token's smallest unit, or nil.
func PaidValueOf(payment any) *big.Int {
	raw := get(payment, "payload", "authorization", "value")
	if raw == nil || raw == "" {
		return nil
	}
	v := bigInt(raw)
	if v == nil || v.Sign() <= 0 {
		return nil
	}
	return v
}

// DaysPaid is how many terms value buys at unit per term: a whole number in [1, maxDays], else 0.
func DaysPaid(value *big.Int, unit string, maxDays int) int {
	if value == nil {
		return 0
	}
	per := bigInt(unit)
	if per == nil || per.Sign() <= 0 {
		return 0
	}
	q, r := new(big.Int).QuoRem(value, per, new(big.Int))
	if r.Sign() != 0 || q.Cmp(big.NewInt(1)) < 0 || q.Cmp(big.NewInt(int64(maxDays))) > 0 {
		return 0
	}
	return int(q.Int64())
}

// CoinPay is how the gateway reaches CoinPay's verify and settle routes.
type CoinPay struct {
	APIKey  string
	BaseURL string
	Client  *http.Client
}

func (c CoinPay) post(ctx context.Context, path string, body any) (int, map[string]any) {
	raw, _ := json.Marshal(body)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(raw))
	if err != nil {
		return 0, map[string]any{}
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-api-key", c.APIKey)
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, map[string]any{}
	}
	defer res.Body.Close()
	text, _ := io.ReadAll(res.Body)
	var out map[string]any
	if json.Unmarshal(text, &out) != nil || out == nil {
		out = map[string]any{}
	}
	return res.StatusCode, out
}

// Settlement is the outcome of VerifyAndSettle.
type Settlement struct {
	OK     bool
	Payer  string
	Ref    string
	Reason string
	Replay bool
}

var replayVerify = regexp.MustCompile(`(?i)already used|replay`)
var replaySettle = regexp.MustCompile(`(?i)already settled|already being settled`)
var alreadySettled = regexp.MustCompile(`(?i)already settled`)

func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0
	case nil:
		return false
	}
	return true
}

func firstString(m map[string]any, keys ...string) (string, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			return str(v), true
		}
	}
	return "", false
}

// VerifyAndSettle verifies, then settles. Two calls because verify moves no money.
func (c CoinPay) VerifyAndSettle(ctx context.Context, payment any, expected Expected) Settlement {
	vs, v := c.post(ctx, "/api/x402/verify", map[string]any{"payment": payment, "expected": expected})
	if !truthy(v["valid"]) {
		reason, ok := firstString(v, "error", "reason")
		if !ok {
			reason = "verify failed (" + strconv.Itoa(vs) + ")"
		}
		return Settlement{Reason: reason, Replay: replayVerify.MatchString(reason)}
	}
	ss, s := c.post(ctx, "/api/x402/settle", map[string]any{"payment": payment})
	if !truthy(s["settled"]) {
		reason, ok := firstString(s, "error")
		if !ok {
			reason = "settle failed (" + strconv.Itoa(ss) + ")"
		}
		return Settlement{Reason: reason, Replay: replaySettle.MatchString(reason)}
	}
	ref, ok := firstString(s, "txHash")
	if !ok || ref == "" {
		ref = NonceOf(payment)
	}
	return Settlement{OK: true, Payer: str(get(v, "payment", "from")), Ref: ref}
}

// SettleAgain reports whether the proof has already been paid, when a settle is asked about twice.
func (c CoinPay) SettleAgain(ctx context.Context, payment any) bool {
	_, s := c.post(ctx, "/api/x402/settle", map[string]any{"payment": payment})
	if truthy(s["settled"]) {
		return true
	}
	e, _ := firstString(s, "error")
	return alreadySettled.MatchString(e)
}
