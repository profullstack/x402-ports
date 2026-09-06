package x402gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"
)

// Pass is a signed, self-describing token: cp_<payload>.<signature>, HMAC-SHA256.
type Pass struct {
	Token     string
	ExpiresAt int64
	Ref       string
}

// Claims are what a valid pass carries.
type Claims struct {
	Exp float64 `json:"exp"`
	Iat any     `json:"iat"`
	Ref any     `json:"ref"`
}

func sign(secret, data string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// MintPass mints a pass. ref may be empty (written as null); now is unix seconds, 0 means the clock.
func MintPass(secret, ref string, expiresAt, now int64) (Pass, error) {
	if now == 0 {
		now = time.Now().Unix()
	}
	if secret == "" {
		return Pass{}, errors.New("a pass needs a signing secret")
	}
	if expiresAt <= now {
		return Pass{}, errors.New("a pass needs a future expiry")
	}
	var refJSON any
	if ref != "" {
		refJSON = ref
	}
	claims := struct {
		V   int   `json:"v"`
		Iat int64 `json:"iat"`
		Exp int64 `json:"exp"`
		Ref any   `json:"ref"`
	}{1, now, expiresAt, refJSON}
	raw, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(raw)
	return Pass{Token: "cp_" + payload + "." + sign(secret, payload), ExpiresAt: expiresAt, Ref: ref}, nil
}

// ReadPass returns the claims when the signature holds and the pass is live, else nil. Never panics.
func ReadPass(token, secret string, now int64) *Claims {
	if now == 0 {
		now = time.Now().Unix()
	}
	if secret == "" || !strings.HasPrefix(token, "cp_") {
		return nil
	}
	dot := strings.IndexByte(token, '.')
	if dot < 0 {
		return nil
	}
	payload, sig := token[3:dot], token[dot+1:]
	if payload == "" || sig == "" {
		return nil
	}
	if !hmac.Equal([]byte(sign(secret, payload)), []byte(sig)) {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(payload, "="))
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return nil
	}
	if v, ok := m["v"].(float64); !ok || v != 1 {
		return nil
	}
	exp, ok := m["exp"].(float64)
	if !ok || math.IsNaN(exp) || math.IsInf(exp, 0) || exp <= float64(now) {
		return nil
	}
	return &Claims{Exp: exp, Iat: m["iat"], Ref: m["ref"]}
}
