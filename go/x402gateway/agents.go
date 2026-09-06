// Package x402gateway sells crawl access to AI training crawlers, by the day,
// over x402, settled by CoinPay. It is a port of @profullstack/x402-gateway
// and answers the same fixtures: the same 402 body, the same signed pass
// (cp_<payload>.<hmac>), the same robots.txt, the same order of decisions.
package x402gateway

import "strings"

// TrainingAgents are training-only crawlers: refused in robots.txt, charged by the gateway.
var TrainingAgents = []string{
	"GPTBot",
	"ClaudeBot",
	"anthropic-ai",
	"CCBot",
	"meta-externalagent",
	"FacebookBot",
	"Bytespider",
	"Applebot-Extended",
}

// RetrievalAgents are named in robots.txt so their operators can see they are welcome.
var RetrievalAgents = []string{
	"OAI-SearchBot",
	"ChatGPT-User",
	"Claude-SearchBot",
	"Claude-User",
	"PerplexityBot",
	"Perplexity-User",
	"Google-Extended",
	"Bingbot",
}

// IsTrainingAgent reports whether a user agent names one of agents (substring, case-insensitive).
// A nil agents means TrainingAgents.
func IsTrainingAgent(userAgent string, agents []string) bool {
	if agents == nil {
		agents = TrainingAgents
	}
	ua := strings.ToLower(userAgent)
	if ua == "" {
		return false
	}
	for _, a := range agents {
		if strings.Contains(ua, strings.ToLower(a)) {
			return true
		}
	}
	return false
}
