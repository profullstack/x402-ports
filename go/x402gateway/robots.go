package x402gateway

import "strings"

// RobotsOptions shapes RobotsTxt.
type RobotsOptions struct {
	SiteURL   string
	Disallow  []string
	Allow     []string
	Sitemap   *string // nil: <siteUrl>/sitemap.xml; pointer to "": omit
	Path      string  // default /crawl
	Refused   []string
	Training  []string // nil: TrainingAgents
	Retrieval []string // nil: RetrievalAgents
	Comments  []string
}

// RobotsTxt writes robots.txt with the crawlers sorted the way the gateway sorts them.
func RobotsTxt(o RobotsOptions) string {
	base := strings.TrimRight(o.SiteURL, "/")
	if o.Path == "" {
		o.Path = "/crawl"
	}
	if o.Training == nil {
		o.Training = TrainingAgents
	}
	if o.Retrieval == nil {
		o.Retrieval = RetrievalAgents
	}
	sitemap := base + "/sitemap.xml"
	if o.Sitemap != nil {
		sitemap = *o.Sitemap
	}
	welcome := func(agent string) string {
		lines := []string{"User-agent: " + agent, "Allow: /"}
		for _, p := range o.Allow {
			lines = append(lines, "Allow: "+p)
		}
		for _, p := range o.Disallow {
			lines = append(lines, "Disallow: "+p)
		}
		return strings.Join(lines, "\n")
	}
	refuse := func(agent string) string { return "User-agent: " + agent + "\nDisallow: /" }
	charge := func(agent string) string { return refuse(agent) + "\nAllow: " + o.Path }

	var lines []string
	for _, c := range o.Comments {
		lines = append(lines, "# "+c)
	}
	if len(o.Comments) > 0 {
		lines = append(lines, "")
	}
	for _, a := range o.Refused {
		lines = append(lines, refuse(a)+"\n")
	}
	for _, a := range o.Training {
		lines = append(lines, charge(a)+"\n")
	}
	for _, a := range o.Retrieval {
		lines = append(lines, welcome(a)+"\n")
	}
	lines = append(lines, welcome("*"), "")
	if sitemap != "" {
		lines = append(lines, "Sitemap: "+sitemap, "")
	}
	return strings.Join(lines, "\n")
}
