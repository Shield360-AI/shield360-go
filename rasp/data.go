package rasp

import (
	_ "embed"
	"encoding/json"
)

// The contract's shared data, embedded. Both files are byte-identical copies
// of sdk/rasp (rules/default-rules.json, testdata/dnslog-domains.json); a
// test says so.

//go:embed data/default-rules.json
var defaultRulesJSON []byte

//go:embed data/dnslog-domains.json
var dnslogJSON []byte

var dnslogSuffixes, dnslogHosts = func() ([]string, map[string]bool) {
	var d struct {
		Domains []string `json:"domains"`
		Hosts   []string `json:"hosts"`
	}
	_ = json.Unmarshal(dnslogJSON, &d)
	hosts := make(map[string]bool, len(d.Hosts))
	for _, h := range d.Hosts {
		hosts[h] = true
	}
	return d.Domains, hosts
}()
