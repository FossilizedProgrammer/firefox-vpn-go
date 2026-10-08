// Package servers fetches the IP Protection proxy server list from Mozilla's
// public Remote Settings collection "vpn-serverlist".
package servers

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

const (
	defaultURL         = "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"
	recommendedCountry = "REC"
)

// Protocol describes one tunneling protocol supported by a proxy server.
// Firefox supports "masque" (HTTP/3 CONNECT-UDP) and "connect" (HTTPS
// CONNECT); production records currently carry no explicit protocols, which
// means the default: connect over TLS.
type Protocol struct {
	Name           string `json:"name"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Scheme         string `json:"scheme"`
	TemplateString string `json:"templateString"`
}

// Server is one proxy edge instance.
type Server struct {
	Hostname    string     `json:"hostname"`
	Port        int        `json:"port"`
	Quarantined bool       `json:"quarantined"`
	Protocols   []Protocol `json:"protocols"`
}

// ConnectHostPort returns the address for the HTTPS CONNECT protocol,
// applying Firefox's default when a record lists no protocols.
func (s *Server) ConnectHostPort() (string, error) {
	if s.Quarantined {
		return "", fmt.Errorf("server %s is quarantined", s.Hostname)
	}
	for _, p := range s.Protocols {
		if p.Name == "connect" {
			host := p.Host
			if host == "" {
				host = s.Hostname
			}
			port := p.Port
			if port == 0 {
				port = s.Port
			}
			return fmt.Sprintf("%s:%d", host, port), nil
		}
	}
	if len(s.Protocols) > 0 {
		return "", fmt.Errorf("server %s has no connect protocol", s.Hostname)
	}
	port := s.Port
	if port == 0 {
		port = 443
	}
	return fmt.Sprintf("%s:%d", s.Hostname, port), nil
}

type City struct {
	Code    string   `json:"code"`
	Name    string   `json:"name"`
	Servers []Server `json:"servers"`
}

type Country struct {
	Code   string `json:"code"`
	Name   string `json:"name"`
	Locked bool   `json:"locked"`
	Cities []City `json:"cities"`
}

// List is the parsed server list.
type List struct {
	Countries []Country
}

func (l *List) usableServer(city *City) *Server {
	var candidates []*Server
	for i := range city.Servers {
		if !city.Servers[i].Quarantined {
			candidates = append(candidates, &city.Servers[i])
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(candidates))))
	if err != nil {
		return candidates[0]
	}
	return candidates[n.Int64()]
}

// Pick resolves a country code ("" = recommended/anycast) to a server.
func (l *List) Pick(countryCode string) (*Server, error) {
	if countryCode == "" {
		countryCode = recommendedCountry
	}
	var country *Country
	for i := range l.Countries {
		if strings.EqualFold(l.Countries[i].Code, countryCode) {
			country = &l.Countries[i]
			break
		}
	}
	if country == nil {
		if countryCode == recommendedCountry {
			for i := range l.Countries {
				if l.Countries[i].Code == "US" {
					country = &l.Countries[i]
					break
				}
			}
		}
		if country == nil {
			return nil, fmt.Errorf("country %q not in server list", countryCode)
		}
	}
	for i := range country.Cities {
		if s := l.usableServer(&country.Cities[i]); s != nil {
			return s, nil
		}
	}
	return nil, fmt.Errorf("no usable server for country %q", country.Code)
}

// AvailableCountries lists country codes that have at least one usable server.
func (l *List) AvailableCountries() []string {
	var out []string
	for _, c := range l.Countries {
		if c.Code == recommendedCountry {
			continue
		}
		for i := range c.Cities {
			if len(c.Cities[i].Servers) > 0 {
				out = append(out, c.Code)
				break
			}
		}
	}
	return out
}

// FreeCountries returns the countries not locked behind premium
// preconditions. Firefox's UI hides locked countries from users who are not
// premium (VPN subscription, unlimited bandwidth, or default browser).
func (l *List) FreeCountries() []Country {
	var out []Country
	for _, c := range l.Countries {
		if c.Code != recommendedCountry && !c.Locked {
			out = append(out, c)
		}
	}
	return out
}

// Fetcher retrieves the server list.
type Fetcher struct {
	URL  string
	HTTP *http.Client
}

func NewFetcher() *Fetcher {
	return &Fetcher{
		URL:  defaultURL,
		HTTP: &http.Client{Timeout: 30 * time.Second},
	}
}

type recordsPage struct {
	Data []json.RawMessage `json:"data"`
}

// Fetch downloads and parses the list. Records are wrapped in Remote Settings
// envelopes; the server-list JSON itself is stored per record (flat country
// object, possibly under the record's "data"... the collection stores plain
// country objects as records, so we try both shapes).
func (f *Fetcher) Fetch() (*List, error) {
	url := f.URL
	if !strings.Contains(url, "_limit") {
		sep := "?"
		if strings.Contains(url, "?") {
			sep = "&"
		}
		url += sep + "_limit=100"
	}
	resp, err := f.HTTP.Get(url)
	if err != nil {
		return nil, fmt.Errorf("servers: fetch failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("servers: HTTP %d fetching server list", resp.StatusCode)
	}
	var page recordsPage
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, fmt.Errorf("servers: invalid response: %w", err)
	}
	if len(page.Data) == 0 {
		return nil, errors.New("servers: empty server list")
	}
	list := &List{}
	for _, raw := range page.Data {
		var country Country
		if err := json.Unmarshal(raw, &country); err != nil {
			continue
		}
		if country.Code == "" {
			// Records may nest the country under "entry".
			var wrapped struct {
				Entry Country `json:"entry"`
			}
			if err := json.Unmarshal(raw, &wrapped); err != nil || wrapped.Entry.Code == "" {
				continue
			}
			country = wrapped.Entry
		}
		list.Countries = append(list.Countries, country)
	}
	if len(list.Countries) == 0 {
		return nil, errors.New("servers: no countries parsed from server list")
	}
	return list, nil
}
