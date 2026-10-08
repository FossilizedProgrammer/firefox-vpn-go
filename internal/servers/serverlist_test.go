package servers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// fixture mirrors the shape of the live "vpn-serverlist" records (countries
// with cities/servers; no explicit "protocols" means the default HTTPS
// CONNECT protocol).
const fixture = `{
  "data": [
    {
      "code": "REC", "name": "Recommended",
      "cities": [{"code": "REC", "name": "Anycast", "servers": [
        {"hostname": "rec1.m1.fastly-masque.net", "port": 2499}
      ]}]
    },
    {
      "code": "US", "name": "United States",
      "cities": [{"code": "KJFK", "name": "New York", "servers": [
        {"hostname": "us1.m1.fastly-masque.net", "port": 2499, "quarantined": true},
        {"hostname": "us2.m1.fastly-masque.net", "port": 2499}
      ]}]
    },
    {
      "code": "DE", "name": "Germany",
      "cities": [{"code": "EDDB", "name": "Berlin", "servers": [
        {"hostname": "de1.m1.fastly-masque.net", "port": 2499,
         "protocols": [{"name": "connect", "host": "de1.m1.fastly-masque.net", "port": 8443, "scheme": "https"}]}
      ]}]
    }
  ]
}`

func newTestServer(t *testing.T) *Fetcher {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fixture))
	}))
	t.Cleanup(srv.Close)
	return &Fetcher{URL: srv.URL, HTTP: srv.Client()}
}

func TestFetchAndDefaults(t *testing.T) {
	f := newTestServer(t)
	list, err := f.Fetch()
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Countries) != 3 {
		t.Fatalf("got %d countries", len(list.Countries))
	}

	// REC entry, no explicit protocols → default connect on record port.
	s, err := list.Pick("")
	if err != nil {
		t.Fatal(err)
	}
	if hp, err := s.ConnectHostPort(); err != nil || hp != "rec1.m1.fastly-masque.net:2499" {
		t.Fatalf("Pick(\"\") = %s, %v", hp, err)
	}

	// US: first server is quarantined, must be skipped.
	s, err = list.Pick("US")
	if err != nil {
		t.Fatal(err)
	}
	if hp, _ := s.ConnectHostPort(); hp != "us2.m1.fastly-masque.net:2499" {
		t.Fatalf("Pick(US) = %s (quarantined server leaked)", hp)
	}

	// Explicit connect protocol overrides the record port.
	s, err = list.Pick("DE")
	if err != nil {
		t.Fatal(err)
	}
	if hp, _ := s.ConnectHostPort(); hp != "de1.m1.fastly-masque.net:8443" {
		t.Fatalf("Pick(DE) = %s, want explicit protocol port 8443", hp)
	}

	if len(list.AvailableCountries()) != 2 {
		t.Fatalf("AvailableCountries = %v", list.AvailableCountries())
	}
}

func TestPickUnknownCountry(t *testing.T) {
	f := newTestServer(t)
	list, err := f.Fetch()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := list.Pick("XX"); err == nil {
		t.Fatal("expected error for unknown country")
	}
}
