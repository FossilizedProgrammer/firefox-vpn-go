package servers

import (
	"os"
	"testing"
)

// Live check against Mozilla's real Remote Settings; skipped unless
// FFVPN_LIVE_TEST=1 (needs network access).
func TestLiveFetch(t *testing.T) {
	if os.Getenv("FFVPN_LIVE_TEST") != "1" {
		t.Skip("live test disabled; set FFVPN_LIVE_TEST=1")
	}
	list, err := NewFetcher().Fetch()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("countries: %v", list.AvailableCountries())
	s, err := list.Pick("")
	if err != nil {
		t.Fatal(err)
	}
	hp, _ := s.ConnectHostPort()
	t.Logf("recommended edge: %s", hp)
}
