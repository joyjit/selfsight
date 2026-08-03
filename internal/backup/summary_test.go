package backup

import (
	"strings"
	"testing"
)

const vapPrefix = "system:vapSettings:vapSettingTable:"

// vapCfg builds one band's slot config from field lines.
func vapCfg(band, vap string, fields ...string) string {
	var b strings.Builder
	for _, f := range fields {
		b.WriteString(vapPrefix + band + ":" + vap + ":" + f + "\n")
	}
	return b.String()
}

// The AP's signature for a deleted network — the slot's profile emptying plus
// assorted field churn on both bands — must read as one sentence, not six
// raw lines.
func TestSummarizeNetworkRemoved(t *testing.T) {
	from := vapCfg("wlan0", "vap1", "ssid psktest", "vapProfileName SSID2", "vapProfileStatus 1", "dhcpOfferBcastToUcast 1") +
		vapCfg("wlan1", "vap1", "ssid psktest", "vapProfileName SSID2", "vapProfileStatus 1", "dhcpOfferBcastToUcast 1")
	to := vapCfg("wlan0", "vap1", "ssid psktest", "vapProfileName NONE", "vapProfileStatus 0", "dhcpOfferBcastToUcast 0") +
		vapCfg("wlan1", "vap1", "ssid psktest", "vapProfileName NONE", "vapProfileStatus 0", "dhcpOfferBcastToUcast 0")

	got := Summarize(from, to)
	if len(got) != 1 {
		t.Fatalf("want exactly one sentence, got %q", got)
	}
	if got[0] != "Network “psktest” was removed" {
		t.Errorf("wrong sentence: %q", got[0])
	}
}

func TestSummarizeNetworkAdded(t *testing.T) {
	from := vapCfg("wlan0", "vap1", "vapProfileName NONE", "vapProfileStatus 0")
	to := vapCfg("wlan0", "vap1", "ssid guest", "vapProfileName SSID2", "vapProfileStatus 1")

	got := Summarize(from, to)
	if len(got) != 1 || got[0] != "Network “guest” was added (2.4 GHz only)" {
		t.Errorf("want single added sentence with band, got %q", got)
	}
}

func TestSummarizeFieldChanges(t *testing.T) {
	base := func(hide, vlan string) string {
		return vapCfg("wlan0", "vap0", "ssid HomeNet", "vapProfileName SSID1", "hideNetworkName "+hide, "vlanID "+vlan) +
			vapCfg("wlan1", "vap0", "ssid HomeNet", "vapProfileName SSID1", "hideNetworkName "+hide, "vlanID "+vlan)
	}
	got := Summarize(base("0", "1"), base("1", "20"))
	want := map[string]bool{
		"Network “HomeNet” was hidden (no longer broadcast)": true,
		"Network “HomeNet”: VLAN 1 → 20":                     true,
	}
	if len(got) != len(want) {
		t.Fatalf("want %d sentences, got %q", len(want), got)
	}
	for _, s := range got {
		if !want[s] {
			t.Errorf("unexpected sentence %q", s)
		}
	}
}

// Changes outside the network table are counted, not translated.
func TestSummarizeCountsOtherChanges(t *testing.T) {
	from := vapCfg("wlan0", "vap0", "ssid HomeNet", "vapProfileName SSID1", "hideNetworkName 0") +
		"system:trafficControl:enable 0\n"
	to := vapCfg("wlan0", "vap0", "ssid HomeNet", "vapProfileName SSID1", "hideNetworkName 1") +
		"system:trafficControl:enable 1\n"

	got := Summarize(from, to)
	if len(got) != 2 {
		t.Fatalf("want sentence + other-count, got %q", got)
	}
	if !strings.Contains(got[1], "1 other low-level setting") {
		t.Errorf("missing other-count line: %q", got)
	}
}

// Nothing understandable changed -> no summary (the raw diff stands alone).
func TestSummarizeNothingKnown(t *testing.T) {
	if got := Summarize("system:a:b 1\n", "system:a:b 2\n"); len(got) != 0 {
		t.Errorf("want no summary, got %q", got)
	}
}
