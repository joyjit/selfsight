package core

import "testing"

func desired() Desired {
	return Desired{
		SSIDs: []SSID{
			{Name: "HomeNet", VLAN: 1, Security: "wpa2-psk"},
			{Name: "Guest", VLAN: 20, Security: "wpa2-psk"},
		},
		Radios: map[string]Radio{
			"2g": {Channel: "auto"},
			"5g": {Channel: "44"},
		},
	}
}

func TestDriftInSync(t *testing.T) {
	// Observed matches desired: HomeNet present (vlan 1, WPA2-PSK/AES), Guest
	// present, 5g on channel 44, 2g auto (not checked).
	rep := ComputeDrift(desired(),
		[]ObservedSSID{
			{Name: "HomeNet", VLAN: 1, Security: "WPA2-PSK/AES"},
			{Name: "Guest", VLAN: 20, Security: "WPA2-PSK/AES"},
		},
		[]ObservedRadio{{Band: "2g", Channel: "6"}, {Band: "5g", Channel: "44"}},
	)
	if !rep.InSync {
		t.Fatalf("expected in sync, got drift: %+v", rep.Items)
	}
}

func TestDriftDetectsDifferences(t *testing.T) {
	rep := ComputeDrift(desired(),
		[]ObservedSSID{
			{Name: "HomeNet", VLAN: 5, Security: "WPA2-PSK/AES"}, // vlan drift 1 vs 5
			// Guest missing entirely
		},
		[]ObservedRadio{{Band: "5g", Channel: "36"}}, // channel drift 44 vs 36
	)
	if rep.InSync {
		t.Fatal("expected drift")
	}
	want := map[string]string{ // scope+field -> observed
		"ssid:HomeNet/vlan":  "5",
		"ssid:Guest/present": "missing",
		"radio:5g/channel":   "36",
	}
	for _, it := range rep.Items {
		key := it.Scope + "/" + it.Field
		if exp, ok := want[key]; ok {
			if it.Observed != exp || it.InSync {
				t.Errorf("%s: observed=%q inSync=%v", key, it.Observed, it.InSync)
			}
			delete(want, key)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing expected drift items: %v", want)
	}
}

func TestDriftOnlyChecksDeclared(t *testing.T) {
	// No desired config => never any drift, whatever the device reports.
	rep := ComputeDrift(Desired{},
		[]ObservedSSID{{Name: "Whatever", VLAN: 9, Security: "open"}},
		[]ObservedRadio{{Band: "5g", Channel: "100"}},
	)
	if !rep.InSync || len(rep.Items) != 0 {
		t.Errorf("undeclared config must not drift: %+v", rep)
	}
	if rep.Items == nil {
		t.Error("Items must be a non-nil slice so it serializes as [] not null")
	}
}

func TestDriftTriStateBooleans(t *testing.T) {
	tr, fa := true, false

	// Declared hidden/enabled drift against the observed values.
	rep := ComputeDrift(Desired{
		SSIDs:  []SSID{{Name: "Net", Hidden: &tr, Enabled: &tr}},
		Radios: map[string]Radio{"5g": {Enabled: &fa}},
	},
		[]ObservedSSID{{Name: "Net", Hidden: false, Enabled: true}},
		[]ObservedRadio{{Band: "5g", Channel: "36", Enabled: &tr}},
	)
	if rep.InSync {
		t.Fatalf("hidden and radio-enabled drift expected: %+v", rep)
	}
	byField := map[string]DriftItem{}
	for _, it := range rep.Items {
		byField[it.Scope+"/"+it.Field] = it
	}
	if it := byField["ssid:Net/hidden"]; it.InSync || it.Desired != "yes" || it.Observed != "no" {
		t.Errorf("hidden drift wrong: %+v", it)
	}
	if it := byField["ssid:Net/enabled"]; !it.InSync {
		t.Errorf("enabled matches and must be in sync: %+v", it)
	}
	if it := byField["radio:5g/enabled"]; it.InSync || it.Desired != "off" || it.Observed != "on" {
		t.Errorf("radio enabled drift wrong: %+v", it)
	}

	// nil (undeclared) booleans are unmanaged; an unobserved radio status
	// (Enabled nil) never drifts even when declared.
	rep = ComputeDrift(Desired{
		SSIDs:  []SSID{{Name: "Net"}},
		Radios: map[string]Radio{"5g": {Enabled: &fa}},
	},
		[]ObservedSSID{{Name: "Net", Hidden: true, Enabled: false}},
		[]ObservedRadio{{Band: "5g", Channel: "36"}}, // no radioStatus observed
	)
	if !rep.InSync {
		t.Errorf("undeclared/unobserved booleans must not drift: %+v", rep)
	}
}
