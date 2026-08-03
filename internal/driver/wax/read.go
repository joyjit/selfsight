package wax

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"selfsight/internal/device"
)

// Read payloads: the exact subtrees the AP expects, with empty-string leaves.
// These match testdata/wax610/*.request.json byte-for-byte in shape and are
// proven on live hardware. Keep them in sync with the fixtures.
const (
	payloadSystemInfo  = `{"system":{"monitor":{"channelWidth":{"wlan0":"","wlan1":""},"operateMode":{"wlan0":"","wlan1":""},"currentChannel":{"wlan0":"","wlan1":""},"radioApStatus":{"wlan0":{"numberOfStations":""},"wlan1":{"numberOfStations":""}},"stats":{"wlan0":{"traffic":"","channelUtil":"","selfChannelUtil":"","obssChannelUtil":""},"wlan1":{"traffic":"","channelUtil":"","selfChannelUtil":"","obssChannelUtil":""},"lan":{"traffic":""}},"lanStatus":{"eth0":""},"internetConnectivityStatus":"","totalNumberOfDevices":"","wdsMode":"","sysSerialNumber":"","ethernetMacAddress":"","sysVersion":"","defaultGateway":"","sysCountryRegion":"","defaultGatewayStatus":"","ipAddress":"","DeviceInfo":{"UpTime":""},"FiveGhzSupport":{"wlan1":""},"FiveGHzLowHighSupport":{"wlan":""}},"basicSettings":{"deviceMode":"","cloudStatus":"","apName":"","sysCountryRegion":"","dhcpClientStatus":"","engageStatus":"","fqdn":""}}}`
	payloadRadios      = `{"system":{"wlanSettings":{"wlanSettingTable":{"wlan0":{"radioStatus":"","maxWirelessClients":""},"wlan1":{"radioStatus":"","maxWirelessClients":""}}}}}`
	payloadSSIDDetails = `{"system":{"wlanSettings":{"wlanSettingTable":{"ssidGetDetails":""}}}}`
	payloadClients     = `{"system":{"monitor":{"radioApStatus":{"totalNumberOfStations":""},"clientList":""}}}`
	// payloadClientList asks for the full per-client table per radio. 3146087 is
	// the column bitmask that yields ip/mac/hname/ssid/dOs/mode/vlanID. Only a
	// standalone AP answers this (status 0); an Insight-managed one returns 100.
	payloadClientList = `{"system":{"monitor":{"optCliList":{"wlan0":{"3146087":""},"wlan1":{"3146087":""}}}}}`
	payloadFirmware   = `{"system":{"FwUpdate":{"ImageAvailable":"","ImageVersion":"","LastcheckedDate":"","releasenotesurl":""}}}`
)

// bandLabel maps the AP's internal radio keys to human bands.
var bandLabel = map[string]string{"wlan0": "2.4 GHz", "wlan1": "5 GHz", "wlan2": "6 GHz"}

// SystemInfo and its sibling status types are the vendor-neutral shapes
// from internal/device — aliased so this package reads naturally.
type SystemInfo = device.SystemInfo

// RadioStat is one band's live operating state.
type RadioStat = device.RadioStat

// SystemInfo reads identity, network, and live radio state in one call.
func (c *Client) SystemInfo(ctx context.Context) (*SystemInfo, error) {
	var r struct {
		System struct {
			Monitor struct {
				ChannelWidth   map[string]string          `json:"channelWidth"`
				OperateMode    map[string]string          `json:"operateMode"`
				CurrentChannel map[string]string          `json:"currentChannel"`
				RadioApStatus  map[string]json.RawMessage `json:"radioApStatus"`
				Stats          map[string]struct {
					Traffic     string `json:"traffic"`
					ChannelUtil string `json:"channelUtil"`
					SelfUtil    string `json:"selfChannelUtil"`
					ObssUtil    string `json:"obssChannelUtil"`
				} `json:"stats"`
				TotalDevices string `json:"totalNumberOfDevices"`
				Serial       string `json:"sysSerialNumber"`
				MAC          string `json:"ethernetMacAddress"`
				Version      string `json:"sysVersion"`
				Gateway      string `json:"defaultGateway"`
				GatewayState string `json:"defaultGatewayStatus"`
				IPAddress    string `json:"ipAddress"`
				DeviceInfo   struct {
					UpTime string `json:"UpTime"`
				} `json:"DeviceInfo"`
			} `json:"monitor"`
			Basic struct {
				CloudStatus string `json:"cloudStatus"`
				APName      string `json:"apName"`
				FQDN        string `json:"fqdn"`
			} `json:"basicSettings"`
		} `json:"system"`
	}
	if err := c.socket(ctx, payloadSystemInfo, &r); err != nil {
		return nil, err
	}
	m := r.System.Monitor
	si := &SystemInfo{
		Name:       r.System.Basic.APName,
		Serial:     m.Serial,
		MAC:        m.MAC,
		Firmware:   m.Version,
		IP:         m.IPAddress,
		Gateway:    m.Gateway,
		GatewayUp:  strings.EqualFold(m.GatewayState, "Reachable") || m.GatewayState == "1",
		Uptime:     m.DeviceInfo.UpTime,
		Standalone: r.System.Basic.CloudStatus != "1",
		Devices:    atoi(m.TotalDevices),
		FQDN:       unsetFQDN(r.System.Basic.FQDN),
	}
	for _, band := range sortedKeys(m.OperateMode) {
		si.Radios = append(si.Radios, RadioStat{
			Band:         bandLabel[band],
			Mode:         m.OperateMode[band],
			Channel:      m.CurrentChannel[band],
			ChannelWidth: m.ChannelWidth[band],
			Stations:     stationsOf(m.RadioApStatus[band]),
			Traffic:      m.Stats[band].Traffic,
			ChannelUtil:  m.Stats[band].ChannelUtil,
			SelfUtil:     m.Stats[band].SelfUtil,
			ObssUtil:     m.Stats[band].ObssUtil,
		})
	}
	return si, nil
}

// RadioSetting is one band's configured state (not live stats).
type RadioSetting = device.RadioSetting

// RadioSettings reads per-band radio on/off and client cap.
func (c *Client) RadioSettings(ctx context.Context) ([]RadioSetting, error) {
	var r struct {
		System struct {
			WlanSettings struct {
				Table map[string]struct {
					RadioStatus string `json:"radioStatus"`
					MaxClients  string `json:"maxWirelessClients"`
				} `json:"wlanSettingTable"`
			} `json:"wlanSettings"`
		} `json:"system"`
	}
	if err := c.socket(ctx, payloadRadios, &r); err != nil {
		return nil, err
	}
	var out []RadioSetting
	for _, band := range sortedKeys(r.System.WlanSettings.Table) {
		v := r.System.WlanSettings.Table[band]
		out = append(out, RadioSetting{
			Band:       bandLabel[band],
			On:         v.RadioStatus == "1",
			MaxClients: atoi(v.MaxClients),
		})
	}
	return out, nil
}

// SSID is one configured wireless network (deduped across bands).
type SSID = device.SSID

// authLabel/encLabel translate the AP's numeric codes.
func securityLabel(auth, enc int) string {
	a := map[int]string{0: "Open", 32: "WPA2-PSK", 64: "WPA3-SAE", 96: "WPA2/WPA3"}[auth]
	if a == "" {
		a = "auth" + strconv.Itoa(auth)
	}
	if auth == 0 {
		return a
	}
	e := map[int]string{4: "AES", 8: "TKIP", 12: "AES+TKIP"}[enc]
	if e == "" {
		e = "enc" + strconv.Itoa(enc)
	}
	return a + "/" + e
}

// SSIDs reads the full wireless config (ssidGetDetails) and returns one entry
// per configured SSID, listing the bands it runs on. Pre-shared keys are read
// by the AP but deliberately not surfaced here.
func (c *Client) SSIDs(ctx context.Context) ([]SSID, error) {
	var r struct {
		System struct {
			WlanSettings struct {
				Table struct {
					Details map[string]json.RawMessage `json:"ssidGetDetails"`
				} `json:"wlanSettingTable"`
			} `json:"wlanSettings"`
		} `json:"system"`
	}
	if err := c.socket(ctx, payloadSSIDDetails, &r); err != nil {
		return nil, err
	}
	type vap struct {
		SSID       string `json:"ssid"`
		Hidden     int    `json:"hideNetworkName"`
		Status     int    `json:"vapProfileStatus"`
		AuthType   int    `json:"authenticationType"`
		Encryption int    `json:"encryption"`
		VLAN       int    `json:"vlanID"`
	}

	var out []SSID
	for _, slot := range sortedKeys(r.System.WlanSettings.Table.Details) {
		var bands map[string]json.RawMessage
		if err := json.Unmarshal(r.System.WlanSettings.Table.Details[slot], &bands); err != nil {
			continue
		}
		var s SSID
		found := false
		for _, bandKey := range sortedKeys(bands) {
			if !strings.HasPrefix(bandKey, "wlan") {
				continue // "band" and other scalar fields
			}
			// The slot's network sits in one vap per band, but the vap key
			// varies (SSID1 uses vap0, later slots vap1+) — scan them all.
			var vaps map[string]json.RawMessage
			if err := json.Unmarshal(bands[bandKey], &vaps); err != nil {
				continue
			}
			var v vap
			for _, vapKey := range sortedKeys(vaps) {
				var cand vap
				if err := json.Unmarshal(vaps[vapKey], &cand); err == nil && cand.SSID != "" {
					v = cand
					break
				}
			}
			if v.SSID == "" {
				continue
			}
			if !found {
				s = SSID{
					Name:     v.SSID,
					VLAN:     v.VLAN,
					Security: securityLabel(v.AuthType, v.Encryption),
					Hidden:   v.Hidden == 1,
					Enabled:  v.Status == 1,
				}
				found = true
			}
			s.Bands = append(s.Bands, bandLabel[bandKey])
		}
		if found {
			out = append(out, s)
		}
	}
	return out, nil
}

// Clients is the connected-client summary.
type Clients = device.Clients

// SSIDCount is one SSID's client count on one band.
type SSIDCount = device.SSIDCount

// Clients reads the connected-client counts.
func (c *Client) Clients(ctx context.Context) (*Clients, error) {
	var r struct {
		System struct {
			Monitor struct {
				RadioApStatus struct {
					Total string `json:"totalNumberOfStations"`
				} `json:"radioApStatus"`
				ClientList map[string]json.RawMessage `json:"clientList"`
			} `json:"monitor"`
		} `json:"system"`
	}
	if err := c.socket(ctx, payloadClients, &r); err != nil {
		return nil, err
	}
	out := &Clients{Total: atoi(r.System.Monitor.RadioApStatus.Total)}
	for _, band := range sortedKeys(r.System.Monitor.ClientList) {
		var rows []struct {
			SSID  string `json:"ssid"`
			Count string `json:"numberOfClients"`
		}
		if err := json.Unmarshal(r.System.Monitor.ClientList[band], &rows); err != nil {
			continue // lan is an object, not a list, when empty
		}
		for _, row := range rows {
			if row.SSID == "" {
				continue
			}
			out.PerSSID = append(out.PerSSID, SSIDCount{
				SSID:  row.SSID,
				Band:  bandLabel[band],
				Count: atoi(row.Count),
			})
		}
	}
	return out, nil
}

// ClientDetail is one connected station. Signal/rate aren't in this table;
// the AP only exposes them via a separate per-client call not modeled here.
type ClientDetail = device.ClientDetail

// ClientList reads the full connected-client table (per radio). A client can
// appear under more than one radio, so it dedupes by MAC, keeping the first.
func (c *Client) ClientList(ctx context.Context) ([]ClientDetail, error) {
	var r struct {
		System struct {
			Monitor struct {
				OptCliList map[string]map[string]json.RawMessage `json:"optCliList"`
			} `json:"monitor"`
		} `json:"system"`
	}
	if err := c.socket(ctx, payloadClientList, &r); err != nil {
		return nil, err
	}
	var out []ClientDetail
	seen := map[string]bool{}
	for _, band := range sortedKeys(r.System.Monitor.OptCliList) {
		for _, col := range r.System.Monitor.OptCliList[band] {
			var rows []struct {
				IP     string `json:"ip"`
				MAC    string `json:"mac"`
				Hname  string `json:"hname"`
				SSID   string `json:"ssid"`
				DOs    string `json:"dOs"`
				Mode   string `json:"mode"`
				VlanID string `json:"vlanID"`
			}
			if err := json.Unmarshal(col, &rows); err != nil {
				continue // empty radios come back as {} not [], skip them
			}
			for _, row := range rows {
				if row.MAC == "" || seen[row.MAC] {
					continue
				}
				seen[row.MAC] = true
				out = append(out, ClientDetail{
					Hostname: row.Hname,
					MAC:      row.MAC,
					IP:       row.IP,
					SSID:     row.SSID,
					Band:     bandLabel[band],
					OS:       row.DOs,
					Mode:     row.Mode,
					VLAN:     atoi(row.VlanID),
				})
			}
		}
	}
	return out, nil
}

// Firmware is the AP's firmware/update state.
type Firmware = device.Firmware

// Firmware reads the current firmware-update status (does not trigger a check).
func (c *Client) Firmware(ctx context.Context) (*Firmware, error) {
	var r struct {
		System struct {
			FwUpdate struct {
				ImageAvailable string `json:"ImageAvailable"`
				ImageVersion   string `json:"ImageVersion"`
				LastChecked    string `json:"LastcheckedDate"`
				ReleaseNotes   string `json:"releasenotesurl"`
			} `json:"FwUpdate"`
		} `json:"system"`
	}
	if err := c.socket(ctx, payloadFirmware, &r); err != nil {
		return nil, err
	}
	return &Firmware{
		UpdateAvailable: r.System.FwUpdate.ImageAvailable == "1",
		AvailableImage:  r.System.FwUpdate.ImageVersion,
		LastChecked:     r.System.FwUpdate.LastChecked,
		ReleaseNotesURL: r.System.FwUpdate.ReleaseNotes,
	}, nil
}

// --- small helpers --- //

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// unsetFQDN maps the AP's "no FQDN configured" sentinel to an empty string. The
// vendor UI stores a blank field as the literal "0" and treats that value as
// unset on the way back in, so it is a sentinel and never a real name — a
// single-label "0" is not a fully qualified domain name in any case.
func unsetFQDN(s string) string {
	if s == "0" {
		return ""
	}
	return strings.TrimSpace(s)
}

func stationsOf(raw json.RawMessage) int {
	var v struct {
		N string `json:"numberOfStations"`
	}
	_ = json.Unmarshal(raw, &v)
	return atoi(v.N)
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
