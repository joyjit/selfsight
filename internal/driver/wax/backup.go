package wax

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
)

// Backup is a device configuration backup: the AP's own encrypted config
// archive plus the filename it advertised.
type Backup struct {
	Filename string
	Data     []byte
}

// Backup downloads the AP's configuration archive. It is read-only — it changes
// nothing on the device — and is the safety net taken before any config write.
//
// Two steps (both warm-jar authenticated): POST /LogFile with method 3 and the
// admin password (the AP re-confirms the password before handing out a backup),
// then GET /wac510-backup for the archive, whose name comes from the
// Content-Disposition header. The archive is opaque/encrypted (restore-only).
func (c *Client) Backup(ctx context.Context, adminPassword string) (*Backup, error) {
	// 1. Authorize the backup.
	body, err := json.Marshal(map[string]any{"method": 3, "password": adminPassword})
	if err != nil {
		return nil, err
	}
	base, err := c.base(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/LogFile", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	c.sign(req)
	resp, err := c.http.Do(req)
	if err != nil {
		c.forgetDial()
		return nil, fmt.Errorf("wax: backup authorize: %w", err)
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	var env struct {
		Status apiStatus `json:"status"`
	}
	if err := json.Unmarshal(respBody, &env); err != nil {
		return nil, fmt.Errorf("wax: backup authorize: bad response (HTTP %d): %w", resp.StatusCode, err)
	}
	if err := env.Status.err(); err != nil {
		return nil, fmt.Errorf("wax: backup authorize: %w", err)
	}

	// 2. Download the archive.
	greq, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/wac510-backup", nil)
	if err != nil {
		return nil, err
	}
	c.sign(greq)
	gresp, err := c.http.Do(greq)
	if err != nil {
		c.forgetDial()
		return nil, fmt.Errorf("wax: backup download: %w", err)
	}
	defer gresp.Body.Close()
	if gresp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wax: backup download: HTTP %d", gresp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(gresp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("wax: backup download returned no data")
	}
	return &Backup{Filename: backupFilename(gresp.Header.Get("Content-Disposition")), Data: data}, nil
}

// backupFilename extracts the filename from a Content-Disposition header,
// falling back to a generic name.
func backupFilename(cd string) string {
	if cd != "" {
		if _, params, err := mime.ParseMediaType(cd); err == nil {
			if fn := strings.TrimSpace(params["filename"]); fn != "" {
				return fn
			}
		}
	}
	return "wax-config-backup.tar"
}
