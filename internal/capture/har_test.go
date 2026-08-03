package capture

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestRenderResponseBase64(t *testing.T) {
	var r harResponse
	r.Status = 200
	r.StatusText = "OK"
	r.Headers = []harHeader{{Name: "Content-Type", Value: "application/json"}}
	r.Content.Encoding = "base64"
	r.Content.Text = base64.StdEncoding.EncodeToString([]byte(`{"status":0}`))

	got := renderResponse(r)
	if !strings.HasPrefix(got, "HTTP/1.1 200 OK\r\n") {
		t.Errorf("bad status line: %q", got)
	}
	if !strings.Contains(got, `{"status":0}`) {
		t.Errorf("base64 body not decoded: %q", got)
	}
}

func TestRenderRequestSkipsPseudoHeaders(t *testing.T) {
	r := harRequest{
		Method: "POST",
		URL:    "https://192.0.2.20/api/login",
		Headers: []harHeader{
			{Name: ":method", Value: "POST"},
			{Name: "Content-Type", Value: "application/json"},
		},
	}
	r.PostData.Text = `{"user":"admin"}`
	got := renderRequest(r)
	if strings.Contains(got, ":method") {
		t.Errorf("HTTP/2 pseudo-header leaked: %q", got)
	}
	if !strings.Contains(got, "Content-Type: application/json") {
		t.Errorf("real header missing: %q", got)
	}
	if !strings.HasSuffix(got, `{"user":"admin"}`) {
		t.Errorf("body missing: %q", got)
	}
}
