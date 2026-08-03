package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A successful live read populates the cache; the cached endpoint then serves
// the same reading, stamped with when it was taken, without touching the AP.
func TestStatusCachedAfterLiveRead(t *testing.T) {
	ts := fakeAP(false)
	t.Cleanup(ts.Close)
	srv := serverForAP(t, ts)

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/devices/ap1/status/cached", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("before any live read: want 404, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/devices/ap1/status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("live read: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	ts.Close() // AP goes away; the cache must still answer
	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/devices/ap1/status/cached", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("cached read: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var got struct {
		FetchedAt time.Time `json:"fetchedAt"`
		Status    struct {
			System struct{ Serial string } `json:"system"`
		} `json:"status"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.System.Serial != "S1" {
		t.Errorf("cached reading lost data: %s", rr.Body.String())
	}
	if got.FetchedAt.IsZero() || time.Since(got.FetchedAt) > time.Minute {
		t.Errorf("bad fetchedAt: %v", got.FetchedAt)
	}
}
