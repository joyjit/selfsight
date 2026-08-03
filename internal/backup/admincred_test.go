package backup

import "testing"

func TestAdminCredential(t *testing.T) {
	mk := func(cfg string) []byte { return buildFixtureTar(t, cfg, "shadow\n") }

	base := "system:basicSettings:apName Home\n" +
		"system:basicSettings:adminName admin\n" +
		"system:basicSettings:adminPasswd $5$salt$hash\n"

	got, err := AdminCredential(mk(base))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Same credential, unrelated config change (apName) → identical result, so
	// an ordinary restore of a different-day snapshot does NOT read as a revert.
	same, _ := AdminCredential(mk(
		"system:basicSettings:apName Garage\n" +
			"system:basicSettings:adminName admin\n" +
			"system:basicSettings:adminPasswd $5$salt$hash\n"))
	if got != same {
		t.Error("same login must compare equal regardless of other config")
	}

	// A different password hash → different result (a real revert).
	diff, _ := AdminCredential(mk(
		"system:basicSettings:adminName admin\n" +
			"system:basicSettings:adminPasswd $5$salt$OTHER\n"))
	if got == diff {
		t.Error("changed admin password must compare unequal")
	}

	// A different admin user is also a login change.
	renamed, _ := AdminCredential(mk(
		"system:basicSettings:adminName root\n" +
			"system:basicSettings:adminPasswd $5$salt$hash\n"))
	if got == renamed {
		t.Error("changed admin name must compare unequal")
	}

	// Missing fields are an error, not a silent equal — the caller fails safe.
	if _, err := AdminCredential(mk("system:basicSettings:apName Home\n")); err == nil {
		t.Error("missing admin fields must be an error")
	}
	if _, err := AdminCredential([]byte("not a tar")); err == nil {
		t.Error("garbage archive must be an error")
	}
}
