package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMemoryStoreHasNoCredentialFileFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	policy := `{"markerPrefix":"saw","allowHosts":["api.example.test"],"profiles":{"nvidia":["api.example.test"]},"bindings":[{"secret":"inference","key":"api_key","providers":["nvidia"]}]}`
	if err := os.WriteFile(path, []byte(policy), 0600); err != nil {
		t.Fatal(err)
	}
	material := map[string]map[string]string{"inference": {"api_key": "synthetic-fixture"}}
	store, err := NewMemory(path, material)
	if err != nil {
		t.Fatal(err)
	}
	material["inference"]["api_key"] = "changed"
	if err := store.Reload(); err == nil {
		t.Fatal("memory policy accepted reload")
	}
	_, resolved, err := store.Snapshot()
	if err != nil || len(resolved) != 1 || resolved[0].Value != "synthetic-fixture" {
		t.Fatal("memory snapshot changed")
	}
	if _, err = NewMemory(path, map[string]map[string]string{}); err == nil {
		t.Fatal("accepted missing material")
	}
}

func TestMemoryDataDoesNotReadOrReloadPolicyFiles(t *testing.T) {
	raw := []byte(`{"markerPrefix":"saw","allowHosts":["api.example.test"],"profiles":{"nvidia":["api.example.test"]},"bindings":[{"secret":"inference","key":"api_key","providers":["nvidia"]}]}`)
	material := map[string]map[string]string{"inference": {"api_key": "memory-fixture"}}
	store, err := NewMemoryData(raw, material)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = 'x'
	}
	material["inference"]["api_key"] = "changed"
	_, resolved, err := store.Snapshot()
	if err != nil || len(resolved) != 1 || resolved[0].Value != "memory-fixture" {
		t.Fatal("memory configuration changed or read external files")
	}
	if store.path != "" || store.secretsDir != "" || store.Reload() == nil {
		t.Fatal("memory configuration retained a filesystem fallback")
	}
}

func TestMemoryDataRejectsUnknownPolicyAndTrailingValues(t *testing.T) {
	for _, raw := range []string{`{"unreviewed":"private-fixture-marker"}`, `{} {}`, `null`, `not-json`} {
		if _, err := NewMemoryData([]byte(raw), nil); err == nil || err.Error() != "CredentialPolicyRejected" {
			t.Fatal("malformed public policy did not produce a safe rejection")
		}
	}
}
