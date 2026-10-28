package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSharedSecretUsesAllowedTypesAndExplicitProviderNarrowsHosts(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "secrets", "inference")
	if err := os.MkdirAll(secret, 0700); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(root, "config.json")
	if err := os.WriteFile(policy, []byte(`{"markerPrefix":"saw-cred","allowHosts":["api.example.test","other.example.test","custom.example.test"],"profiles":{"nvidia":["api.example.test"],"build":["api.example.test"],"openai":["other.example.test"]},"bindings":[{"secret":"inference","key":"api_key","providers":["nvidia","build","openai","custom-inference"]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"api_key": "test-key", "url": "https://custom.example.test/v1"} {
		if err := os.WriteFile(filepath.Join(secret, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	store, err := New(policy, filepath.Join(root, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		provider string
		hosts    []string
	}{
		{"", []string{"api.example.test", "other.example.test", "custom.example.test"}},
		{"nvidia", []string{"api.example.test", "custom.example.test"}},
		{"custom-inference", []string{"custom.example.test"}},
	} {
		if err := os.WriteFile(filepath.Join(secret, "provider"), []byte(tc.provider), 0600); err != nil {
			t.Fatal(err)
		}
		_, bindings, err := store.Snapshot()
		if err != nil || len(bindings) != 1 {
			t.Fatalf("provider %q: %v", tc.provider, err)
		}
		if !reflect.DeepEqual(bindings[0].Hosts, tc.hosts) {
			t.Fatalf("provider %q: hosts %v, want %v", tc.provider, bindings[0].Hosts, tc.hosts)
		}
	}
	if err := os.WriteFile(filepath.Join(secret, "provider"), []byte("unbound"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Snapshot(); err == nil {
		t.Fatal("an explicit unbound provider must be refused")
	}
}

func TestSnapshotFollowsSecretRotation(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "secrets", "inference")
	if err := os.MkdirAll(secret, 0700); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(root, "config.json")
	if err := os.WriteFile(policy, []byte(`{"markerPrefix":"saw-cred","allowHosts":["api.example.test"],"profiles":{"nvidia":["api.example.test"]},"bindings":[{"secret":"inference","key":"api_key","providers":["nvidia"]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"provider": "nvidia", "api_key": "first-key"} {
		if err := os.WriteFile(filepath.Join(secret, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	store, err := New(policy, filepath.Join(root, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	_, bindings, err := store.Snapshot()
	if err != nil || bindings[0].Value != "first-key" {
		t.Fatalf("first snapshot: %v %v", bindings, err)
	}
	if err := os.WriteFile(filepath.Join(secret, "api_key"), []byte("rotated-key"), 0600); err != nil {
		t.Fatal(err)
	}
	_, bindings, err = store.Snapshot()
	if err != nil || bindings[0].Value != "rotated-key" {
		t.Fatalf("rotated snapshot: %v %v", bindings, err)
	}
	if err := os.WriteFile(filepath.Join(secret, "url"), []byte("http://private.example.test:8000/v1"), 0600); err != nil {
		t.Fatal(err)
	}
	_, bindings, err = store.Snapshot()
	if err != nil || len(bindings[0].Hosts) != 1 || bindings[0].Hosts[0] != "api.example.test" {
		t.Fatalf("plain HTTP URL must not become an intercept binding: %v %v", bindings, err)
	}
	if err := os.WriteFile(filepath.Join(secret, "url"), []byte("https://custom.example.test/v1"), 0600); err != nil {
		t.Fatal(err)
	}
	_, bindings, err = store.Snapshot()
	if err != nil || len(bindings[0].Hosts) != 2 || bindings[0].Hosts[1] != "custom.example.test" {
		t.Fatalf("custom HTTPS host was not bound: %v %v", bindings, err)
	}
	if err := os.Remove(filepath.Join(secret, "api_key")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Snapshot(); err == nil {
		t.Fatal("missing key must make the proxy unready")
	}
}

func TestKeylessHTTPDoesNotRequireAnInterceptBinding(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "secrets", "inference")
	if err := os.MkdirAll(secret, 0700); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(root, "config.json")
	if err := os.WriteFile(policy, []byte(`{"markerPrefix":"saw-cred","allowHosts":["api.example.test"],"profiles":{},"bindings":[{"secret":"inference","key":"api_key","providers":["custom-inference"]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := New(policy, filepath.Join(root, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"", "unused-key"} {
		if err := os.WriteFile(filepath.Join(secret, "api_key"), []byte(key), 0600); err != nil {
			t.Fatal(err)
		}
		for _, endpoint := range []string{"http://models.example.test:8000/v1", "https://models.example.test/v1"} {
			if err := os.WriteFile(filepath.Join(secret, "url"), []byte(endpoint), 0600); err != nil {
				t.Fatal(err)
			}
			_, bindings, err := store.Snapshot()
			if endpoint[:5] == "http:" {
				if err != nil || len(bindings) != 0 {
					t.Fatalf("HTTP must stay ready without intercepting: %v %v", bindings, err)
				}
			} else if key == "" && err == nil {
				t.Fatal("HTTPS still requires its bound key")
			} else if key != "" && (err != nil || len(bindings) != 1) {
				t.Fatalf("HTTPS must still bind its key: %v %v", bindings, err)
			}
		}
	}
}

func TestWildcardIsOneLabel(t *testing.T) {
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"us-aiplatform.googleapis.com", true},
		{"us.east-aiplatform.googleapis.com", false},
		{"else.googleapis.com", false},
	} {
		if got := MatchHost(tc.host, "*-aiplatform.googleapis.com"); got != tc.want {
			t.Fatalf("%s: got %t, want %t", tc.host, got, tc.want)
		}
	}
}
