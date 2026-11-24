package main

import (
	"strings"
	"testing"
)

func TestConfidentialSupervisorRequiresGuestLocalProxy(t *testing.T) {
	good := []string{"/openshell-supervisor", "--upstream-proxy", "http://127.0.0.1:3128", "--upstream-proxy-ca-bundle", "/run/openshell/saw-proxy-ca.pem"}
	if !validSupervisorArgs(good) {
		t.Fatal("rejected local proxy")
	}
	for _, bad := range [][]string{
		{}, {"/other"}, {"/openshell-supervisor"},
		append(append([]string{}, good...), "--upstream-no-proxy", "*"),
		append(append([]string{}, good...), "--upstream-no-proxy=*"),
		append(append([]string{}, good...), "--upstream-proxy=http://external.example.test"),
		append(append([]string{}, good...), "--upstream-proxy", "http://external.example.test"),
		append(append([]string{}, good...), "--upstream-proxy-ca-bundle", "/other.pem"),
	} {
		if validSupervisorArgs(bad) {
			t.Fatal("accepted proxy bypass")
		}
	}
}

func TestMeasuredBootstrapHasNoFileFallback(t *testing.T) {
	raw := `{"schemaVersion":1,"policy":{"markerPrefix":"saw","allowHosts":["api.example.test"],"profiles":{"nvidia":["api.example.test"]},"bindings":[{"secret":"inference","key":"api_key","providers":["nvidia"]}]},"resources":{"inference":"default/saw-alice-0123456789abcdef/inference"},"publicCAFile":"/run/openshell/saw-proxy-ca.pem"}`
	env := confidentialBootstrapEnv + "=" + raw
	cfg, err := loadConfidentialBootstrap([]string{env})
	if err != nil || cfg.SchemaVersion != 1 || cfg.Resources["inference"] == "" {
		t.Fatal("valid measured bootstrap was rejected")
	}
	for _, input := range [][]string{
		{}, {"SAW_CONFIDENTIAL_CONFIG=/unmeasured/config.json"},
		{env, env}, {env, "SAW_CONFIDENTIAL_CONFIG=/unmeasured/config.json"},
		{confidentialBootstrapEnv + "={}"}, {env + ` {}`},
		{confidentialBootstrapEnv + "=" + strings.Repeat("x", 65537)},
		{confidentialBootstrapEnv + "=" + strings.Replace(raw, `"schemaVersion":1`, `"schemaVersion":2`, 1)},
		{confidentialBootstrapEnv + "=" + strings.Replace(raw, `"schemaVersion":1`, `"unknown":"private-fixture-marker","schemaVersion":1`, 1)},
	} {
		if _, err := loadConfidentialBootstrap(input); err == nil || err.Error() != "AttestationConfigurationRejected" {
			t.Fatal("unsafe bootstrap did not produce a safe rejection")
		}
	}
}
