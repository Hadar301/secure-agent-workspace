package main

import "testing"

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
