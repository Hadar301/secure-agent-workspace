package cdh

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (r roundTrip) RoundTrip(q *http.Request) (*http.Response, error) { return r(q) }
func client(status int, body string) *Client {
	return &Client{HTTP: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "127.0.0.1:8006" {
			panic("external resource request")
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}}
}
func TestFetchAndSafeErrors(t *testing.T) {
	resource := "default/saw-alice-0123456789abcdef/inference"
	fields, err := client(200, `{"api_key":"synthetic-fixture"}`).Fetch(context.Background(), resource)
	if err != nil || fields["api_key"] != "synthetic-fixture" {
		t.Fatal("resource fetch failed")
	}
	for _, tc := range []struct {
		status     int
		body, want string
	}{
		{403, "private server detail", "CredentialReleaseDenied"},
		{500, "private server detail", "CredentialFetchUnavailable"},
		{200, "private server detail", "CredentialMaterialRejected"},
		{200, strings.Repeat("x", MaxResourceBytes+1), "CredentialMaterialRejected"},
		{302, "private server detail", "CredentialFetchUnavailable"},
	} {
		_, err := client(tc.status, tc.body).Fetch(context.Background(), resource)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("unsafe failure for status %d", tc.status)
		}
	}
	for _, bad := range []string{"../inference", "default/saw-alice-0123456789abcdef/../other", "https://example.test/x", "default/saw-alice/inference"} {
		if _, err := client(200, `{}`).Fetch(context.Background(), bad); err == nil {
			t.Fatal("accepted invalid resource")
		}
	}
}
func TestFetchHasBoundedRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	_, err := client(503, "private").FetchAll(ctx, map[string]string{"inference": "default/saw-alice-0123456789abcdef/inference"})
	if err == nil || err.Error() != "CredentialFetchUnavailable" {
		t.Fatal("deadline not enforced")
	}
}
