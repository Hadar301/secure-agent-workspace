// Package cdh fetches registration-scoped resources from the guest-local API.
// It never reads Kubernetes Secrets and never returns response bodies in errors.
package cdh

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"
)

const MaxResourceBytes = 1024 * 1024

var resourcePattern = regexp.MustCompile(`^default/saw-[a-z0-9-]+-[a-f0-9]{16}/[a-z0-9][a-z0-9-]*$`)

type Client struct{ HTTP *http.Client }

func New() *Client {
	return &Client{HTTP: &http.Client{Timeout: 10 * time.Second,
		Transport:     &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (c *Client) Fetch(ctx context.Context, resource string) (map[string]string, error) {
	if !resourcePattern.MatchString(resource) {
		return nil, errors.New("CredentialResourceRejected")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://127.0.0.1:8006/cdh/resource/"+resource, nil)
	if err != nil {
		return nil, errors.New("CredentialResourceRejected")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, errors.New("CredentialFetchUnavailable")
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, errors.New("CredentialReleaseDenied")
	default:
		return nil, errors.New("CredentialFetchUnavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResourceBytes+1))
	if err != nil || len(raw) > MaxResourceBytes {
		return nil, errors.New("CredentialMaterialRejected")
	}
	var fields map[string]string
	if json.Unmarshal(raw, &fields) != nil || len(fields) == 0 {
		return nil, errors.New("CredentialMaterialRejected")
	}
	return fields, nil
}

// FetchAll retries transient failures within a caller-owned deadline. An
// authorization failure is terminal. No response content enters the error.
func (c *Client) FetchAll(ctx context.Context, resources map[string]string) (map[string]map[string]string, error) {
	if len(resources) == 0 || len(resources) > 32 {
		return nil, errors.New("CredentialResourceRejected")
	}
	result := make(map[string]map[string]string)
	for secret, resource := range resources {
		for {
			if ctx.Err() != nil {
				return nil, errors.New("CredentialFetchUnavailable")
			}
			fields, err := c.Fetch(ctx, resource)
			if err == nil {
				result[secret] = fields
				break
			}
			if err.Error() != "CredentialFetchUnavailable" {
				return nil, err
			}
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, errors.New("CredentialFetchUnavailable")
			case <-timer.C:
			}
		}
	}
	return result, nil
}
