package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/ca"
	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/cdh"
	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/config"
	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/proxy"
)

// Public bootstrap configuration. Its JSON value must be pinned by the measured
// guest policy. Kubernetes identity/bootstrap Secrets never contain provider keys.
type confidentialConfig struct {
	SchemaVersion int               `json:"schemaVersion"`
	Policy        json.RawMessage   `json:"policy"`
	Resources     map[string]string `json:"resources"`
	PublicCAFile  string            `json:"publicCAFile"`
}

func confidential(args []string) error {
	if !validSupervisorArgs(args) {
		return errors.New("SupervisorCommandRejected")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	cfg, err := loadConfidentialBootstrap(os.Environ())
	if err != nil {
		return err
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 300*time.Second)
	material, err := cdh.New().FetchAll(fetchCtx, cfg.Resources)
	cancel()
	if err != nil {
		return err
	}
	store, err := config.NewMemoryData(cfg.Policy, material)
	if err != nil {
		return err
	}
	cert, key, err := ca.Generate()
	if err != nil {
		return errors.New("CredentialProxyUnavailable")
	}
	authority := ca.NewMemory(cert, key)
	if authority.Ready() != nil {
		return errors.New("CredentialProxyUnavailable")
	}
	// The file contains only a public CA. The key and provider material stay in memory.
	if os.WriteFile(cfg.PublicCAFile, cert, 0600) != nil {
		return errors.New("CredentialProxyUnavailable")
	}
	defer os.Remove(cfg.PublicCAFile)
	listener, err := net.Listen("tcp", "127.0.0.1:3128")
	if err != nil {
		return errors.New("CredentialProxyUnavailable")
	}
	server := &http.Server{Handler: &proxy.Server{Store: store, CA: authority}, ReadHeaderTimeout: 10 * time.Second}
	proxyExit := make(chan error, 1)
	go func() { proxyExit <- server.Serve(listener) }()
	// The driver passes the existing supervisor arguments. Override no argument
	// here: the admission policy must require this exact guest-local proxy.
	child := exec.CommandContext(ctx, args[0], args[1:]...)
	child.Stdout, child.Stderr, child.Stdin = os.Stdout, os.Stderr, os.Stdin
	if child.Start() != nil {
		server.Close()
		return errors.New("SupervisorStartFailed")
	}
	childExit := make(chan error, 1)
	go func() { childExit <- child.Wait() }()
	select {
	case err = <-childExit:
		server.Close()
		if err != nil {
			return errors.New("SupervisorFailed")
		}
		return nil
	case <-proxyExit:
		stop()
		<-childExit
		return errors.New("CredentialProxyUnavailable")
	case <-ctx.Done():
		server.Close()
		<-childExit
		return errors.New("SupervisorStopped")
	}
}

const confidentialBootstrapEnv = "SAW_CONFIDENTIAL_BOOTSTRAP_JSON"

func loadConfidentialBootstrap(environ []string) (*confidentialConfig, error) {
	var raw string
	count := 0
	for _, entry := range environ {
		if strings.HasPrefix(entry, confidentialBootstrapEnv+"=") {
			raw = strings.TrimPrefix(entry, confidentialBootstrapEnv+"=")
			count++
		}
		if strings.HasPrefix(entry, "SAW_CONFIDENTIAL_CONFIG=") {
			return nil, errors.New("AttestationConfigurationRejected")
		}
	}
	if count != 1 || len(raw) == 0 || len(raw) > 64*1024 {
		return nil, errors.New("AttestationConfigurationRejected")
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(raw)))
	decoder.DisallowUnknownFields()
	var cfg confidentialConfig
	var trailing any
	if decoder.Decode(&cfg) != nil || decoder.Decode(&trailing) != io.EOF ||
		cfg.SchemaVersion != 1 || len(cfg.Policy) == 0 || len(cfg.Resources) == 0 ||
		cfg.PublicCAFile != "/run/openshell/saw-proxy-ca.pem" {
		return nil, errors.New("AttestationConfigurationRejected")
	}
	return &cfg, nil
}

func validSupervisorArgs(args []string) bool {
	if len(args) == 0 || args[0] != "/openshell-supervisor" {
		return false
	}
	proxyCount, caCount := 0, 0
	for i, arg := range args {
		switch arg {
		case "--upstream-proxy":
			proxyCount++
			if i+1 >= len(args) || args[i+1] != "http://127.0.0.1:3128" {
				return false
			}
		case "--upstream-proxy-ca-bundle":
			caCount++
			if i+1 >= len(args) || args[i+1] != "/run/openshell/saw-proxy-ca.pem" {
				return false
			}
		case "--upstream-proxy-connect-by-hostname":
		default:
			if strings.HasPrefix(arg, "--upstream-") {
				return false
			}
		}
	}
	return proxyCount == 1 && caCount == 1
}
