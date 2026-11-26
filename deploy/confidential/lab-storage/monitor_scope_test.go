// SPDX-License-Identifier: Apache-2.0
package peerpodvolume

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	api "github.com/confidential-containers/cloud-api-adaptor/src/csi-wrapper/pkg/apis/peerpodvolume/v1alpha1"
	clientset "github.com/confidential-containers/cloud-api-adaptor/src/csi-wrapper/pkg/generated/peerpodvolume/clientset/versioned"
	"k8s.io/client-go/rest"
)

func TestMonitorUsesOnlyItsNamespace(t *testing.T) {
	paths := make(chan string, 16)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths <- r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("watch") == "true" {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		_, _ = w.Write([]byte(`{"apiVersion":"confidentialcontainers.org/v1alpha1","kind":"PeerpodVolumeList","metadata":{"resourceVersion":"1"},"items":[]}`))
	}))
	defer server.Close()
	client, err := clientset.NewForConfig(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	const namespace = "saw-ppvc-0123456789abcdef"
	monitor, err := NewPodVolumeMonitor(client, namespace, func(*api.PeerpodVolume) {}, func(*api.PeerpodVolume) {})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- monitor.Start(ctx) }()
	want := "/apis/confidentialcontainers.org/v1alpha1/namespaces/" + namespace + "/peerpodvolumes"
	// New client-go versions can use one streaming watch for the initial list.
	// Inspect the real request path without requiring the legacy two-call flow.
	for i := 0; i < 1; i++ {
		select {
		case path := <-paths:
			if path != want {
				t.Fatalf("watch escaped namespace: %q", path)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("namespace-scoped list/watch did not start")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("monitor did not stop")
	}
}

func TestMonitorRejectsUnscopedNamespace(t *testing.T) {
	for _, namespace := range []string{"", "*", "bad/namespace"} {
		if _, err := NewPodVolumeMonitor(nil, namespace, nil, nil); err == nil {
			t.Fatalf("accepted invalid namespace %q", namespace)
		}
	}
}
