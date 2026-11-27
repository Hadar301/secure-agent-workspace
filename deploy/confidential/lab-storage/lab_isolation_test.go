// SPDX-License-Identifier: Apache-2.0
package wrapper

import (
	"bytes"
	"context"
	"encoding/json"
	api "github.com/confidential-containers/cloud-api-adaptor/src/csi-wrapper/pkg/apis/peerpodvolume/v1alpha1"
	peerclient "github.com/confidential-containers/cloud-api-adaptor/src/csi-wrapper/pkg/generated/peerpodvolume/clientset/versioned"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/golang/protobuf/jsonpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLabTargetScope(t *testing.T) {
	service := &NodeService{}
	uid := "01234567-89ab-4cde-8f01-23456789abcd"
	for _, root := range []string{"/var/lib/kubelet", "/var/data/kubelet"} {
		pod, volume, err := service.getPodUIDandVolumeName(root + "/pods/" + uid + "/volumes/kubernetes.io~csi/pvc-test/mount")
		if err != nil || pod != uid || volume != "pvc-test" {
			t.Fatal("valid lab target rejected")
		}
	}
	for _, path := range []string{"", "/var/lib/kubelet", "/tmp/pods/" + uid + "/volumes/kubernetes.io~csi/pvc-test/mount", "/var/lib/kubelet/pods/" + uid + "/volumes/kubernetes.io~csi/../mount", "/var/lib/kubelet/pods/not-a-uid/volumes/kubernetes.io~csi/pvc-test/mount", "/var/lib/kubelet/pods/" + uid + "/volumes/kubernetes.io~csi/pvc-test/mount/extra"} {
		_, _, err := service.getPodUIDandVolumeName(path)
		if status.Code(err) != codes.InvalidArgument || status.Convert(err).Message() != "LabVolumeTargetRejected" {
			t.Fatal("unsafe target accepted or input exposed")
		}
	}
}

type labIdentity struct {
	csi.UnimplementedIdentityServer
	name string
}

func (i *labIdentity) GetPluginInfo(context.Context, *csi.GetPluginInfoRequest) (*csi.GetPluginInfoResponse, error) {
	return &csi.GetPluginInfoResponse{Name: i.name, VendorVersion: "lab-test"}, nil
}
func TestLabIdentityUsesItsOwnSocket(t *testing.T) {
	for _, name := range []string{"saw-ppvc-0123456789abcdef.disk.csi.saw.redhat.com", "saw-ppvc-fedcba9876543210.disk.csi.saw.redhat.com"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "driver.sock")
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			server := grpc.NewServer()
			csi.RegisterIdentityServer(server, &labIdentity{name: name})
			go server.Serve(listener)
			defer server.Stop()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			reply, err := NewIdentityService(path).GetPluginInfo(ctx, &csi.GetPluginInfoRequest{})
			if err != nil || reply.GetName() != name {
				t.Fatal("wrapper changed the isolated driver identity")
			}
		})
	}
}

func TestLabStagingScope(t *testing.T) {
	service := &NodeService{Namespace: "saw-ppvc-0123456789abcdef"}
	valid := "/var/lib/kubelet/plugins/kubernetes.io/csi/saw-ppvc-0123456789abcdef.disk.csi.saw.redhat.com/abcdef/globalmount"
	if err := service.validateStagingTarget(valid); err != nil {
		t.Fatal("valid staging path rejected")
	}
	for _, path := range []string{"/var/lib/kubelet", strings.Replace(valid, "0123456789abcdef", "fedcba9876543210", 1), strings.Replace(valid, "abcdef/globalmount", "../globalmount", 1)} {
		if status.Code(service.validateStagingTarget(path)) != codes.InvalidArgument {
			t.Fatal("foreign staging path accepted")
		}
	}
}

func TestLabCleanupUsesUpdatedVersion(t *testing.T) {
	uid := "01234567-89ab-4cde-8f01-23456789abcd"
	target := "/var/lib/kubelet/pods/" + uid + "/volumes/kubernetes.io~csi/pvc-test/mount"
	record := api.PeerpodVolume{TypeMeta: metav1.TypeMeta{APIVersion: "confidentialcontainers.org/v1alpha1", Kind: "PeerpodVolume"}, ObjectMeta: metav1.ObjectMeta{Name: "volume-test", Namespace: "lab", ResourceVersion: "1"}}
	record.Spec.PodUID = uid
	record.Spec.VolumeName = "pvc-test"
	record.Spec.TargetPath = target
	updates := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(record)
			return
		}
		if r.Method != http.MethodPut {
			t.Errorf("unexpected API mutation: %s", r.Method)
			w.WriteHeader(500)
			return
		}
		var received api.PeerpodVolume
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/status") {
			if received.ResourceVersion != "2" || received.Status.State != api.NodeUnpublishVolumeCached {
				t.Error("cleanup used stale state or resource version")
				w.WriteHeader(409)
				return
			}
			received.ResourceVersion = "3"
		} else {
			if received.Spec.WrapperNodeUnpublishVolumeReq == "" {
				t.Error("cleanup request missing")
			}
			received.ResourceVersion = "2"
		}
		updates++
		json.NewEncoder(w).Encode(received)
	}))
	defer server.Close()
	client, err := peerclient.NewForConfig(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	service := &NodeService{Namespace: "lab", PeerpodvolumeClient: client}
	_, err = service.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{VolumeId: "volume-test", TargetPath: "/var/lib/kubelet"})
	if status.Code(err) != codes.InvalidArgument || updates != 0 {
		t.Fatal("unsafe cleanup reached a mutation")
	}
	_, err = service.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{VolumeId: "volume-test", TargetPath: target})
	if err != nil || updates != 2 {
		t.Fatalf("idempotent scoped cleanup failed: %v", err)
	}
}

func TestLabProvisioningScopeAndCredentialExclusion(t *testing.T) {
	namespace := "saw-ppvc-0123456789abcdef"
	parameters := map[string]string{"peerpod": "true", "csi.storage.k8s.io/pvc/namespace": "saw-ppvc-probe-0123456789abcdef"}
	if err := labCreateScope(namespace, &csi.CreateVolumeRequest{Parameters: parameters}); err != nil {
		t.Fatal("valid lab claim rejected")
	}
	foreign := map[string]string{"peerpod": "true", "csi.storage.k8s.io/pvc/namespace": "other-owner"}
	service := &ControllerService{Namespace: namespace}
	_, err := service.CreateVolume(context.Background(), &csi.CreateVolumeRequest{Parameters: foreign})
	if status.Code(err) != codes.PermissionDenied || status.Convert(err).Message() != "LabClaimScopeRejected" {
		t.Fatal("foreign claim reached the backend")
	}
	if status.Code(labCreateScope("default", &csi.CreateVolumeRequest{Parameters: parameters})) != codes.PermissionDenied {
		t.Fatal("unscoped installation accepted")
	}
	secret := map[string]string{"api_key": "do-not-expose"}
	_, err = service.CreateVolume(context.Background(), &csi.CreateVolumeRequest{Parameters: parameters, Secrets: secret})
	if status.Code(err) != codes.InvalidArgument || strings.Contains(err.Error(), "do-not-expose") {
		t.Fatal("credential payload accepted or exposed")
	}
	node := &NodeService{}
	_, err = node.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{Secrets: secret})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatal("node stage reached storage with a credential")
	}
	_, err = node.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{Secrets: secret})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatal("node publish reached storage with a credential")
	}
}

type labStageBackend struct {
	csi.UnimplementedNodeServer
	failure  error
	block    bool
	failFor  int
	attempts int
	mu       sync.Mutex
	started  chan struct{}
}

func (b *labStageBackend) NodeStageVolume(ctx context.Context, request *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
	if request.PublishContext["LUN"] != "0" {
		return nil, status.Error(codes.InvalidArgument, "bad test LUN")
	}
	b.mu.Lock()
	b.attempts++
	attempt := b.attempts
	failure := b.failure
	if b.failFor > 0 && attempt > b.failFor {
		failure = nil
	}
	b.mu.Unlock()
	if b.started != nil {
		select {
		case b.started <- struct{}{}:
		default:
		}
	}
	if b.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if failure != nil {
		return nil, failure
	}
	return &csi.NodeStageVolumeResponse{}, nil
}
func TestLabGuestStageStatusIsBoundedAndSafe(t *testing.T) {
	cases := []struct {
		name, reason                               string
		failure                                    error
		block, missingBackend, foreign, concurrent bool
		failFor                                    int
	}{
		{name: "success"},
		{name: "delayed-device", failFor: 2, failure: status.Error(codes.Internal, "failed to find disk: do-not-expose")},
		{name: "concurrent-stage", reason: "GuestStageTimeout", block: true, concurrent: true},
		{name: "device", reason: "GuestDeviceUnavailable", failure: status.Error(codes.Internal, "failed to find disk: do-not-expose")},
		{name: "mount", reason: "GuestMountFailed", failure: status.Error(codes.Internal, "could not mount do-not-expose")},
		{name: "permission", reason: "GuestStagePermissionDenied", failure: status.Error(codes.PermissionDenied, "do-not-expose")},
		{name: "generic", reason: "GuestStageFailed", failure: status.Error(codes.Internal, "do-not-expose")},
		{name: "timeout", reason: "GuestStageTimeout", block: true},
		{name: "missing-backend", reason: "GuestBackendUnavailable", missingBackend: true},
		{name: "foreign-replacement", foreign: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := api.PeerpodVolume{ObjectMeta: metav1.ObjectMeta{Name: "lab-volume", Namespace: "lab", ResourceVersion: "1"}}
			original.Spec.PodUID = "01234567-89ab-4cde-8f01-23456789abcd"
			original.Spec.VolumeID = "lab-volume"
			original.Spec.VMID = "lab-vm"
			original.Spec.TargetPath = "/var/lib/kubelet/pods/" + original.Spec.PodUID + "/volumes/kubernetes.io~csi/lab-volume/mount"
			original.Status.State = api.ControllerPublishVolumeApplied
			var encoded bytes.Buffer
			if err := (&jsonpb.Marshaler{}).Marshal(&encoded, &csi.NodeStageVolumeRequest{VolumeId: "lab-volume"}); err != nil {
				t.Fatal(err)
			}
			original.Spec.WrapperNodeStageVolumeReq = encoded.String()
			original.Spec.WrapperControllerPublishVolumeRes = `{"publishContext":{"LUN":"0"}}`
			reports := make(chan api.PeerpodVolume, 1)
			apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				latest := original.DeepCopy()
				latest.ResourceVersion = "17"
				if tc.foreign {
					latest.Spec.PodUID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
				}
				if r.Method == http.MethodGet {
					json.NewEncoder(w).Encode(latest)
					return
				}
				if r.Method != http.MethodPut || !strings.HasSuffix(r.URL.Path, "/status") {
					t.Error("unexpected status mutation")
					w.WriteHeader(500)
					return
				}
				var report api.PeerpodVolume
				if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				if report.ResourceVersion != "17" {
					t.Error("status used a stale version")
				}
				reports <- report
				json.NewEncoder(w).Encode(report)
			}))
			defer apiServer.Close()
			client, err := peerclient.NewForConfig(&rest.Config{Host: apiServer.URL})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "backend.sock")
			backend := &labStageBackend{failure: tc.failure, block: tc.block, failFor: tc.failFor, started: make(chan struct{}, 1)}
			if !tc.missingBackend {
				listener, err := net.Listen("unix", path)
				if err != nil {
					t.Fatal(err)
				}
				server := grpc.NewServer()
				csi.RegisterNodeServer(server, backend)
				go server.Serve(listener)
				defer server.Stop()
			}
			service := NewPodVMNodeService(path, "lab", client)
			service.operationTimeout = 200 * time.Millisecond
			service.retryDelay = time.Millisecond
			started := time.Now()
			if tc.concurrent {
				done := make(chan struct{})
				go func() { service.ReproduceNodeStageVolume(&original); close(done) }()
				select {
				case <-backend.started:
				case <-time.After(time.Second):
					t.Fatal("stage backend did not start")
				}
				service.ReproduceNodeStageVolume(&original)
				<-done
			} else {
				service.ReproduceNodeStageVolume(&original)
			}
			backend.mu.Lock()
			attempts := backend.attempts
			backend.mu.Unlock()
			if tc.name == "delayed-device" && attempts != 3 {
				t.Fatal("transient device was not retried to readiness")
			}
			if tc.concurrent && attempts != 1 {
				t.Fatal("concurrent stage reached the backend twice")
			}
			if tc.name == "generic" && attempts != 1 {
				t.Fatal("non-transient failure was retried")
			}
			if time.Since(started) > 2*time.Second {
				t.Fatal("guest stage did not stop at its bound")
			}
			select {
			case report := <-reports:
				if tc.foreign {
					t.Fatal("status changed a replacement registration")
				}
				expected := api.NodeStageVolumeApplied
				if tc.reason != "" {
					expected = "nodeStageVolumeFailed"
				}
				if report.Status.State != expected || report.Status.Reason != tc.reason {
					t.Fatal("wrong safe stage result")
				}
				value, _ := json.Marshal(report.Status)
				if strings.Contains(string(value), "do-not-expose") {
					t.Fatal("backend input leaked into status")
				}
			default:
				if !tc.foreign {
					t.Fatal("guest stage produced no status")
				}
			}
		})
	}
}

func TestLabGuestDeviceCountsExposeNoDeviceIdentifiers(t *testing.T) {
	root := t.TempDir()
	devices := []struct{ name, vendor, model string }{
		{"0:0:0:0", "MSFT", "Virtual Disk"},
		{"4:0:0:1", "MSFT", "VIRTUAL DISK"},
		{"9:0:0:2", "do-not-expose", "private-device-description"},
		{"host0", "MSFT", "Virtual Disk"},
		{"-1:0:0:0", "MSFT", "Virtual Disk"},
	}
	for _, device := range devices {
		dir := filepath.Join(root, device.name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "vendor"), []byte(device.vendor), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "model"), []byte(device.model), 0600); err != nil {
			t.Fatal(err)
		}
	}
	got := labGuestDeviceCounts(root)
	if !got.DeviceProbeAvailable || got.ScsiDeviceCount != 3 || got.LowScsiHostCount != 1 || got.AzureDiskCount != 2 {
		t.Fatal("wrong bounded guest device counts")
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "do-not-expose") || strings.Contains(string(raw), "private-device-description") {
		t.Fatal("guest device identifiers leaked")
	}
	missing := labGuestDeviceCounts(filepath.Join(root, "missing"))
	if missing.DeviceProbeAvailable || missing.ScsiDeviceCount != 0 {
		t.Fatal("missing device probe falsely passed")
	}
}
