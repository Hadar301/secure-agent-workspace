// SPDX-License-Identifier: Apache-2.0
package wrapper

import (
	"context"
	"encoding/json"
	api "github.com/confidential-containers/cloud-api-adaptor/src/csi-wrapper/pkg/apis/peerpodvolume/v1alpha1"
	peerclient "github.com/confidential-containers/cloud-api-adaptor/src/csi-wrapper/pkg/generated/peerpodvolume/clientset/versioned"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
