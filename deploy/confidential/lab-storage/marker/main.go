// SPDX-License-Identifier: Apache-2.0
// Own the single helper-root marker. Never overwrite another registration.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

const sourcePath = "/var/lib/kubelet"
const infoFile = "mountInfo.json"
const ownerKey = "saw.redhat.com/storage-lab-registration"

func payload(registration string) ([]byte, error) {
	if !regexp.MustCompile(`^[a-f0-9]{16}$`).MatchString(registration) {
		return nil, errors.New("LabMarkerRegistrationRejected")
	}
	return json.Marshal(struct {
		Device   string            `json:"device"`
		FsType   string            `json:"fstype"`
		Metadata map[string]string `json:"metadata"`
	}{"/dev/zero", "ext4", map[string]string{ownerKey: registration}})
}
func markerDir(root string) string {
	return filepath.Join(root, base64.URLEncoding.EncodeToString([]byte(sourcePath)))
}
func owned(path string, expected []byte) error {
	entry, err := os.Lstat(path)
	if err != nil || !entry.Mode().IsRegular() {
		return errors.New("LabMarkerOwnershipUnverified")
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, expected) {
		return errors.New("LabMarkerOwnerMismatch")
	}
	return nil
}
func prepare(root, registration string) (resultErr error) {
	expected, err := payload(registration)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(root, 0700); err != nil {
		return errors.New("LabMarkerRootUnavailable")
	}
	dir := markerDir(root)
	if err = os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return errors.New("LabMarkerDirectoryUnavailable")
	}
	entry, err := os.Lstat(dir)
	if err != nil || !entry.IsDir() || entry.Mode()&os.ModeSymlink != 0 {
		return errors.New("LabMarkerDirectoryRejected")
	}
	path := filepath.Join(dir, infoFile)
	if _, err = os.Lstat(path); err == nil {
		return owned(path, expected)
	} else if !os.IsNotExist(err) {
		return errors.New("LabMarkerOwnershipUnverified")
	}
	tmp, err := os.CreateTemp(root, ".saw-marker-")
	if err != nil {
		return errors.New("LabMarkerWriteRejected")
	}
	name := tmp.Name()
	defer func() {
		if cleanupErr := os.Remove(name); cleanupErr != nil && !os.IsNotExist(cleanupErr) {
			resultErr = errors.New("LabMarkerTemporaryCleanupRejected")
		}
	}()
	if _, err = tmp.Write(expected); err != nil {
		tmp.Close()
		return errors.New("LabMarkerWriteRejected")
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return errors.New("LabMarkerWriteRejected")
	}
	if err = tmp.Close(); err != nil {
		return errors.New("LabMarkerWriteRejected")
	}
	if err = os.Link(name, path); err != nil {
		if os.IsExist(err) {
			return owned(path, expected)
		}
		return errors.New("LabMarkerWriteRejected")
	}
	return nil
}
func remove(root, registration string) error {
	expected, err := payload(registration)
	if err != nil {
		return err
	}
	dir := markerDir(root)
	entry, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !entry.IsDir() || entry.Mode()&os.ModeSymlink != 0 {
		return errors.New("LabMarkerDirectoryRejected")
	}
	path := filepath.Join(dir, infoFile)
	if err = owned(path, expected); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != infoFile {
		return errors.New("LabMarkerSandboxReferencesRemain")
	}
	if err = os.Remove(path); err != nil {
		return errors.New("LabMarkerRemoveRejected")
	}
	if err = os.Remove(dir); err != nil {
		return errors.New("LabMarkerRemoveRejected")
	}
	return nil
}
func main() {
	mode := flag.String("mode", "", "prepare or remove")
	root := flag.String("root", "/host/direct-volumes", "mounted marker registry")
	registration := flag.String("registration", "", "lab registration")
	flag.Parse()
	var err error
	switch *mode {
	case "prepare":
		err = prepare(*root, *registration)
	case "remove":
		err = remove(*root, *registration)
	default:
		err = errors.New("LabMarkerModeRejected")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	fmt.Println("LabMarkerOperationPassed")
}
