// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

const ownerA = "0123456789abcdef"
const ownerB = "fedcba9876543210"

func TestOwnedMarkerLifecycle(t *testing.T) {
	root := t.TempDir()
	if err := prepare(root, ownerA); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(markerDir(root), infoFile)
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = prepare(root, ownerA); err != nil {
		t.Fatal(err)
	}
	if err = prepare(root, ownerB); err == nil {
		t.Fatal("foreign registration overwrote marker")
	}
	now, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(first, now) {
		t.Fatal("owned bytes changed")
	}
	if err = remove(root, ownerB); err == nil {
		t.Fatal("foreign removal succeeded")
	}
	if err = remove(root, ownerA); err != nil {
		t.Fatal(err)
	}
	if err = remove(root, ownerA); err != nil {
		t.Fatal("cleanup is not idempotent")
	}
}
func TestPreserveSandboxAndForeignState(t *testing.T) {
	root := t.TempDir()
	if err := prepare(root, ownerA); err != nil {
		t.Fatal(err)
	}
	dir := markerDir(root)
	if err := os.WriteFile(filepath.Join(dir, "sandbox-reference"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := remove(root, ownerA); err == nil {
		t.Fatal("active reference was removed")
	}
	if err := os.Remove(filepath.Join(dir, "sandbox-reference")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, infoFile), []byte("foreign-data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := prepare(root, ownerA); err == nil {
		t.Fatal("foreign marker adopted")
	}
	if err := remove(root, ownerA); err == nil {
		t.Fatal("foreign marker removed")
	}
}
func TestRejectSymlinkAndInvalidIdentity(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	if err := os.Symlink(target, markerDir(root)); err != nil {
		t.Fatal(err)
	}
	if err := prepare(root, ownerA); err == nil {
		t.Fatal("symlink marker accepted")
	}
	if err := remove(root, ownerA); err == nil {
		t.Fatal("symlink marker removed")
	}
	if err := prepare(t.TempDir(), "do-not-expose"); err == nil || err.Error() != "LabMarkerRegistrationRejected" {
		t.Fatal("invalid identity accepted or exposed")
	}
}
