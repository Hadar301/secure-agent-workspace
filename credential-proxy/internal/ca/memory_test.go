package ca

import "testing"

func TestMemoryAuthority(t *testing.T) {
	cert, key, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	a := NewMemory(cert, key)
	if err = a.Ready(); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Certificate("api.example.test"); err != nil {
		t.Fatal(err)
	}
	if err = NewMemory([]byte("invalid"), key).Ready(); err == nil {
		t.Fatal("accepted invalid authority")
	}
}
