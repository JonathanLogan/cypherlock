package ratchetserver

import (
	"crypto/rand"
	"testing"
)

func TestMarshall(t *testing.T) {
	sk, err := NewServerKeys(rand.Reader)
	if err != nil {
		t.Fatalf("NewServerKeys: %s", err)
	}
	skm := sk.Marshall()
	sk2, err := new(ServerKeys).Unmarshall(skm)
	if err != nil {
		t.Fatalf("Unmarshall: %s", err)
	}
	if sk.EncPrivateKey != sk2.EncPrivateKey {
		t.Error("EncPrivateKey")
	}
	if sk.EncPublicKey != sk2.EncPublicKey {
		t.Error("EncPublicKey")
	}
	if sk.SigPublicKey != sk2.SigPublicKey {
		t.Error("SigPublicKey")
	}
	if sk.SigPrivateKey != sk2.SigPrivateKey {
		t.Error("SigPrivateKey")
	}
}
