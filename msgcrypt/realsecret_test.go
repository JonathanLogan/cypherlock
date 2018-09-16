package msgcrypt

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestRealSecret(t *testing.T) {
	realSecret := []byte("A real secret to protect")
	secretKey, encrypted, err := EncryptRealSecret(realSecret, rand.Reader)
	if err != nil {
		t.Fatalf("EncryptRealSecret: %s", err)
	}
	realSecret2, err := DecryptRealSecret(secretKey, encrypted)
	if err != nil {
		t.Fatalf("DecryptRealSecret: %s", err)
	}
	if !bytes.Equal(realSecret2, realSecret) {
		t.Error("Cleartexts dont match")
	}
}
