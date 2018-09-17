package msgcrypt

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSymmetric(t *testing.T) {
	message := []byte("Test message")
	key, err := genRandom(rand.Reader)
	if err != nil {
		t.Fatalf("genRandom: %s", err)
	}
	msg, err := SymEncrypt(key, message, rand.Reader)
	if err != nil {
		t.Errorf("SymEncrypt: %s", err)
	}
	clear, err := SymDecrypt(key, msg)
	if err != nil {
		t.Errorf("SymDecrypt: %s", err)
	}
	if !bytes.Equal(message, clear) {
		t.Error("Cleartext no match")
	}
}

func TestPassword(t *testing.T) {
	passphrase := []byte("Secret passphrase")
	message := []byte("Test message")

	msg, err := PasswordEncrypt(passphrase, message, rand.Reader)
	if err != nil {
		t.Errorf("PasswordEncrypt: %s", err)
	}
	ct, err := PasswordDecrypt(passphrase, msg)
	if err != nil {
		t.Errorf("PasswordDecrypt: %s", err)
	}
	if !bytes.Equal(ct, message) {
		t.Error("Cleartext no match")
	}
}
