package msgcrypt

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEnvelopeMessage(t *testing.T) {
	pubkey, privkey := genTestKeys()
	input := []byte("Test message")
	validFrom, validTo := uint64(102398), uint64(5987123)
	msg := NewEnvelopeMessage(pubkey, validFrom, validTo, input)
	enc, err := msg.Encrypt(rand.Reader)
	if err != nil {
		t.Fatalf("Encrypt: %s", err)
	}
	msg2, err := new(EnvelopeMessage).Parse(enc)
	if err != nil {
		t.Fatalf("Parse: %s", err)
	}
	err = msg2.Decrypt(privkey)
	if err != nil {
		t.Fatalf("Decrypt: %s", err)
	}
	if !bytes.Equal(input, msg2.RatchetMessage) {
		t.Error("Cleartext does not match")
	}
	if msg2.ValidFrom != validFrom {
		t.Error("ValidFrom mismatch")
	}
	if msg2.ValidTo != validTo {
		t.Error("ValidTo mismatch")
	}

}
