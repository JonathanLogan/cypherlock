package msgcrypt

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestResponseMsg(t *testing.T) {
	pubkey, privkey := genTestKeys()
	pubkeyServ, privkeyServ := genTestKeys()
	input := []byte("test payload")
	msg := NewResponseMessage(pubkeyServ, pubkey, input)
	encrypted, err := msg.Encrypt(privkeyServ, rand.Reader)
	if err != nil {
		t.Fatalf("Encrypt: %s", err)
	}
	msg2, err := new(ResponseMessage).Parse(encrypted)
	if err != nil {
		t.Fatalf("Parse: %s", err)
	}
	err = msg2.Decrypt(privkey)
	if err != nil {
		t.Fatalf("Decrypt: %s", err)
	}
	if !bytes.Equal(input, msg2.Payload) {
		t.Error("Cleartext does not match.")
	}
}
