package msgcrypt

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestRatchetMessage(t *testing.T) {
	pubkey, privkey := genTestKeys()
	input := []byte("testmessage")
	msg, receivePrivKey, err := NewRatchetMessage(pubkey, input, rand.Reader)
	if err != nil {
		t.Fatalf("NewRatchetMessage: %s", err)
	}
	encMsg, err := msg.Encrypt(rand.Reader)
	if err != nil {
		t.Fatalf("Encrypt: %s", err)
	}
	msg2, err := new(RatchetMessage).Parse(encMsg)
	if err != nil {
		t.Fatalf("Parse: %s", err)
	}
	err = msg2.Decrypt(lookupF(pubkey, privkey))
	if err != nil {
		t.Fatalf("Encrypt: %s", err)
	}
	if !bytes.Equal(msg2.Payload, input) {
		t.Fatal("Cleartext no match")
	}
	receiverPubKey := new([32]byte)
	curve25519.ScalarBaseMult(receiverPubKey, receivePrivKey)
	if !bytes.Equal(msg2.ReceiverPublicKey[:], receiverPubKey[:]) {
		t.Fatal("PubKey no match")
	}
}
