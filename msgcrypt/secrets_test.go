package msgcrypt

import (
	"github.com/JonathanLogan/cypherlock/ratchet"
	"crypto/rand"
	"errors"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func genTestKeys() (pubkey, privkey *[32]byte) {
	pubkey, privkey, err := GenKeyPair(rand.Reader)
	if err != nil {
		panic("genTestKeys")
	}
	return pubkey, privkey
}

func TestToPublicKey(t *testing.T) {
	pubkey, privkey := genTestKeys()
	secret, sendKey, nonce, err := ToPublicKey(rand.Reader, pubkey)
	if err != nil {
		t.Errorf("ToPublicKey: %s", err)
	}
	secret2 := DecryptKey(sendKey, nonce, privkey)
	if *secret != *secret2 {
		t.Error("Secrets dont match")
	}
}

// SecretFunc is a function that returns a secret for a ratchet key.
// type SecretFunc func(expectedPubKey, peerPubKey *[32]byte) (*[32]byte, error)

func lookupF(pubkey, privkey *[32]byte) ratchet.SecretFunc {
	return func(expectedPubKey, peerPubKey *[32]byte) (*[32]byte, error) {
		if *expectedPubKey != *pubkey {
			return nil, errors.New("Unexpected Public Key")
		}
		presecret := new([32]byte)
		curve25519.ScalarMult(presecret, privkey, peerPubKey)
		secret := keyHASH(presecret)
		return secret, nil
	}
}

func TestToRatchetKey(t *testing.T) {
	pubkey, privkey := genTestKeys()
	secret, sendKey, nonce, err := ToRatchetKey(rand.Reader, pubkey)
	if err != nil {
		t.Errorf("ToRatchetKey: %s", err)
	}
	secret2, err := DecryptRatchetKey(sendKey, nonce, pubkey, lookupF(pubkey, privkey))
	if err != nil {
		t.Errorf("DecryptRatchetKey: %s", err)
	}
	if *secret != *secret2 {
		t.Error("Secrets dont macth")
	}
}

func TestToEphemeralKey(t *testing.T) {
	serverpubkey, serverprivkey := genTestKeys()
	receiverpubkey, receiverprivkey := genTestKeys()
	secret, nonce, ephemeralKey, err := ToEphemeralKey(rand.Reader, receiverpubkey, serverprivkey)
	if err != nil {
		t.Errorf("ToEphemeralKey: %s", err)
	}
	secret2 := FromEphemeralKey(nonce, ephemeralKey, serverpubkey, receiverprivkey)
	if *secret != *secret2 {
		t.Error("Secrets dont macth")
	}
}
