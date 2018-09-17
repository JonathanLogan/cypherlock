// Package msgcrypt implements message enryption and decryption.
package msgcrypt

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256"
	"errors"
	"io"

	"github.com/JonathanLogan/cypherlock/ratchet"

	"golang.org/x/crypto/curve25519"
)

var (
	// ErrMesssageIncomplete is returned when a message is too short.
	ErrMessageIncomplete = errors.New("github.com/JonathanLogan/cypherlock/msgcrypt: Message incomplete")
	// ErrCannotDecrypt is returned if the decryption failed.
	ErrCannotDecrypt = errors.New("github.com/JonathanLogan/cypherlock/msgcrypt: Decryption failed")
)

func genSymNonce(rand io.Reader) (*[24]byte, error) {
	r := new([24]byte)
	_, err := io.ReadFull(rand, r[:])
	if err != nil {
		return nil, err
	}
	return r, nil
}

func GenKeyPair(rand io.Reader) (pubkey, privkey *[32]byte, err error) {
	pubkey = new([32]byte)
	privkey, err = genRandom(rand)
	if err != nil {
		return nil, nil, err
	}
	curve25519.ScalarBaseMult(pubkey, privkey)
	return pubkey, privkey, nil
}

func genRandom(rand io.Reader) (*[32]byte, error) {
	d := new([32]byte)
	_, err := io.ReadFull(rand, d[:])
	if err != nil {
		return nil, err
	}
	return d, nil
}

func tempKey(rand io.Reader) (sendKeyPrivate, sendKeyPublic, nonce *[32]byte, err error) {
	sendKeyPrivate, err = genRandom(rand)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce, err = genRandom(rand)
	if err != nil {
		return nil, nil, nil, err
	}
	sendKeyPublic = new([32]byte)
	curve25519.ScalarBaseMult(sendKeyPublic, sendKeyPrivate)
	return sendKeyPrivate, sendKeyPublic, nonce, nil
}

// ToPublicKey creates a secret to encrypt to a public key.
func ToPublicKey(rand io.Reader, serverPubKey *[32]byte) (secret *[32]byte, sendKey *[32]byte, nonce *[32]byte, err error) {
	sendKeyPriv, sendKey, nonce, err := tempKey(rand)
	if err != nil {
		return nil, nil, nil, err
	}
	secret = twoPartySecret(sendKeyPriv, serverPubKey, nonce, false)
	return secret, sendKey, nonce, nil
}

// DecryptKey returns a secret for a message.
func DecryptKey(sendKey *[32]byte, nonce *[32]byte, myPrivateKey *[32]byte) (secret *[32]byte) {
	return twoPartySecret(myPrivateKey, sendKey, nonce, false)
}

func keyHMAC(presecret, nonce *[32]byte) (secret *[32]byte) {
	h := hmac.New(crypto.SHA256.New, nonce[:])
	h.Write(presecret[:])
	secretT := h.Sum(nil)
	secret = new([32]byte)
	copy(secret[:], secretT[:])
	return secret
}

func keyHASH(presecret *[32]byte) (secret *[32]byte) {
	secret = new([32]byte)
	h := crypto.SHA256.New()
	h.Write(presecret[:])
	ss := h.Sum(nil)
	copy(secret[:], ss)
	return secret
}

func twoPartySecret(privKey, pubkey, nonce *[32]byte, ratchet bool) (secret *[32]byte) {
	presecret := new([32]byte)
	curve25519.ScalarMult(presecret, privKey, pubkey)
	if ratchet {
		presecret = keyHASH(presecret)
	}
	return keyHMAC(presecret, nonce)
}

// ToRatchetKey creates a secrt to encrypt to a ratchet key.
func ToRatchetKey(rand io.Reader, ratchetPubKey *[32]byte) (secret *[32]byte, sendKey *[32]byte, nonce *[32]byte, err error) {
	sendKeyPriv, sendKey, nonce, err := tempKey(rand)
	if err != nil {
		return nil, nil, nil, err
	}
	secret = twoPartySecret(sendKeyPriv, ratchetPubKey, nonce, true)
	return secret, sendKey, nonce, nil
}

// DecryptRatchetKey returns a secret from a ratchet message.
func DecryptRatchetKey(sendKey *[32]byte, nonce *[32]byte, ratchetPubKey *[32]byte, getSecret ratchet.SecretFunc) (secret *[32]byte, err error) {
	presecret, err := getSecret(ratchetPubKey, sendKey)
	if err != nil {
		return nil, err
	}
	return keyHMAC(presecret, nonce), nil
}

// ToEphemeralKey creates a secret to encrypt to a key with an ephemeral key.
func ToEphemeralKey(rand io.Reader, receiverPublicKey *[32]byte, serverPrivateKey *[32]byte) (secret *[32]byte, nonce *[32]byte, ephemeralKey *[32]byte, err error) {
	ephemeralPriv, ephemeralKey, nonce, err := tempKey(rand)
	// serverPriv x receiverPub = K1
	// ephemeralPriv x receiverPub =K2
	k1 := twoPartySecret(serverPrivateKey, receiverPublicKey, nonce, true)
	k2 := twoPartySecret(ephemeralPriv, receiverPublicKey, nonce, true)
	return keyHMAC(k1, k2), nonce, ephemeralKey, nil
}

// FromEphemeralKey returns a secret from an ephemeral key.
func FromEphemeralKey(nonce *[32]byte, ephemeralKey *[32]byte, serverPublicKey *[32]byte, receiverPrivateKey *[32]byte) (secret *[32]byte) {
	k1 := twoPartySecret(receiverPrivateKey, serverPublicKey, nonce, true)
	k2 := twoPartySecret(receiverPrivateKey, ephemeralKey, nonce, true)
	return keyHMAC(k1, k2)
}
