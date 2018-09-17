package msgcrypt

import (
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

// ToDo: encrypt master secret. Max Size 500byte, padding.

var (
	// ErrSecretToLong is returned when trying to encode a real secret over 500 byte length.
	ErrSecretToLong = errors.New("msgcrypt: secret too long")
	// ErrEncryptedTooShort is returned if the encrypted message is too short.
	ErrEncryptedTooShort = errors.New("msgcrypt: encrypted message too short")
)

// MaxSecretSize is the maximum size of a secret.
const MaxSecretSize = 500

// EncryptRealSecret encrypts a real secret to a random secretKey.
func EncryptRealSecret(realSecret []byte, rand io.Reader) (secretKey *[32]byte, encrypted []byte, err error) {
	if len(realSecret) > MaxSecretSize {
		return nil, nil, ErrSecretToLong
	}
	msg := make([]byte, MaxSecretSize+8)
	binary.BigEndian.PutUint64(msg[0:8], uint64(len(realSecret)))
	copy(msg[8:], realSecret)
	secretKey, err = genRandom(rand)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := genSymNonce(rand)
	if err != nil {
		return nil, nil, err
	}
	out := secretbox.Seal(nil, msg, nonce, secretKey)
	return secretKey, append(nonce[:], out...), nil
}

// DecryptRealSecret decrypts a real secret.
func DecryptRealSecret(secretKey *[32]byte, encrypted []byte) (realSecret []byte, err error) {
	if len(encrypted) < MaxSecretSize+8+24+secretbox.Overhead {
		return nil, ErrEncryptedTooShort
	}
	nonce := new([24]byte)
	copy(nonce[:], encrypted)
	pad, ok := secretbox.Open(nil, encrypted[24:], nonce, secretKey)
	if !ok {
		return nil, ErrCannotDecrypt
	}
	lenS := binary.BigEndian.Uint64(pad[0:8])
	return pad[8 : 8+lenS], nil
}
