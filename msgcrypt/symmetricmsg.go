package msgcrypt

import (
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"
)

// SymEncrypt encrypts message with a key.
func SymEncrypt(key *[32]byte, message []byte, rand io.Reader) ([]byte, error) {
	nonce, err := genSymNonce(rand)
	if err != nil {
		return nil, err
	}
	return secretbox.Seal(nonce[:], message, nonce, key), nil
}

// SymDecrypt decrypts a message with a key.
func SymDecrypt(key *[32]byte, message []byte) ([]byte, error) {
	if len(message) < 24+secretbox.Overhead+1 {
		return nil, ErrMessageIncomplete
	}
	nonce := new([24]byte)
	copy(nonce[:], message[0:24])
	ct, ok := secretbox.Open(nil, message[24:], nonce, key)
	if !ok {
		return nil, ErrCannotDecrypt
	}
	return ct, nil
}

// generate a 32 byte key from password.
func keyFromPassword32(password, salt []byte) *[32]byte {
	key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
	r := new([32]byte)
	copy(r[:], key[:])
	return r
}

// PasswordEncrypt encrypts a message with a password.
func PasswordEncrypt(password, message []byte, rand io.Reader) ([]byte, error) {
	salt, err := genRandom(rand)
	if err != nil {
		return nil, err
	}
	key := keyFromPassword32(password, salt[:])
	ct, err := SymEncrypt(key, message, rand)
	if err != nil {
		return nil, err
	}
	return append(salt[:], ct...), nil
}

// PasswordDecrypt decrypts a message with a password.
func PasswordDecrypt(password, message []byte) ([]byte, error) {
	key := keyFromPassword32(password, message[0:32])
	ct, err := SymDecrypt(key, message[32:])
	if err != nil {
		return nil, err
	}
	return ct, nil
}
