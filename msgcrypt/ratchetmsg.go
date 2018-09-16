package msgcrypt

import (
	"github.com/JonathanLogan/cypherlock/ratchet"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

// RatchetMessage is a message for a ratchet.
type RatchetMessage struct {
	RatchetPublicKey  [32]byte // Ratchet pubkey
	SenderPublicKey   [32]byte // Ephemeral
	ReceiverPublicKey [32]byte // Encrypt response to this, with ServerKey
	DHNonce           [32]byte
	SymNonce          [24]byte
	Payload           []byte
	encPayload        []byte
}

// NewRatchetMessage creates a new RatchetMessage with fields set.
func NewRatchetMessage(ratchetPubkey *[32]byte, payload []byte, rand io.Reader) (msg *RatchetMessage, receivePrivKey *[32]byte, err error) {
	rm := &RatchetMessage{
		RatchetPublicKey: *ratchetPubkey,
		Payload:          payload,
	}
	sn, err := genSymNonce(rand)
	if err != nil {
		return nil, nil, err
	}
	rm.SymNonce = *sn
	receivePub, receivePriv, err := GenKeyPair(rand)
	if err != nil {
		return nil, nil, err
	}
	rm.ReceiverPublicKey = *receivePub
	return rm, receivePriv, nil
}

const (
	ratchetMessageBaseSize      = 32 + 32 + 32 + 32 + 24
	ratchetMessageNoPayloadSize = ratchetMessageBaseSize + secretbox.Overhead
)

// Return the memory template.
func (rm *RatchetMessage) template() []byte {
	capacity := ratchetMessageNoPayloadSize + len(rm.Payload)
	tmpl := make([]byte, 0, capacity)
	tmpl = append(tmpl, rm.RatchetPublicKey[:]...)
	tmpl = append(tmpl, rm.SenderPublicKey[:]...)
	tmpl = append(tmpl, rm.ReceiverPublicKey[:]...)
	tmpl = append(tmpl, rm.DHNonce[:]...)
	tmpl = append(tmpl, rm.SymNonce[:]...)
	return tmpl
}

// Encrypt the RatchetMessage.
func (rm *RatchetMessage) Encrypt(rand io.Reader) ([]byte, error) {
	secret, sendKey, nonce, err := ToRatchetKey(rand, &rm.RatchetPublicKey)
	if err != nil {
		return nil, err
	}
	rm.DHNonce = *nonce
	rm.SenderPublicKey = *sendKey
	return secretbox.Seal(rm.template(), rm.Payload, &rm.SymNonce, secret), nil
}

// Parse a binary encrypted RatchetMessage into the struct.
func (rm *RatchetMessage) Parse(d []byte) (*RatchetMessage, error) {
	if len(d) < ratchetMessageNoPayloadSize+1 {
		return nil, ErrMessageIncomplete
	}
	orm := new(RatchetMessage)
	copy(orm.RatchetPublicKey[:], d[0:32])
	copy(orm.SenderPublicKey[:], d[32:64])
	copy(orm.ReceiverPublicKey[:], d[64:96])
	copy(orm.DHNonce[:], d[96:128])
	copy(orm.SymNonce[:], d[128:152])
	orm.encPayload = make([]byte, len(d)-152)
	copy(orm.encPayload, d[152:])
	return orm, nil
}

func (rm *RatchetMessage) Decrypt(getSecret ratchet.SecretFunc) error {
	var ok bool
	secret, err := DecryptRatchetKey(&rm.SenderPublicKey, &rm.DHNonce, &rm.RatchetPublicKey, getSecret)
	if err != nil {
		return err
	}
	rm.Payload, ok = secretbox.Open(nil, rm.encPayload, &rm.SymNonce, secret)
	if !ok {
		return ErrCannotDecrypt
	}
	rm.encPayload = nil
	return nil
}
