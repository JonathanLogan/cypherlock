package msgcrypt

import (
	"encoding/binary"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

// EnvelopeMessage is the message to a server.
type EnvelopeMessage struct {
	ReceiverPublicKey [32]byte // ServerKey
	SenderPublicKey   [32]byte // Ephemeral
	DHNonce           [32]byte
	SymNonce          [24]byte
	ValidFrom         uint64
	ValidTo           uint64
	RatchetMessage    []byte // Must be encrypted already.
	encPayload        []byte
}

// NewEnvelopeMessage cretes a new EnvelopeMessage.
func NewEnvelopeMessage(receiverPublicKey *[32]byte, validFrom, validTo uint64, ratchetMessage []byte) *EnvelopeMessage {
	em := &EnvelopeMessage{
		RatchetMessage:    ratchetMessage,
		ReceiverPublicKey: *receiverPublicKey,
		ValidFrom:         validFrom,
		ValidTo:           validTo,
	}
	return em
}

const (
	envelopeMessageBaseSize         = 32 + 32 + 32 + 24
	envelopeMessageExtraPayloadSize = 8 + 8
	envelopeMessageNoPayloadSize    = envelopeMessageExtraPayloadSize + envelopeMessageBaseSize + secretbox.Overhead
)

func (em *EnvelopeMessage) templ() []byte {
	capacity := envelopeMessageNoPayloadSize + len(em.RatchetMessage)
	tmpl := make([]byte, 0, capacity)
	tmpl = append(tmpl, em.ReceiverPublicKey[:]...)
	tmpl = append(tmpl, em.SenderPublicKey[:]...)
	tmpl = append(tmpl, em.DHNonce[:]...)
	tmpl = append(tmpl, em.SymNonce[:]...)
	return tmpl
}

func (em *EnvelopeMessage) genPayload() []byte {
	pl := make([]byte, envelopeMessageExtraPayloadSize, envelopeMessageExtraPayloadSize+len(em.RatchetMessage))
	binary.BigEndian.PutUint64(pl[0:8], em.ValidFrom)
	binary.BigEndian.PutUint64(pl[8:16], em.ValidTo)
	pl = append(pl, em.RatchetMessage...)
	return pl
}

// Encrypt an EnvelopeMessage.
func (em *EnvelopeMessage) Encrypt(rand io.Reader) ([]byte, error) {
	secret, sendKey, nonce, err := ToPublicKey(rand, &em.ReceiverPublicKey)
	if err != nil {
		return nil, err
	}
	sn, err := genSymNonce(rand)
	if err != nil {
		return nil, err
	}
	em.SymNonce = *sn
	em.DHNonce = *nonce
	em.SenderPublicKey = *sendKey
	return secretbox.Seal(em.templ(), em.genPayload(), &em.SymNonce, secret), nil
}

// Parse a binary EnvelopeMesssage.
func (em *EnvelopeMessage) Parse(d []byte) (*EnvelopeMessage, error) {
	if len(d) < envelopeMessageNoPayloadSize {
		return nil, ErrMessageIncomplete
	}
	nem := new(EnvelopeMessage)
	copy(nem.ReceiverPublicKey[:], d[0:32])
	copy(nem.SenderPublicKey[:], d[32:64])
	copy(nem.DHNonce[:], d[64:96])
	copy(nem.SymNonce[:], d[96:120])
	nem.encPayload = make([]byte, len(d)-120)
	copy(nem.encPayload, d[120:])
	return nem, nil
}

func (em *EnvelopeMessage) parseCleartext(d []byte) error {
	if len(d) <= envelopeMessageExtraPayloadSize+1 {
		return ErrMessageIncomplete
	}
	em.ValidFrom = binary.BigEndian.Uint64(d[0:8])
	em.ValidTo = binary.BigEndian.Uint64(d[8:16])
	em.RatchetMessage = make([]byte, 0, len(d)-envelopeMessageExtraPayloadSize)
	em.RatchetMessage = append(em.RatchetMessage, d[16:]...)
	return nil
}

// Decrypt an EnvelopMessage.
func (em *EnvelopeMessage) Decrypt(receiverPrivateKey *[32]byte) error {
	secret := DecryptKey(&em.SenderPublicKey, &em.DHNonce, receiverPrivateKey)
	pl, ok := secretbox.Open(nil, em.encPayload, &em.SymNonce, secret)
	if !ok {
		return ErrCannotDecrypt
	}
	return em.parseCleartext(pl)
}
