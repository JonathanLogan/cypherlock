package msgcrypt

import (
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

// ResponseMessage is a message containing a decrypted payload.
type ResponseMessage struct {
	ReceiverPublicKey  [32]byte // RatchetMessage.ReceiverPublicKey
	EphemeralPublicKey [32]byte // Ephemeral
	SenderPublicKey    [32]byte // ServerKey
	DHNonce            [32]byte
	SymNonce           [24]byte
	Payload            []byte
	encPayload         []byte
}

// NewResponseMessage creates a new NewResponseMessage.
func NewResponseMessage(senderPubKey, receiverPubKey *[32]byte, payload []byte) *ResponseMessage {
	return &ResponseMessage{
		SenderPublicKey:   *senderPubKey,
		ReceiverPublicKey: *receiverPubKey,
		Payload:           payload,
	}
}

const (
	responseMessageBaseSize      = 32 + 32 + 32 + 32 + 24
	responseMessageNoPayloadSize = responseMessageBaseSize + secretbox.Overhead
)

func (rmsg *ResponseMessage) template() []byte {
	capacity := responseMessageNoPayloadSize + len(rmsg.Payload)
	tmpl := make([]byte, 0, capacity)

	tmpl = append(tmpl, rmsg.ReceiverPublicKey[:]...)
	tmpl = append(tmpl, rmsg.EphemeralPublicKey[:]...)
	tmpl = append(tmpl, rmsg.SenderPublicKey[:]...)
	tmpl = append(tmpl, rmsg.DHNonce[:]...)
	tmpl = append(tmpl, rmsg.SymNonce[:]...)
	return tmpl
}

// Encrypt a ResponseMessage.
func (rmsg *ResponseMessage) Encrypt(serverPrivateKey *[32]byte, rand io.Reader) ([]byte, error) {
	sn, err := genSymNonce(rand)
	if err != nil {
		return nil, err
	}
	rmsg.SymNonce = *sn
	secret, nonce, ephemeralKey, err := ToEphemeralKey(rand, &rmsg.ReceiverPublicKey, serverPrivateKey)
	if err != nil {
		return nil, err
	}
	rmsg.EphemeralPublicKey = *ephemeralKey
	rmsg.DHNonce = *nonce
	return secretbox.Seal(rmsg.template(), rmsg.Payload, &rmsg.SymNonce, secret), nil
}

// Parse a binary ResponseMessage.
func (rmsg *ResponseMessage) Parse(d []byte) (*ResponseMessage, error) {
	if len(d) < responseMessageNoPayloadSize+1 {
		return nil, ErrMessageIncomplete
	}
	nrmsg := new(ResponseMessage)
	copy(nrmsg.ReceiverPublicKey[:], d[0:32])
	copy(nrmsg.EphemeralPublicKey[:], d[32:64])
	copy(nrmsg.SenderPublicKey[:], d[64:96])
	copy(nrmsg.DHNonce[:], d[96:128])
	copy(nrmsg.SymNonce[:], d[128:152])
	nrmsg.encPayload = make([]byte, len(d)-152)
	copy(nrmsg.encPayload, d[152:])
	return nrmsg, nil
}

// Decrypt a ReponseMessage.
func (rmsg *ResponseMessage) Decrypt(receiverPrivateKey *[32]byte) error {
	var ok bool
	secret := FromEphemeralKey(&rmsg.DHNonce, &rmsg.EphemeralPublicKey, &rmsg.SenderPublicKey, receiverPrivateKey)
	rmsg.Payload, ok = secretbox.Open(nil, rmsg.encPayload, &rmsg.SymNonce, secret)
	if !ok {
		return ErrCannotDecrypt
	}
	rmsg.encPayload = nil
	return nil
}
