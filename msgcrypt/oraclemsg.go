package msgcrypt

import (
	"encoding/binary"
	"errors"
	"io"
	"strconv"

	"github.com/JonathanLogan/cypherlock/ratchet"
	"github.com/JonathanLogan/cypherlock/timesource"
)

var (
	// ErrPolicyExpired is returned when the policy of a message has expired.
	ErrPolicyExpired = errors.New("github.com/JonathanLogan/cypherlock/msgcrypt: Policy expired")
)

// OracleMessage contains an oracle message for the sender, and the secret access.
type OracleMessage struct {
	ValidFrom          uint64   // From when is the message valid.
	ValidTo            uint64   // Until when is the message valid.
	ResponsePrivateKey [32]byte // The private key to decrypt the server response.
	EncryptedSecretKey []byte   // The encrypted key to decrypt the secret.
	ServerURL          string   // The URL to send the message to.
	ServerMessage      []byte   // The message to send to the server. about 352 bytes.
}

func encodeSlice(d []byte) []byte {
	l := make([]byte, 8, 8+len(d))
	binary.BigEndian.PutUint64(l, uint64(len(d)))
	return append(l, d...)
}

// Valid returns true if the message is currently valid.
func (om *OracleMessage) Valid() bool {
	now := uint64(timesource.Clock.Now().Unix())
	if om.ValidFrom > now || om.ValidTo < now {
		return false
	}
	return true
}

// ProcessResponseMessage decrypts the responseMessage and secret.
func (om *OracleMessage) ProcessResponseMessage(d []byte) (secretKey *[32]byte, err error) {
	// decrypt ReponseMessage
	rm, err := new(ResponseMessage).Parse(d)
	if err != nil {
		return nil, err
	}
	err = rm.Decrypt(&om.ResponsePrivateKey)
	if err != nil {
		return nil, err
	}
	// Decrypt response content
	key := new([32]byte)
	copy(key[:], rm.Payload)
	secretT, err := SymDecrypt(key, om.EncryptedSecretKey)
	if err != nil {
		return nil, err
	}
	secretKey = new([32]byte)
	copy(secretKey[:], secretT)
	return secretKey, nil
}

// Marshall an OracleMessage.
func (om OracleMessage) Marshall() []byte {
	cap := 8 + 8 + 32 + 8 + len(om.EncryptedSecretKey) + 8 + len(om.ServerURL) + 8 + len(om.ServerMessage)
	ret := make([]byte, 48, cap)
	binary.BigEndian.PutUint64(ret[0:8], om.ValidFrom)
	binary.BigEndian.PutUint64(ret[8:16], om.ValidTo)
	copy(ret[16:48], om.ResponsePrivateKey[:])
	ret = append(ret, encodeSlice(om.EncryptedSecretKey)...)
	ret = append(ret, encodeSlice([]byte(om.ServerURL))...)
	ret = append(ret, encodeSlice(om.ServerMessage)...)
	return ret
}

// Unmarshall an OracleMessage.
func (om *OracleMessage) Unmarshall(d []byte) (*OracleMessage, error) {
	if len(d) < 8+8+32+8+1+8+1+8+1 {
		return nil, ErrMessageIncomplete
	}
	ret := &OracleMessage{
		ValidFrom: binary.BigEndian.Uint64(d[0:8]),
		ValidTo:   binary.BigEndian.Uint64(d[8:16]),
	}
	copy(ret.ResponsePrivateKey[:], d[16:48])
	// EncryptedSecretKey
	l := int(binary.BigEndian.Uint64(d[48:56]))
	if len(d) < 56+l {
		return nil, ErrMessageIncomplete
	}
	c := make([]byte, l)
	copy(c, d[56:56+l])
	ret.EncryptedSecretKey = c
	// ServerURL
	l = l + 56
	l2 := int(binary.BigEndian.Uint64(d[l : l+8]))
	if len(d) < l+8+l2 {
		return nil, ErrMessageIncomplete
	}
	c = make([]byte, l2)
	copy(c, d[l+8:l+8+l2])
	ret.ServerURL = string(c)
	// ServerMessage
	l = l + 8 + l2
	l2 = int(binary.BigEndian.Uint64(d[l : l+8]))
	if len(d) < l+8+l2 {
		return nil, ErrMessageIncomplete
	}
	c = make([]byte, l2)
	copy(c, d[l+8:l+8+l2])
	ret.ServerMessage = c
	return ret, nil
}

// Encrypt the OracleMessage
func (om OracleMessage) Encrypt(passphrase []byte, rand io.Reader) (encrypted []byte, filename string, err error) {
	fn := strconv.FormatUint(om.ValidFrom, 10) + "-" + strconv.FormatUint(om.ValidTo, 10) + ".oracle"
	enc, err := PasswordEncryt(passphrase, om.Marshall(), rand)
	if err != nil {
		return nil, "", err
	}
	return enc, fn, nil
}

func (om OracleMessage) Decrypt(passphrase, message []byte) (*OracleMessage, error) {
	ct, err := PasswordDecrypt(passphrase, message)
	if err != nil {
		return nil, err
	}
	return new(OracleMessage).Unmarshall(ct)
}

// OracleMessageTemplate is the template from which to create an OracleMessage.
type OracleMessageTemplate struct {
	ValidFrom        uint64   // From when is the message valid.
	ValidTo          uint64   // Until when is the message valid.
	ServerURL        string   // The URL to send the message to.
	ServerPublicKey  [32]byte // The server's public key.
	RatchetPublicKey [32]byte // The public key for the ratchet.
}

func (omt OracleMessageTemplate) CreateEncrypted(passphrase []byte, secretKey *[32]byte, rand io.Reader) (enc []byte, filename string, err error) {
	om, err := omt.Create(secretKey, rand)
	if err != nil {
		return nil, "", err
	}
	return om.Encrypt(passphrase, rand)
}

// Create an OracleMessage from an OracleMessageTemplate
func (omt OracleMessageTemplate) Create(secretKey *[32]byte, rand io.Reader) (*OracleMessage, error) {
	// Encryt the SecretKey
	secretEncryptKey, err := genRandom(rand)
	if err != nil {
		return nil, err
	}
	encryptedSecret, err := SymEncrypt(secretEncryptKey, secretKey[:], rand)
	if err != nil {
		return nil, err
	}
	// Create the RatchetMessage
	ratchetMessage, receivePrivKey, err := NewRatchetMessage(&omt.RatchetPublicKey, secretEncryptKey[:], rand)
	if err != nil {
		return nil, err
	}
	ratchetMessageBytes, err := ratchetMessage.Encrypt(rand)
	if err != nil {
		return nil, err
	}
	// Create the EnvelopeMessage
	envMsg := NewEnvelopeMessage(&omt.ServerPublicKey, omt.ValidFrom, omt.ValidTo, ratchetMessageBytes)
	envMsgB, err := envMsg.Encrypt(rand)
	if err != nil {
		return nil, err
	}
	ret := &OracleMessage{
		ValidFrom:          omt.ValidFrom,
		ValidTo:            omt.ValidTo,
		EncryptedSecretKey: encryptedSecret,
		ServerURL:          omt.ServerURL,
		ResponsePrivateKey: *receivePrivKey,
		ServerMessage:      envMsgB,
	}
	return ret, nil
}

// ServerConfig contains the static configuration for OracleMessage processing.
type ServerConfig struct {
	PublicKey, PrivateKey [32]byte           // Server's long term curve25519 keypari
	GetSecretFunc         ratchet.SecretFunc // Lookup function of fountain.
	RandomSource          io.Reader          // Random source for key generation.
}

// ProcessOracleMessage is the server-side processing of OracleMessages.
func (sc ServerConfig) ProcessOracleMessage(d []byte) ([]byte, error) {
	// Decrypt envelope.s
	em, err := new(EnvelopeMessage).Parse(d)
	if err != nil {
		return nil, err
	}
	err = em.Decrypt(&sc.PrivateKey)
	if err != nil {
		return nil, err
	}
	// Validate:  ValidFrom  ValidTo
	now := uint64(timesource.Clock.Now().Unix())
	if em.ValidFrom > now || em.ValidTo < now {
		return nil, ErrPolicyExpired
	}
	// RatchetMessage.
	rm, err := new(RatchetMessage).Parse(em.RatchetMessage)
	if err != nil {
		return nil, err
	}
	err = rm.Decrypt(sc.GetSecretFunc)
	if err != nil {
		return nil, err
	}
	// ResponseMessage
	rspm := NewResponseMessage(&sc.PublicKey, &rm.ReceiverPublicKey, rm.Payload)
	rspmB, err := rspm.Encrypt(&sc.PrivateKey, sc.RandomSource)
	if err != nil {
		return nil, err
	}
	return rspmB, nil
}
