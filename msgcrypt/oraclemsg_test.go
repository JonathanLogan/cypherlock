package msgcrypt

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/JonathanLogan/timesource"
)

func TestOracleMessageMarshall(t *testing.T) {
	td := &OracleMessage{
		ValidFrom:          298,
		ValidTo:            409812,
		ResponsePrivateKey: [32]byte{0x01, 0x2, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		EncryptedSecretKey: []byte("EncryptedSecretKey"),
		ServerURL:          "ServerURL",
		ServerMessage:      []byte("ServerMessage"),
	}
	m := td.Marshall()
	td2, err := new(OracleMessage).Unmarshall(m)
	if err != nil {
		t.Errorf("Unmarshall: %s", err)
	}
	if td.ValidFrom != td2.ValidFrom {
		t.Error("ValidFrom")
	}
	if td.ValidTo != td2.ValidTo {
		t.Error("ValidTo")
	}
	if td.ResponsePrivateKey != td2.ResponsePrivateKey {
		t.Error("ResponsePrivateKey")
	}
	if !bytes.Equal(td.EncryptedSecretKey, td2.EncryptedSecretKey) {
		t.Error("EncryptedSecretKey")
	}
	if td.ServerURL != td2.ServerURL {
		t.Error("ServerURL")
	}
	if !bytes.Equal(td.ServerMessage, td2.ServerMessage) {
		t.Error("ServerMessage")
	}
}

func TestOracleMessageCrypt(t *testing.T) {
	pass := []byte("Secret passphrase")
	td := &OracleMessage{
		ValidFrom:          298,
		ValidTo:            409812,
		ResponsePrivateKey: [32]byte{0x01, 0x2, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		EncryptedSecretKey: []byte("EncryptedSecretKey"),
		ServerURL:          "ServerURL",
		ServerMessage:      []byte("ServerMessage"),
	}
	enc, _, err := td.Encrypt(pass, rand.Reader)
	if err != nil {
		t.Fatalf("Encrypt: %s", err)
	}
	td2, err := new(OracleMessage).Decrypt(pass, enc)
	if err != nil {
		t.Errorf("Unmarshall: %s", err)
	}
	if td.ValidFrom != td2.ValidFrom {
		t.Error("ValidFrom")
	}
	if td.ValidTo != td2.ValidTo {
		t.Error("ValidTo")
	}
	if td.ResponsePrivateKey != td2.ResponsePrivateKey {
		t.Error("ResponsePrivateKey")
	}
	if !bytes.Equal(td.EncryptedSecretKey, td2.EncryptedSecretKey) {
		t.Error("EncryptedSecretKey")
	}
	if td.ServerURL != td2.ServerURL {
		t.Error("ServerURL")
	}
	if !bytes.Equal(td.ServerMessage, td2.ServerMessage) {
		t.Error("ServerMessage")
	}
}

func TestOracleMessageCreate(t *testing.T) {
	passphrase := []byte("Some secret passphrase")
	secretKey, _ := genRandom(rand.Reader)
	pubkeyServer, privkeyServer := genTestKeys()
	pubkeyRatchet, privkeyRatchet := genTestKeys()

	sc := &ServerConfig{
		PublicKey:     *pubkeyServer,
		PrivateKey:    *privkeyServer,
		GetSecretFunc: lookupF(pubkeyRatchet, privkeyRatchet),
		RandomSource:  rand.Reader,
	}

	_, _ = privkeyServer, privkeyRatchet
	omt := &OracleMessageTemplate{
		ValidFrom:        uint64(timesource.Clock.Now().Unix()),
		ValidTo:          uint64(timesource.Clock.Now().Unix()) + 3600,
		ServerURL:        "https://test.com",
		ServerPublicKey:  *pubkeyServer,
		RatchetPublicKey: *pubkeyRatchet,
	}
	enc, fn, err := omt.CreateEncrypted(passphrase, secretKey, rand.Reader)
	if err != nil {
		t.Fatalf("CreateEncrypted: %s", err)
	}
	_, _ = fn, enc
	om, err := new(OracleMessage).Decrypt(passphrase, enc)
	if err != nil {
		t.Fatalf("Decrypt: %s", err)
	}
	if !om.Valid() {
		t.Error("Valid: false")
	}
	resp, err := sc.ProcessOracleMessage(om.ServerMessage)
	if err != nil {
		t.Fatalf("ProcessOracleMessage: %s", err)
	}
	decSecret, err := om.ProcessResponseMessage(resp)
	if err != nil {
		t.Fatalf("ProcessResponseMessage: %s", err)
	}
	if *secretKey != *decSecret {
		t.Error("Secrets don't match")
	}
}
