// Package ratchetserver manages a ratcheting server. It takes care of handling
// fountain creation, pregeneration and persistence.
package ratchetserver

import (
	"github.com/JonathanLogan/cypherlock/msgcrypt"
	"github.com/JonathanLogan/cypherlock/ratchet"
	"github.com/JonathanLogan/cypherlock/timesource"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

type ServerKeys struct {
	EncPublicKey  [32]byte                     // curve25519 public key.
	EncPrivateKey [32]byte                     // curve25519 private key.
	SigPublicKey  [ed25519.PublicKeySize]byte  // ed25519 public key.
	SigPrivateKey [ed25519.PrivateKeySize]byte // ed25519 private key.
}

// NewServerKeys generates new server keys.
func NewServerKeys(rand io.Reader) (*ServerKeys, error) {
	sk := new(ServerKeys)
	_, err := io.ReadFull(rand, sk.EncPrivateKey[:])
	if err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&sk.EncPublicKey, &sk.EncPrivateKey)
	pubkey, privkey, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	copy(sk.SigPublicKey[:], pubkey)
	copy(sk.SigPrivateKey[:], privkey)
	return sk, nil
}

// Marshall ServerKeys into []byte.
func (sk *ServerKeys) Marshall() []byte {
	o := make([]byte, 0, 32+32+ed25519.PublicKeySize+ed25519.PrivateKeySize)
	o = append(o, sk.EncPublicKey[:]...)
	o = append(o, sk.EncPrivateKey[:]...)
	o = append(o, sk.SigPublicKey[:]...)
	o = append(o, sk.SigPrivateKey[:]...)
	return o
}

// Unmarshall byte slice into serverkeys. Returns the filled serverkeys, does not change recipient.
func (sk *ServerKeys) Unmarshall(d []byte) (*ServerKeys, error) {
	if len(d) != 32+32+ed25519.PublicKeySize+ed25519.PrivateKeySize {
		return nil, errors.New("github.com/JonathanLogan/cypherlock/ratchetserver: Unmarshall error.")
	}
	skn := new(ServerKeys)
	copy(skn.EncPublicKey[:], d[0:32])
	copy(skn.EncPrivateKey[:], d[32:64])
	copy(skn.SigPublicKey[:], d[64:64+ed25519.PublicKeySize])
	copy(skn.SigPrivateKey[:], d[64+ed25519.PublicKeySize:64+ed25519.PublicKeySize+ed25519.PrivateKeySize])
	return skn, nil
}

// RatchetServer implements a ratchet server.
type RatchetServer struct {
	keys         *ServerKeys
	fountain     *ratchet.Fountain
	pregenerator *ratchet.PreGenerator
	persistence  Persistence
	keylist      []byte // current signed keylist pregeneration.
	serverConfig *msgcrypt.ServerConfig
	ticker       timesource.Ticker
	isStarted    bool
}

// NewRatchetServer creates a new RatchetServer.
// interKeyDuration is the time between ratchet steps. Seconds.
// pregenInterval is the time for which to pregenerate keys. Seconds.
func NewRatchetServer(persistence Persistence, rand io.Reader, interKeyDuration, pregenInterval int64) (*RatchetServer, error) {
	var err error
	rs := new(RatchetServer)
	rs.persistence = persistence
	rs.keys, err = NewServerKeys(rand)
	if err != nil {
		return nil, err
	}
	rs.fountain, err = ratchet.NewFountain(interKeyDuration, rand)
	if err != nil {
		return nil, err
	}
	rs.pregenerator = ratchet.NewPregeneratorFromFountain(rs.fountain, pregenInterval)
	err = rs.persist()
	if err != nil {
		return nil, err
	}
	rs.serverConfig = &msgcrypt.ServerConfig{
		PublicKey:     rs.keys.EncPublicKey,
		PrivateKey:    rs.keys.EncPrivateKey,
		GetSecretFunc: rs.fountain.GetSecret,
		RandomSource:  rand,
	}
	return rs, nil
}

// SignatureKey returns the key to verify the identity of this server.
func (rs *RatchetServer) SignatureKey() [ed25519.PublicKeySize]byte {
	return rs.keys.SigPublicKey
}

func (rs *RatchetServer) Persist() error {
	return rs.persist()
}

// Write data to persistance layer.
func (rs *RatchetServer) persist() error {
	// StoreTypeServerKeys
	if err := rs.persistence.Store(StoreTypeServerKeys, rs.keys.Marshall()); err != nil {
		return err
	}
	// StoreTypeFountain
	if err := rs.persistence.Store(StoreTypeFountain, rs.fountain.Marshall()); err != nil {
		return err
	}
	// StoreTypePregen
	if err := rs.persistence.Store(StoreTypePregen, rs.pregenerator.Marshall()); err != nil {
		return err
	}
	// StoreTypeKeyList
	if rs.keylist != nil {
		if err := rs.persistence.Store(StoreTypeKeyList, rs.keylist); err != nil {
			return err
		}
	}
	return nil
}

// LoadRatchetServer from persistence layer.
func LoadRatchetServer(persistence Persistence, rand io.Reader) (*RatchetServer, error) {
	rs := new(RatchetServer)
	rs.persistence = persistence
	// StoreTypeServerKeys
	if d, err := rs.persistence.Load(StoreTypeServerKeys); err == nil {
		if serverkeys, err := new(ServerKeys).Unmarshall(d); err == nil {
			rs.keys = serverkeys
		} else {
			return nil, err
		}
	} else {
		return nil, err
	}
	// StoreTypeFountain
	if d, err := rs.persistence.Load(StoreTypeFountain); err == nil {
		if fountain := new(ratchet.Fountain).Unmarshall(d); fountain != nil {
			rs.fountain = fountain
		} else {
			return nil, errors.New("github.com/JonathanLogan/cypherlock/ratchtserver: fountain state cannot be loaded.")
		}
	} else {
		return nil, err
	}
	// StoreTypePregen
	if d, err := rs.persistence.Load(StoreTypePregen); err == nil {
		if pregenerator := new(ratchet.PreGenerator).Unmarshall(rs.fountain, d); pregenerator != nil {
			rs.pregenerator = pregenerator
		} else {
			return nil, errors.New("github.com/JonathanLogan/cypherlock/ratchtserver: pregenerator state cannot be loaded.")
		}
	} else {
		return nil, err
	}
	rs.serverConfig = &msgcrypt.ServerConfig{
		PublicKey:     rs.keys.EncPublicKey,
		PrivateKey:    rs.keys.EncPrivateKey,
		GetSecretFunc: rs.fountain.GetSecret,
		RandomSource:  rand,
	}
	// StoreTypeKeyList
	if d, err := rs.persistence.Load(StoreTypeKeyList); err == nil {
		rs.keylist = d
	}
	return rs, nil
}

func (rs *RatchetServer) GenerateKeys() {
	if keylist := rs.pregenerator.Generate(); keylist != nil {
		keylist.EnvelopeKey = rs.keys.EncPublicKey
		keylist.SignatureKey = rs.keys.SigPublicKey
		keylist.Sign(&rs.keys.SigPrivateKey)
		rs.keylist = keylist.Bytes()
		if err := rs.persistence.Store(StoreTypeKeyList, keylist.Bytes()); err != nil {
			panic(err)
		}
	}
}

// StartService: Start the ratchetserver goroutine.
func (rs *RatchetServer) StartService() {
	if rs.isStarted {
		return
	}
	rs.GenerateKeys()
	rs.fountain.StartService()
	rs.ticker = timesource.Clock.NewTicker(time.Minute * 5)
	go func() {
		for range rs.ticker.Chan() {
			// Pregenerate.
			rs.GenerateKeys()
			// Call persistence.
			if err := rs.persist(); err != nil {
				panic(err)
			}
		}
	}()
}

// Stop background service.
func (rs *RatchetServer) StopService() {
	rs.ticker.Stop()
	rs.isStarted = false
}

// GetKeys returns the current pregenerated keys. EXPOSED.
func (rs *RatchetServer) GetKeys() []byte {
	// Separate all memory.
	kl := make([]byte, len(rs.keylist))
	copy(kl, rs.keylist)
	return kl
}

// Decrypt the message and return it's payload. Only use over TLS. EXPOSED.
func (rs *RatchetServer) Decrypt(msg []byte) ([]byte, error) {
	return rs.serverConfig.ProcessOracleMessage(msg)
}
