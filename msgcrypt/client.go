package msgcrypt

import (
	"github.com/JonathanLogan/cypherlock/clientinterface"
	"github.com/JonathanLogan/cypherlock/types"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/ed25519"
)

var (
	// ErrNoLocksFound is returned if no matching locks could be found in the keylist of the server.
	ErrNoLocksFound = errors.New("github.com/JonathanLogan/cypherlock/msgcrypt: No matching locks found")
	// ErrNoKeylist is returned if no keylist is available.
	ErrNoKeylist = errors.New("github.com/JonathanLogan/cypherlock/msgcrypt: No keylist available")
	// ErrKeylistUntrusted is returned if the keylist could not be verified.
	ErrKeylistUntrusted = errors.New("github.com/JonathanLogan/cypherlock/msgcryt: Keylist is untrusteed")
)

type GetRatchetCallback func(serverURL string) (*types.RatchetList, error)

// Cypherlock implements the client's github.com/JonathanLogan/cypherlock functionality.
type Cypherlock struct {
	SignatureKey      *[ed25519.PublicKeySize]byte // SignatureKey for verification.
	ServerURL         string                       // Address of the server.
	Storage           clientinterface.Storage      // Storage interface
	ClientRPC         clientinterface.ClientRPC    // RPC interface.
	randomSource      io.Reader                    // Source for random bytes suitable for key generation.
	ratchetPublicKeys *types.RatchetList           // The keylist of the github.com/JonathanLogan/cypherlockd.
}

func (cl *Cypherlock) init() {
	if cl.randomSource == nil {
		cl.randomSource = rand.Reader
	}
}

func (cl *Cypherlock) CreateLock(passphrase []byte, secret []byte, validFrom, validTo uint64) (finalValidFrom, finalValidTo uint64, err error) {
	cl.init()
	secretKey, encrypted, err := EncryptRealSecret(secret, cl.randomSource)
	if err != nil {
		return 0, 0, err
	}
	err = cl.Storage.StoreSecret(encrypted)
	if err != nil {
		return 0, 0, err
	}
	return cl.WriteLock(passphrase, secretKey, validFrom, validTo)
}

func (cl *Cypherlock) getRatchetPublicKeysFromFile() error {
	keys, err := cl.Storage.GetKeylist()
	if err != nil {
		return err
	}
	cl.ratchetPublicKeys = keys
	return nil
}

func (cl *Cypherlock) getRatchetPublicKeysFromCypherlockd() error {
	keys, err := cl.ClientRPC.GetKeylist(cl.ServerURL)
	if err != nil {
		return err
	}
	if keys.Verify(cl.SignatureKey) {
		cl.ratchetPublicKeys = keys
		return cl.Storage.StoreKeylist(keys)
	}
	return ErrKeylistUntrusted
}

func (cl *Cypherlock) getLockTargets(validFrom, validTo uint64) ([]types.MatchKey, error) {
	var loaded bool
	err := cl.getRatchetPublicKeysFromFile()
	if err != nil {
		err := cl.getRatchetPublicKeysFromCypherlockd()
		if err != nil {
			return nil, err
		}
		loaded = true
	}
	lockTargets := cl.ratchetPublicKeys.FindRatchetKeys(validFrom, validTo)
	if lockTargets == nil && !loaded {
		err := cl.getRatchetPublicKeysFromCypherlockd()
		if err != nil {
			return nil, err
		}
		lockTargets = cl.ratchetPublicKeys.FindRatchetKeys(validFrom, validTo)
	}
	if lockTargets == nil {
		return nil, ErrNoLocksFound
	}
	return lockTargets, nil
}

// WriteLock creates a set of oracle messages for the given parameters. It returns the _actual_ time range used.
func (cl *Cypherlock) WriteLock(passphrase []byte, secretKey *[32]byte, validFrom, validTo uint64) (finalValidFrom, finalValidTo uint64, err error) {
	cl.init()

	lockTargets, err := cl.getLockTargets(validFrom, validTo)
	if err != nil {
		return 0, 0, err
	}

	realFrom, realTo := types.GetTimeFrame(lockTargets)
	for _, lockTarget := range lockTargets {
		omt := &OracleMessageTemplate{
			ValidFrom:        lockTarget.ValidFrom,
			ValidTo:          lockTarget.ValidTo,
			ServerURL:        cl.ServerURL,
			ServerPublicKey:  lockTarget.EnvelopeKey,
			RatchetPublicKey: lockTarget.RatchetKey,
		}
		oracleMessage, filename, err := omt.CreateEncrypted(passphrase, secretKey, cl.randomSource)
		if err != nil {
			return 0, 0, err
		}
		err = cl.Storage.StoreLock(filename, oracleMessage)
		if err != nil {
			return 0, 0, err
		}
	}
	return realFrom, realTo, nil
}

// loadLockKey recovers the encryption secret for the real secret.
func (cl *Cypherlock) loadLockKey(passphrase []byte, now uint64) (secretKey *[32]byte, err error) {
	omD, err := cl.Storage.GetLock(now)
	if err != nil {
		return nil, err
	}
	om, err := new(OracleMessage).Decrypt(passphrase, omD)
	if err != nil {
		return nil, err
	}
	responseMessage, err := cl.ClientRPC.Decrypt(cl.ServerURL, om.ServerMessage)
	if err != nil {
		return nil, err
	}
	return om.ProcessResponseMessage(responseMessage)
}

// LoadLock returns the secret from a lock.
func (cl *Cypherlock) LoadLock(passphrase []byte, now uint64) (realSecret []byte, err error) {
	secretKey, err := cl.loadLockKey(passphrase, now)
	if err != nil {
		return nil, err
	}
	encrypteSecret, err := cl.Storage.GetSecret()
	if err != nil {
		return nil, err
	}
	return DecryptRealSecret(secretKey, encrypteSecret)
}

// ExtendLock extends a lock towards the future.
func (cl *Cypherlock) ExtendLock(passphrase []byte, now, validFrom, validTo uint64) (finalValidFrom, finalValidTo uint64, err error) {
	secretKey, err := cl.loadLockKey(passphrase, now)
	if err != nil {
		return 0, 0, err
	}
	return cl.WriteLock(passphrase, secretKey, validFrom, validTo)
}
