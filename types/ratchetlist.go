package types

import (
	"crypto"
	"errors"
	"hash"

	"golang.org/x/crypto/ed25519"
)

// RatchetList is a list of ratchet keys.
type RatchetList struct {
	PreviousLineHash [32]byte                    // Last LineHash of previous list. Ignored for now.
	PublicKeys       []PregenerateEntry          // Pregenerated items.
	ListHash         [32]byte                    // Hash of list.
	EnvelopeKey      [32]byte                    // Curve25519 envelope key, long term.
	SignatureKey     [ed25519.PublicKeySize]byte // Long term signature key of server.
	Signature        [ed25519.SignatureSize]byte // Signature over the above.
	h                hash.Hash                   // Continuous hashing.
	marshalled       []byte                      // Marshalled version.
}

// NewRatchetList returns a new ratchet list. New, Append, set SignatureKey and EnvelopeKey, Sign.
func NewRatchetList(previousLineHash [32]byte, expectedLength int) *RatchetList {
	rl := &RatchetList{
		PreviousLineHash: previousLineHash,
		PublicKeys:       make([]PregenerateEntry, 0, expectedLength),
		marshalled:       make([]byte, 0, expectedLength*89+33+ed25519.PublicKeySize+ed25519.SignatureSize+2),
		h:                crypto.SHA256.New(),
	}
	first := [33]byte{0x01} // LastListHash
	copy(first[1:], previousLineHash[:])
	rl.marshalled = append(rl.marshalled, first[:]...)
	rl.h.Write(first[:])
	return rl
}

// Append an entry to the list.
func (rl *RatchetList) Append(e PregenerateEntry) {
	m := e.Marshall()
	rl.marshalled = append(rl.marshalled, m[:]...)
	rl.PublicKeys = append(rl.PublicKeys, e)
}

// addKeyField adds the key field to the end. 0x03 | EnvelopeKey | SignatureKey
func (rl *RatchetList) addKeyField() {
	lastField := [1 + 32 + ed25519.PublicKeySize]byte{0x03} // Type, LtPK,SigPK
	copy(lastField[1:33], rl.EnvelopeKey[:])
	copy(lastField[33:], rl.SignatureKey[:])
	rl.h.Write(lastField[:])
	rl.marshalled = append(rl.marshalled, lastField[:]...)
	h := rl.h.Sum(nil)
	copy(rl.ListHash[:], h)
}

// Sign RatchetList. Make sure EnvelopeKey and SignatureKey are set.
func (rl *RatchetList) Sign(privateKey *[ed25519.PrivateKeySize]byte) {
	rl.addKeyField()
	signature := ed25519.Sign(privateKey[:], rl.ListHash[:])
	copy(rl.Signature[:], signature)
	rl.marshalled = append(rl.marshalled, signature...)
}

// Bytes returns the marshalled bytes, only valid after signing.
func (rl *RatchetList) Bytes() []byte {
	return rl.marshalled
}

func findLastListHash(d []byte) *[32]byte {
	if len(d) < 33 {
		return nil
	}
	if d[0] != 0x01 {
		return nil
	}
	ret := new([32]byte)
	copy(ret[:], d[1:33])
	return ret
}

func (rl *RatchetList) findPubKeys(d []byte) int {
	var i int
	for i = 33; i < len(d); i = i + pageEntryMarshallSize {
		if d[i] != 0x02 {
			return i
		}
		em := new([pageEntryMarshallSize]byte)
		copy(em[:], d[i:i+pageEntryMarshallSize])
		e := Unmarshall(em)
		if e != nil {
			rl.Append(*e)
		}
	}
	return i
}

func (rl *RatchetList) setBody(d []byte, pos int) error {
	if d[pos] != 0x03 {
		return ErrParse
	}
	minLen := 32 + ed25519.PublicKeySize + ed25519.SignatureSize + 1
	if len(d) < pos+minLen {
		return ErrParse
	}
	copy(rl.EnvelopeKey[:], d[pos+1:pos+1+32])
	copy(rl.SignatureKey[:], d[pos+1+32:pos+1+32+ed25519.PublicKeySize])
	copy(rl.Signature[:], d[pos+1+32+ed25519.PublicKeySize:pos+1+32+ed25519.PublicKeySize+ed25519.SignatureSize])
	return nil
}

// ErrParse is returned in case of a parsing error.
var ErrParse = errors.New("types: parsing error")

// Parse a binary RatchetList into struct.
func (rl *RatchetList) Parse(d []byte) (*RatchetList, error) {
	listHash := findLastListHash(d)
	if listHash == nil {
		return nil, ErrParse
	}
	ret := NewRatchetList(*listHash, 2)
	pos := ret.findPubKeys(d)
	err := ret.setBody(d, pos)
	if err != nil {
		return nil, err
	}
	ret.addKeyField()
	ret.marshalled = nil
	return ret, nil
}

// Verify if a signature in a RatchetList matches the list. Import, list must be parsed or created by API.
// expectPubkey is only verified if not nil.
func (rl *RatchetList) Verify(expectPubkey *[ed25519.PublicKeySize]byte) bool {
	if expectPubkey != nil {
		if *expectPubkey != rl.SignatureKey {
			return false
		}
	}
	return ed25519.Verify(rl.SignatureKey[:], rl.ListHash[:], rl.Signature[:])
}

// MatchKey represents one matching key.
type MatchKey struct {
	ValidFrom   uint64
	ValidTo     uint64
	EnvelopeKey [32]byte
	RatchetKey  [32]byte
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func max(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

// FindRatchetKeys finds keys that fit the validFrom/validTo policy. Returns nil if non found.
func (rl *RatchetList) FindRatchetKeys(validFrom, validTo uint64) []MatchKey {
	if validFrom > validTo {
		return nil
	}
	ret := make([]MatchKey, 0, 1)
	for _, e := range rl.PublicKeys {
		match := false
		switch {
		case e.ValidFrom >= validFrom && e.ValidTo <= validTo:
			match = true
		case e.ValidFrom <= validFrom && validFrom <= e.ValidTo:
			match = true
		case e.ValidFrom <= validTo && validTo <= e.ValidTo:
			match = true
		}
		if match {
			q := MatchKey{
				ValidFrom: max(e.ValidFrom, validFrom),
				ValidTo:   min(e.ValidTo, validTo),
			}
			copy(q.RatchetKey[:], e.PublicKey[:])
			copy(q.EnvelopeKey[:], rl.EnvelopeKey[:])
			ret = append(ret, q)
		}
	}
	if len(ret) == 0 {
		return nil
	}
	return ret
}

// GetTimeFrame returns the timeframe covered by the MatchKeys, holes are ignored!
func GetTimeFrame(keys []MatchKey) (validFrom, validTo uint64) {
	for _, e := range keys {
		if e.ValidFrom < validFrom || validFrom == 0 {
			validFrom = e.ValidFrom
		}
		if e.ValidTo > validTo {
			validTo = e.ValidTo
		}
	}
	return validFrom, validTo
}
