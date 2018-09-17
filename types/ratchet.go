// Package types defines types shared between server and client.
package types

import (
	"crypto/sha256"
	"encoding/binary"
)

// PregenerateEntry is a pregenerated Ratchet Key.
type PregenerateEntry struct {
	LineHash  [32]byte // Hash of this line, incorporates previous one.
	Counter   uint64   // Output counter of ratchet.
	ValidFrom uint64   // Time this entry becomes valid.
	ValidTo   uint64   // Time this entry becomes invalid.
	PublicKey [32]byte // Public key of this entry.
}

// NewPregenerateEntry creates a new PreGenerateEntry with the valid hash calculated. Setting previousHash nil means first
// entry in list for fountain.
func NewPregenerateEntry(previousHash *[32]byte, counter, validFrom, validTo uint64, publicKey [32]byte) *PregenerateEntry {
	pge := &PregenerateEntry{
		Counter:   counter,
		ValidFrom: validFrom,
		ValidTo:   validTo,
		PublicKey: publicKey,
	}
	pge.Hash(previousHash)
	return pge
}

// Copy PregenerateEntry.
func (pge *PregenerateEntry) Copy() *PregenerateEntry {
	npge := &PregenerateEntry{
		Counter:   pge.Counter,
		ValidFrom: pge.ValidFrom,
		ValidTo:   pge.ValidTo,
	}
	copy(npge.PublicKey[:], pge.PublicKey[:])
	copy(npge.LineHash[:], pge.LineHash[:])
	return npge
}

// Hash an entry.
func (pge *PregenerateEntry) Hash(previous *[32]byte) {
	npge := pge.Copy()
	if previous != nil {
		copy(npge.LineHash[:], previous[:])
	} else {
		empty := [32]byte{}
		copy(npge.LineHash[:], empty[:])
	}
	d := npge.Marshall()
	h := sha256.New()
	h.Write(d[:])
	nh := h.Sum(nil)
	copy(pge.LineHash[:], nh)
}

// Validate PregenerateEntry.
func (pge *PregenerateEntry) Validate(previous *[32]byte) bool {
	npge := pge.Copy()
	npge.Hash(previous)
	return pge.LineHash == npge.LineHash
}

const pageEntryMarshallSize = 89

// Marshall a PregenerateEntry.
func (pge *PregenerateEntry) Marshall() *[pageEntryMarshallSize]byte {
	ret := new([pageEntryMarshallSize]byte)
	ret[0] = 0x02
	binary.BigEndian.PutUint64(ret[1:9], pge.Counter)
	binary.BigEndian.PutUint64(ret[9:17], pge.ValidFrom)
	binary.BigEndian.PutUint64(ret[17:25], pge.ValidTo)
	copy(ret[25:57], pge.LineHash[:])
	copy(ret[57:89], pge.PublicKey[:])
	return ret
}

// Unmarshall a pregenerate entry.
func Unmarshall(entry *[pageEntryMarshallSize]byte) *PregenerateEntry {
	if entry == nil {
		return nil
	}
	if entry[0] != 0x02 {
		return nil
	}
	npg := &PregenerateEntry{
		Counter:   binary.BigEndian.Uint64(entry[1:9]),
		ValidFrom: binary.BigEndian.Uint64(entry[9:17]),
		ValidTo:   binary.BigEndian.Uint64(entry[17:25]),
	}
	copy(npg.LineHash[:], entry[25:57])
	copy(npg.PublicKey[:], entry[57:89])
	return npg
}
