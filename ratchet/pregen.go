package ratchet

import (
	"encoding/binary"

	"github.com/JonathanLogan/cypherlock/types"
)

type PreGenerator struct {
	ratchet        *RatchetState
	startdate      int64    // Unix time of the start date.
	duration       int64    // Number of seconds between ratchet steps.
	pregenInterval int64    // For how long to generate keys in advance.
	lastCounter    uint64   // Last counter for which we generated.
	lastLineHash   [32]byte // Last linehash generated.
}

// NewPregeneratorFromFountain creates a new PreGenerator from a fountain. Use only when
// creating a new fountain. Use UnmarshallGenerator when unmarshalling.
func NewPregeneratorFromFountain(f *Fountain, pregenInterval int64) *PreGenerator {
	pg := &PreGenerator{
		startdate:      f.startdate,
		duration:       f.duration,
		pregenInterval: pregenInterval,
		ratchet:        f.serviceDesc.ratchet.Copy(),
		lastCounter:    1,
	}
	return pg
}

// Marshall the PreGenerator.
func (pg *PreGenerator) Marshall() []byte {
	o := make([]byte, 64)
	binary.BigEndian.PutUint64(o, uint64(pg.startdate))
	binary.BigEndian.PutUint64(o[8:], uint64(pg.duration))
	binary.BigEndian.PutUint64(o[16:], pg.lastCounter)
	binary.BigEndian.PutUint64(o[24:], uint64(pg.pregenInterval))
	copy(o[32:], pg.lastLineHash[:])
	return o
}

// Unmarshall a pregenerator from bytes and the fountain. Return nil on error.
func (pg *PreGenerator) Unmarshall(f *Fountain, d []byte) *PreGenerator {
	if len(d) < 64 {
		return nil
	}
	pgn := &PreGenerator{
		ratchet:        f.serviceDesc.ratchet.Copy(),
		startdate:      int64(binary.BigEndian.Uint64(d[:8])),
		duration:       int64(binary.BigEndian.Uint64(d[8:16])),
		lastCounter:    binary.BigEndian.Uint64(d[16:24]),
		pregenInterval: int64(binary.BigEndian.Uint64(d[24:32])),
	}
	copy(pgn.lastLineHash[:], d[32:])
	return pgn
}

func (pg *PreGenerator) Generate() *types.RatchetList {
	// Always make sure we're at the last position first.
	if pg.lastCounter < pg.ratchet.Counter() {
		for i := pg.ratchet.Counter(); i <= pg.lastCounter; i++ {
			pg.ratchet.Step()
		}
	}

	// Only do pregenedation when at least half of the previous pregen has been used up or
	// we have never done the initial pregeneration.
	currentStep := uint64(((unixNow() - pg.startdate) / pg.duration) + 1)
	if currentStep > pg.ratchet.Counter() {
		for i := pg.ratchet.Counter(); i <= currentStep; i++ {
			pg.ratchet.Step()
		}
	}
	workRatchet := pg.ratchet.Copy()
	stepsPeriod := uint64(pg.pregenInterval / pg.duration)
	if stepsPeriod < 1 {
		stepsPeriod = 2
	}

	if (currentStep - pg.lastCounter) >= stepsPeriod/2 {
		return nil
	}

	list := types.NewRatchetList(pg.lastLineHash, int(stepsPeriod))
	previousHash := &pg.lastLineHash
	if pg.lastLineHash == [32]byte{} {
		previousHash = nil
	}
	for i := uint64(0); i <= stepsPeriod; i++ {
		from := uint64(pg.startdate + (int64(workRatchet.Counter())-1)*pg.duration)
		to := uint64(int64(from) + pg.duration)

		e := types.NewPregenerateEntry(previousHash, workRatchet.Counter(), from, to, workRatchet.PublicKey)
		list.Append(*e)
		workRatchet.Step()
	}
	pg.ratchet = workRatchet
	pg.lastCounter = workRatchet.Counter()
	return list
}
