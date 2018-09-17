// Package ratchet implements a ratcheting algorithm to generate keypairs for curve25519, using SHA256.
package ratchet

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/curve25519"
)

// State contains the static and dynamic elements of the ratchet.
type State struct {
	counter    uint64   // counter, increases on each ratcheting.
	static     [32]byte // Static element.
	dynamic    [32]byte // Dynamic element.
	privateKey [32]byte // Curve25519 private key.
	PublicKey  [32]byte // Curve25519 public key.
}

// NewRatchet creates a new ratchet state from a random source.
func NewRatchet(rand io.Reader) (*State, error) {
	r := &State{
		counter: 0,
	}
	_, err := io.ReadFull(rand, r.static[:])
	if err != nil {
		return nil, err
	}
	_, err = io.ReadFull(rand, r.dynamic[:])
	if err != nil {
		return nil, err
	}
	r.Step()
	return r, nil
}

// Marshall ratchet state to bytes.
func (s *State) Marshall() []byte {
	o := make([]byte, 136)
	binary.BigEndian.PutUint64(o, s.counter)
	copy(o[8:], s.static[:])
	copy(o[40:], s.dynamic[:])
	copy(o[72:], s.privateKey[:])
	copy(o[104:], s.PublicKey[:])
	return o
}

// Unmarshall a ratchet state, returns nil on error.
func (s *State) Unmarshall(d []byte) *State {
	if len(d) != 136 {
		return nil
	}
	ns := &State{
		counter: binary.BigEndian.Uint64(d),
	}
	copy(ns.static[:], d[8:])
	copy(ns.dynamic[:], d[40:])
	copy(ns.privateKey[:], d[72:])
	copy(ns.PublicKey[:], d[104:])
	return ns
}

// Counter returns the current counter value.
func (s *State) Counter() uint64 {
	return s.counter
}

// Step continues the ratchet by one more step.
func (s *State) Step() *State {
	s.counter++
	d := make([]byte, 40)
	binary.BigEndian.PutUint64(d, s.counter)
	copy(d[8:], s.dynamic[:])
	h := hmac.New(sha256.New, s.static[:])
	h.Write(d)
	nd := h.Sum(nil)
	copy(s.dynamic[:], nd)
	s.genkeys()
	return s
}

// Generate private and public key based on ratchet state.
func (s *State) genkeys() {
	h := hmac.New(sha256.New, s.dynamic[:])
	h.Write(s.static[:])
	res := h.Sum(nil)
	copy(s.privateKey[:], res)
	curve25519.ScalarBaseMult(&s.PublicKey, &s.privateKey)
}

// Copy a ratchet state to not share memory.
func (s *State) Copy() *State {
	n := &State{
		counter: s.counter,
	}
	copy(n.static[:], s.static[:])
	copy(n.dynamic[:], s.dynamic[:])
	copy(n.privateKey[:], s.privateKey[:])
	copy(n.PublicKey[:], s.PublicKey[:])
	return n
}

// SharedSecret creates a shared secret from the RatchetKey and a curve25519 public key (in) by
// multiplying RatchetKey and with in, and drawing the sha256 of the result.
func (s *State) SharedSecret(peerPubKey *[32]byte) *[32]byte {
	dst, out := new([32]byte), new([32]byte)
	curve25519.ScalarMult(dst, &s.privateKey, peerPubKey)
	h := sha256.New()
	h.Write(dst[:])
	ss := h.Sum(nil)
	copy(out[:], ss)
	return out
}
