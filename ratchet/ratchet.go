// Package ratchet implements a ratcheting algorithm to generate keypairs for curve25519, using SHA256.
package ratchet

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/curve25519"
)

// RatchetState contains the static and dynamic elements of the ratchet.
type RatchetState struct {
	counter    uint64   // counter, increases on each ratcheting.
	static     [32]byte // Static element.
	dynamic    [32]byte // Dynamic element.
	privateKey [32]byte // Curve25519 private key.
	PublicKey  [32]byte // Curve25519 public key.
}

// NewRatchet creates a new RatchetState from a random source.
func NewRatchet(rand io.Reader) (*RatchetState, error) {
	r := &RatchetState{
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

// Marshall RatchetState to bytes.
func (r *RatchetState) Marshall() []byte {
	o := make([]byte, 136)
	binary.BigEndian.PutUint64(o, r.counter)
	copy(o[8:], r.static[:])
	copy(o[40:], r.dynamic[:])
	copy(o[72:], r.privateKey[:])
	copy(o[104:], r.PublicKey[:])
	return o
}

// Unmarshall a RatchetState, returns nil on error.
func (r *RatchetState) Unmarshall(d []byte) *RatchetState {
	if len(d) != 136 {
		return nil
	}
	nr := &RatchetState{
		counter: binary.BigEndian.Uint64(d),
	}
	copy(nr.static[:], d[8:])
	copy(nr.dynamic[:], d[40:])
	copy(nr.privateKey[:], d[72:])
	copy(nr.PublicKey[:], d[104:])
	return nr
}

// Counter returns the current counter value.
func (r *RatchetState) Counter() uint64 {
	return r.counter
}

// Step continues the ratchet by one more step.
func (r *RatchetState) Step() *RatchetState {
	r.counter++
	d := make([]byte, 40)
	binary.BigEndian.PutUint64(d, r.counter)
	copy(d[8:], r.dynamic[:])
	h := hmac.New(sha256.New, r.static[:])
	h.Write(d)
	nd := h.Sum(nil)
	copy(r.dynamic[:], nd)
	r.genkeys()
	return r
}

// Generate private and public key based on Ratchet state.
func (r *RatchetState) genkeys() {
	h := hmac.New(sha256.New, r.dynamic[:])
	h.Write(r.static[:])
	res := h.Sum(nil)
	copy(r.privateKey[:], res)
	curve25519.ScalarBaseMult(&r.PublicKey, &r.privateKey)
}

// Copy a RatchetState to not share memory.
func (r *RatchetState) Copy() *RatchetState {
	n := &RatchetState{
		counter: r.counter,
	}
	copy(n.static[:], r.static[:])
	copy(n.dynamic[:], r.dynamic[:])
	copy(n.privateKey[:], r.privateKey[:])
	copy(n.PublicKey[:], r.PublicKey[:])
	return n
}

// SharedSecret creates a shared secret from the RatchetKey and a curve25519 public key (in) by
// multiplying RatchetKey and with in, and drawing the sha256 of the result.
func (r *RatchetState) SharedSecret(peerPubKey *[32]byte) *[32]byte {
	dst, out := new([32]byte), new([32]byte)
	curve25519.ScalarMult(dst, &r.privateKey, peerPubKey)
	h := sha256.New()
	h.Write(dst[:])
	ss := h.Sum(nil)
	copy(out[:], ss)
	return out
}
