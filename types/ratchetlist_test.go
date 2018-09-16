package types

import (
	"crypto/rand"
	"io"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

func genCurve25519KeyPair() (privkey, pubkey *[32]byte) {
	privkey, pubkey = new([32]byte), new([32]byte)
	_, err := io.ReadFull(rand.Reader, privkey[:])
	if err != nil {
		panic(err)
	}
	curve25519.ScalarBaseMult(pubkey, privkey)
	return privkey, pubkey
}

func genED25519KeyPair() (privkey *[ed25519.PrivateKeySize]byte, pubkey *[ed25519.PublicKeySize]byte) {
	privkey = new([ed25519.PrivateKeySize]byte)
	pubkey = new([ed25519.PublicKeySize]byte)
	pubT, privT, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	copy(privkey[:], privT)
	copy(pubkey[:], pubT)
	return privkey, pubkey
}

func TestRatchetList(t *testing.T) {
	sigPrivkey, sigPubkey := genED25519KeyPair()
	privkey, pubkey := genCurve25519KeyPair()
	_ = privkey
	previousLineHash := [32]byte{0x01, 0x02}
	rl := NewRatchetList(previousLineHash, 10)
	rl.EnvelopeKey = *pubkey
	rl.SignatureKey = *sigPubkey
	rl.Append(PregenerateEntry{
		LineHash:  [32]byte{0x01, 0x01},
		Counter:   1,
		ValidFrom: 1,
		ValidTo:   100,
		PublicKey: [32]byte{0x01, 0x02},
	})
	rl.Append(PregenerateEntry{
		LineHash:  [32]byte{0x02, 0x01},
		Counter:   2,
		ValidFrom: 101,
		ValidTo:   200,
		PublicKey: [32]byte{0x02, 0x02},
	})
	rl.Append(PregenerateEntry{
		LineHash:  [32]byte{0x03, 0x01},
		Counter:   3,
		ValidFrom: 201,
		ValidTo:   300,
		PublicKey: [32]byte{0x03, 0x02},
	})
	rl.Sign(sigPrivkey)
	rl2, err := new(RatchetList).Parse(rl.Bytes())
	if err != nil {
		t.Fatalf("Parse: %s", err)
	}
	if rl.PreviousLineHash != rl2.PreviousLineHash {
		t.Error("PreviousLineHash")
	}
	if len(rl.PublicKeys) == len(rl2.PublicKeys) {
		for i, e := range rl.PublicKeys {
			if e.LineHash != rl2.PublicKeys[i].LineHash {
				t.Errorf("LineHash: %d", i)
			}
			if e.Counter != rl2.PublicKeys[i].Counter {
				t.Errorf("Counter: %d", i)
			}
			if e.ValidFrom != rl2.PublicKeys[i].ValidFrom {
				t.Errorf("ValidFrom: %d", i)
			}
			if e.ValidTo != rl2.PublicKeys[i].ValidTo {
				t.Errorf("ValidTo: %d", i)
			}
			if e.PublicKey != rl2.PublicKeys[i].PublicKey {
				t.Errorf("PublicKey: %d", i)
			}
		}
	} else {
		t.Error("Public Keys missed")
	}
	if rl.EnvelopeKey != rl2.EnvelopeKey {
		t.Error("EnvelopeKey")
	}
	if rl.SignatureKey != rl2.SignatureKey {
		t.Error("SignatureKey")
	}
	if rl.Signature != rl2.Signature {
		t.Error("Signature")
	}
	if rl.ListHash != rl2.ListHash {
		t.Error("ListHash")
	}
	if !rl.Verify(sigPubkey) {
		t.Error("Does not verify after create")
	}
	if !rl2.Verify(sigPubkey) {
		t.Error("Does not verify after parse")
	}
	if !rl2.Verify(nil) {
		t.Error("Does not verify after parse (nil)")
	}
	if sigPubkey[2] == 0x01 {
		sigPubkey[2] = 0x00
	} else {
		sigPubkey[2] = 0x01
	}
	if rl2.Verify(sigPubkey) {
		t.Error("May not verify wrong key")
	}
	keys := rl.FindRatchetKeys(1, 100)
	if len(keys) != 1 {
		t.Error("FindRatchetKeys 1")
	}
	keys = rl.FindRatchetKeys(1, 150)
	if len(keys) != 2 {
		t.Error("FindRatchetKeys 2")
	}
	keys = rl.FindRatchetKeys(1, 203)
	if len(keys) != 3 {
		t.Error("FindRatchetKeys 3")
	}
	keys = rl.FindRatchetKeys(102, 203)
	if len(keys) != 2 {
		t.Error("FindRatchetKeys 4")
	}
	keys = rl.FindRatchetKeys(102, 303)
	if len(keys) != 2 {
		t.Error("FindRatchetKeys 5")
	}
	keys = rl.FindRatchetKeys(0, 303)
	if len(keys) != 3 {
		t.Error("FindRatchetKeys 6")
	}
}
