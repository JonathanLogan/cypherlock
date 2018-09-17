// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// We have an implementation in amd64 assembly so this code is only run on
// non-amd64 platforms. The amd64 assembly does not support gccgo.
// +build !amd64 gccgo appengine

package curve25519

func scalarMult(out, in, base *[32]byte) {
	var e [32]byte

	copy(e[:], in[:])
	e[0] &= 248
	e[31] &= 127
	e[31] |= 64

	var x1, x2, z2, x3, z3, tmp0, tmp1 fieldElement
	feFromBytes(&x1, base)
	feOne(&x2)
	feCopy(&x3, &x1)
	feOne(&z3)

	swap := int32(0)
	for pos := 254; pos >= 0; pos-- {
		b := e[pos/8] >> uint(pos&7)
		b &= 1
		swap ^= int32(b)
		feCSwap(&x2, &x3, swap)
		feCSwap(&z2, &z3, swap)
		swap = int32(b)

		feSub(&tmp0, &x3, &z3)
		feSub(&tmp1, &x2, &z2)
		feAdd(&x2, &x2, &z2)
		feAdd(&z2, &x3, &z3)
		feMul(&z3, &tmp0, &x2)
		feMul(&z2, &z2, &tmp1)
		feSquare(&tmp0, &tmp1)
		feSquare(&tmp1, &x2)
		feAdd(&x3, &z3, &z2)
		feSub(&z2, &z3, &z2)
		feMul(&x2, &tmp1, &tmp0)
		feSub(&tmp1, &tmp1, &tmp0)
		feSquare(&z2, &z2)
		feMul121666(&z3, &tmp1)
		feSquare(&x3, &x3)
		feAdd(&tmp0, &tmp0, &z3)
		feMul(&z3, &x1, &z2)
		feMul(&z2, &tmp1, &tmp0)
	}

	feCSwap(&x2, &x3, swap)
	feCSwap(&z2, &z3, swap)

	feInvert(&z2, &z2)
	feMul(&x2, &x2, &z2)
	feToBytes(out, &x2)
}
