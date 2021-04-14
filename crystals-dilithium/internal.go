package dilithium

import (
	"golang.org/x/crypto/sha3"
)

//Reduce32 maps a to the [-Q, Q] domain
func reduce32(a int32) int32 {
	t := (a + (1 << 22)) >> 23
	t = a - t*q
	return t
}

func addQ(a int32) int32 {
	a += (a >> 31) & q
	return a
}

//Freeze maps a to the [0, Q] domain
func freeze(a int32) int32 {
	a = reduce32(a)
	a = addQ(a)
	return a
}

//Power2Round returns a1 and a0+Q such that a = a1*2^D+a0
func power2Round(a int32) (int32, int32) {
	a1 := (a + (1 << (d - 1)) - 1) >> d
	a0 := a - (a1 << d)
	return a1, a0
}

//Decompose returns a1 and a0+Q such that a = a1*alpha + a0
func decompose(a int32, GAMMA2 int32) (int32, int32) {
	a1 := (a + 127) >> 7

	if GAMMA2 == (q-1)/32 {
		a1 = (a1*1025 + (1 << 21)) >> 22
		a1 &= 15
	}
	if GAMMA2 == (q-1)/88 {
		a1 = (a1*11275 + (1 << 23)) >> 24
		a1 ^= ((43 - a1) >> 31) & a1
	}
	a0 := a - a1*2*GAMMA2
	a0 -= (((q-1)/2 - a0) >> 31) & q
	return a1, a0
}

//MakeHint returns 1 iff a0 overflows a1
func makeHint(a1, a0 int32, GAMMA2 int32) int32 {
	if a0 > GAMMA2 || a0 < -GAMMA2 || (a0 == -GAMMA2 && a1 != 0) {
		return 1
	}
	return 0
}

//UseHint computes the real HighBits of a
func useHint(a int32, hint int32, GAMMA2 int32) int32 {
	a1, a0 := decompose(a, GAMMA2)
	if hint == 0 {
		return a1
	}
	if a0 > 0 {
		if GAMMA2 == (q-1)/32 {
			return (a1 + 1) & 15
		} //GAMMA2 == (q-1)/88
		if a1 == 43 {
			return 0
		}
		return a1 + 1
	}
	if GAMMA2 == (q-1)/32 {
		return (a1 - 1) & 15
	} //GAMMA2 == (q-1)/88
	if a1 == 0 {
		return 43
	}
	return a1 - 1
}

//Mat is used to hold A
type Mat []Vec

//ExpandSeed uses rho to create a KxL matrix of uniform polynomials (A)
func expandSeed(rho [SEEDBYTES]byte, K, L int) Mat {
	A := make(Mat, K)
	for i := 0; i < K; i++ {
		A[i] = make(Vec, L)
		for j := 0; j < L; j++ {
			A[i][j] = polyUniform(rho, uint16((i<<8)+j))
		}
	}
	return A
}

//Challenge creates a Poly with exactly 60 1's and the rest 0's.
func challenge(hc []byte, T int) Poly {
	var c Poly
	var outbuf [shake256Rate]byte
	state := sha3.NewShake256()
	state.Write(hc[:])
	state.Read(outbuf[:])

	signs := uint64(0)
	for i := uint(0); i < 8; i++ {
		signs |= uint64(outbuf[i]) << (8 * i)
	}
	pos := 8
	b := 0
	for i := n - T; i < n; i++ {
		for {
			if pos >= shake256Rate {
				state.Read(outbuf[:])
				pos = 0
			}
			b = int(outbuf[pos])
			pos++
			if b <= i {
				break
			}
		}
		c[i] = c[b]
		c[b] = 1 - 2*int32((signs&1))
		signs >>= 1
	}

	return c
}
