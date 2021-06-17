package dilithium

import (
	"golang.org/x/crypto/sha3"
)

//reduce32 maps a to the [-Q, Q] domain
func reduce32(a int32) int32 {
	t := (a + (1 << 22)) >> 23
	t = a - t*q
	return t
}

//addQ maps a to a "positive" representation in constant time
func addQ(a int32) int32 {
	a += (a >> 31) & q
	return a
}

//freeze maps a to the [0, Q] domain
func freeze(a int32) int32 {
	a = reduce32(a)
	a = addQ(a)
	return a
}

//power2Round returns a1 and a0+Q such that a = a1*2^D+a0
func power2Round(a int32) (int32, int32) {
	a1 := (a + (1 << (d - 1)) - 1) >> d
	a0 := a - (a1 << d)
	return a1, a0
}

//decompose returns a1 and a0+Q such that a = a1*alpha + a0
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

//makeHint returns 1 iff a0 overflows a1
func makeHint(a1, a0 int32, GAMMA2 int32) int32 {
	if a0 > GAMMA2 || a0 < -GAMMA2 || (a0 == -GAMMA2 && a1 != 0) {
		return 1
	}
	return 0
}

//useHint computes the real high bits of a
func useHint(a int32, hint int32, GAMMA2 int32) int32 {
	a1, a0 := decompose(a, GAMMA2)
	if hint == 0 {
		return a1
	}
	if a0 > 0 {
		if GAMMA2 == (q-1)/32 {
			return (a1 + 1) & 15
		}
		if a1 == 43 {
			return 0
		}
		return a1 + 1
	}
	if GAMMA2 == (q-1)/32 {
		return (a1 - 1) & 15
	}
	if a1 == 0 {
		return 43
	}
	return a1 - 1
}

//Mat is used to hold the matrix A
type Mat []Vec

//expandSeed uses rho to create A, a KxL matrix of uniform polynomials
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

//challenge creates a Poly with exactly T 1's and the rest 0's
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

//Computes the integer in {-(q-1)/2,...,(q-1)/2} congruent to a modulo q
func barretReduce(a int32) int32 {
	v := int32(((uint32(1) << 26) + uint32(q/2)) / uint32(q))
	t := int32(v) * int32(a) >> 26
	t *= int32(q)
	return a - t
}

//montgomeryReduce is used to reduce a montgomery coefficient  [0, RQ]
func montgomeryReduce(a int64) int32 {
	t := int32(a * qInv)
	t = int32((a - int64(t)*q) >> 32)
	return t
}
