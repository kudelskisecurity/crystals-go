package dilithium

import (
	"golang.org/x/crypto/sha3"
)

// Poly represents a polynomial of deg n with coefs in [0, Q).
type Poly [n]int32

// freeze calls Freeze on each coef.
func (p *Poly) freeze() {
	for i := 0; i < n; i++ {
		p[i] = freeze(p[i])
	}
}

// reduce calls Reduce32 on each coef.
func (p *Poly) reduce() {
	for i := 0; i < n; i++ {
		p[i] = reduce32(p[i])
	}
}

// add two Poly without normalization.
func add(a, b Poly) Poly {
	var c Poly
	for i := 0; i < n; i++ {
		c[i] = a[i] + b[i]
	}
	return c
}

// addQ calls addQ on eah coefficient.
func (p *Poly) addQ() {
	for i := 0; i < n; i++ {
		p[i] = addQ(p[i])
	}
}

// sub subtracts b from a without normalization.
func sub(a, b Poly) Poly {
	var c Poly
	for i := 0; i < n; i++ {
		c[i] = a[i] - b[i]
	}
	return c
}

// shift mult all coefs by 2^d.
func (p *Poly) shift() {
	for i := 0; i < n; i++ {
		p[i] <<= d
	}
}

// montMul performs pointwise mutl (to be used with nTT Poly).
// Refers to poly_pointwise_montgomery in ref implementation.
func montMul(a, b Poly) Poly {
	var c Poly
	for i := 0; i < n; i++ {
		c[i] = montgomeryReduce(int64(a[i]) * int64(b[i]))
	}
	return c
}

// isBelow returns true if all coefs are in [Q-b, Q+b].
func (p Poly) isBelow(bound int32) bool {
	res := true
	if bound > (q-1)/8 {
		return false
	}
	for i := 0; i < n; i++ {
		t := p[i] >> 31
		t = p[i] - (t & 2 * p[i])
		res = res && (t < bound)
	}
	return res
}

// rej fills a with coefs in [0, Q) generated with buf using rejection sampling.
func rej(a []int32, buf []byte) int {
	ctr, buflen, alen := 0, len(buf), len(a)
	for pos := 0; pos+3 < buflen && ctr < alen; pos += 3 {
		var t uint32
		t = uint32(buf[pos])
		t |= uint32(buf[pos+1]) << 8
		t |= uint32(buf[pos+2]) << 16
		t &= 0x7fffff

		if t < q {
			a[ctr] = int32(t)
			ctr++
		}
	}
	return ctr
}

// polyUniform samples a polynomial with coefs in [0, Q].
func polyUniform(seed [SEEDBYTES]byte, nonce uint16) Poly {
	var a Poly
	var outbuf [5 * shake128Rate]byte

	state := sha3.NewShake128()
	state.Write(seed[:])
	state.Write([]byte{byte(nonce), byte(nonce >> 8)})
	state.Read(outbuf[:])

	ctr := rej(a[:], outbuf[:])
	for ctr < n {
		off := 5 * shake128Rate % 3
		for i := 0; i < off; i++ {
			outbuf[i] = outbuf[5*shake128Rate-off+i]
		}
		state.Read(outbuf[off:])
		ctr += rej(a[ctr:], outbuf[:])
	}
	return a
}

// rejEta fills a with coefs in [0, eta) generated with buf using rejection sampling.
func rejEta(a []int32, buf []byte, eta int32) int {
	ctr, buflen, alen := 0, len(buf), len(a)
	for pos := 0; pos < buflen && ctr < alen; pos++ {
		var t0, t1 int32
		t0 = int32(buf[pos]) & 0x0F
		t1 = int32(buf[pos]) >> 4
		if eta == 2 {
			if t0 < 15 {
				t0 -= (205 * t0 >> 10) * 5
				a[ctr] = eta - t0
				ctr++
			}
			if t1 < 15 && ctr < alen {
				t1 -= (205 * t1 >> 10) * 5
				a[ctr] = eta - t1
				ctr++
			}
		}
		if eta == 4 {
			if t0 < 9 {
				a[ctr] = eta - t0
				ctr++
			}
			if t1 < 9 && ctr < alen {
				a[ctr] = eta - t1
				ctr++
			}
		}
	}
	return ctr
}

// polyUniformEta samples a polynomial with coefs in [Q-eta, Q+eta].
func polyUniformEta(seed [2 * SEEDBYTES]byte, nonce uint16, eta int32) Poly {
	var a Poly
	blocks := 1 // eta == 2
	if eta == 4 {
		blocks = 2
	}
	outbuf := make([]byte, shake256Rate*blocks)

	state := sha3.NewShake256()
	state.Write(seed[:])
	state.Write([]byte{uint8(nonce), uint8(nonce >> 8)})
	state.Read(outbuf)

	ctr := rejEta(a[:], outbuf, eta)
	for ctr < n {
		sub := outbuf[:shake256Rate]
		state.Read(sub)
		ctr += rejEta(a[ctr:], sub, eta)
	}
	return a
}

// polyUniformGamma1 samples a polynomial with coefs in [Q-gamma1, Q+gamma1].
func polyUniformGamma1(rhoP [2 * SEEDBYTES]byte, nonce uint16, gamma1 int32) Poly {
	var outbuf [shake256Rate * 5]byte
	state := sha3.NewShake256()
	state.Write(rhoP[:])
	state.Write([]byte{uint8(nonce), uint8(nonce >> 8)})
	state.Read(outbuf[:])
	POLYSIZE := 640
	if gamma1 == (q-1)/88 {
		POLYSIZE = 576
	}
	a := unpackZ(outbuf[:], 1, POLYSIZE, gamma1)
	return a[0]
}

// equal returns true if b is equal to a (all coefs are).
func (p Poly) equal(b Poly) bool {
	res := true
	for i := 0; i < n; i++ {
		if p[i] != b[i] {
			res = false
		}
	}
	return res
}

// polyPower2Round calls power2Round on each coef.
func polyPower2Round(p Poly) (Poly, Poly) {
	var p1, p0 Poly
	for j := 0; j < n; j++ {
		p1[j], p0[j] = power2Round(p[j])
	}
	return p1, p0
}

// polyDecompose calls decompose on each coef.
func polyDecompose(p Poly, gamma2 int32) (Poly, Poly) {
	var p1, p0 Poly
	for j := 0; j < n; j++ {
		p1[j], p0[j] = decompose(p[j], gamma2)
	}
	return p1, p0
}

// polyUseHint uses the hint to correct the hight bits of u.
func polyUseHint(u, h Poly, gamma2 int32) Poly {
	var p Poly
	for j := 0; j < n; j++ {
		p[j] = useHint(u[j], h[j], gamma2)
	}
	return p
}

// tomont converts a poly to its montgomery representation.
func (p *Poly) tomont() {
	for i := 0; i < n; i++ {
		p[i] = montgomeryReduce(int64(p[i]))
	}
}

// fromMont converts back to [0, Q].
func (p *Poly) fromMont() {
	inv := uint64(8265825)
	for i := uint(0); i < n; i++ {
		p[i] = int32((uint64(p[i]) * inv) % q)
	}
}
