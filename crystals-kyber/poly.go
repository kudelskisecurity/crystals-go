package kyber

import (
	"golang.org/x/crypto/sha3"
)

// Poly represents a polynomial of deg n with coefs in [0, Q).
type Poly [n]int16

func add(a, b Poly) Poly {
	var c Poly
	for i := 0; i < n; i++ {
		c[i] = a[i] + b[i]
	}
	return c
}

func sub(a, b Poly) Poly {
	var c Poly
	for i := 0; i < n; i++ {
		c[i] = a[i] - b[i]
	}
	return c
}

func (p *Poly) reduce() {
	for i := 0; i < n; i++ {
		p[i] = barretReduce(p[i])
	}
}

func (p *Poly) freeze() {
	for i := 0; i < n; i++ {
		p[i] = freeze(p[i])
	}
}

func rej(a []int16, buf []byte) int {
	ctr, buflen, alen := 0, len(buf), len(a)
	for pos := 0; pos+3 <= buflen && ctr < alen; pos += 3 {
		val0 := (uint16(buf[pos]) | (uint16(buf[pos+1]) << 8)) & 0xfff
		val1 := (uint16(buf[pos+1]>>4) | (uint16(buf[pos+2]) << 4)) & 0xfff
		if val0 < uint16(q) {
			a[ctr] = int16(val0)
			ctr++
		}
		if val1 < uint16(q) && ctr != alen {
			a[ctr] = int16(val1)
			ctr++
		}
	}
	return ctr
}

func polyUniform(rho []byte, nonce []byte) Poly {
	var outbuf [shake128Rate]byte

	state := sha3.NewShake128()
	state.Write(rho)
	state.Write(nonce)
	state.Read(outbuf[:])

	var a Poly
	ctr := rej(a[:], outbuf[:])
	for ctr < n {
		state.Read(outbuf[:shake128Rate])
		ctr += rej(a[ctr:], outbuf[:shake128Rate])
	}
	return a
}

func polyGetNoise(eta int, seed []byte, nonce byte) Poly {
	outbuf := make([]byte, eta*n/4)
	state := sha3.NewShake256()
	state.Write(seed)
	state.Write([]byte{nonce})
	state.Read(outbuf)
	var p Poly
	if eta == 3 {
		p = polyCBD3(outbuf)
	}
	if eta == 2 {
		p = polyCBD2(outbuf)
	}
	return p
}

func polyCBD2(outbuf []byte) Poly {
	var t, d uint32
	var a, b int16
	var p Poly

	for i := 0; i < n/8; i++ {
		t = load32LE(outbuf[4*i:])
		d = t & 0x55555555
		d += (t >> 1) & 0x55555555

		for j := 0; j < 8; j++ {
			a = int16((d >> (4*j + 0)) & 0x3)
			b = int16((d >> (4*j + 2)) & 0x3)
			p[8*i+j] = a - b
		}
	}
	return p
}

func polyCBD3(outbuf []byte) Poly {
	var t, d uint32
	var a, b int16
	var p Poly

	for i := 0; i < n/4; i++ {
		t = load24LE(outbuf[3*i:])
		d = t & 0x00249249
		d += (t >> 1) & 0x00249249
		d += (t >> 2) & 0x00249249

		for j := 0; j < 4; j++ {
			a = int16((d >> (6*j + 0)) & 0x7)
			b = int16((d >> (6*j + 3)) & 0x7)
			p[4*i+j] = a - b
		}
	}
	return p
}

func polyBaseMul(a, b Poly) Poly {
	var r Poly
	for i := 0; i < n/4; i++ {
		copy(r[4*i:4*i+2], basemul(a[4*i:4*i+2], b[4*i:4*i+2], zetas[64+i]))
		copy(r[4*i+2:4*i+4], basemul(a[4*i+2:4*i+4], b[4*i+2:4*i+4], -zetas[64+i]))
	}
	return r
}

func (p *Poly) toMont() {
	var f int16 = int16((uint64(1) << 32) % uint64(q))
	for i := 0; i < n; i++ {
		p[i] = montgomeryReduce(int32(p[i]) * int32(f))
	}
}
