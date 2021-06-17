package kyber

import (
	"golang.org/x/crypto/sha3"
)

//Poly represents a polynomial of deg n with coefs in [0, Q)
type Poly [n]int16

func add(a, b Poly) Poly {
	var c Poly
	for i := 0; i < n; i++ {
		c[i] = a[i] + b[i]
	}
	return c
}

//sub substracts b from a without normalization
func sub(a, b Poly) Poly {
	var c Poly
	for i := 0; i < n; i++ {
		c[i] = a[i] - b[i]
	}
	return c
}

//reduce calls barretReduce on each coef
func (p *Poly) reduce() {
	for i := 0; i < n; i++ {
		p[i] = barretReduce(p[i])
	}
}

//freeze calls Freeze on each coef
func (p *Poly) freeze() {
	for i := 0; i < n; i++ {
		p[i] = freeze(p[i])
	}
}

//rej fills a with coefs in [0, Q) generated with buf using rejection sampling
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

//polyUniform samples a polynomial with coefs in [0, Q]
func polyUniform(rho []byte, nonce []byte) Poly {
	var outbuf [shake128Rate]byte

	state := sha3.NewShake128()
	state.Write(rho[:])
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

//polyGetNoise samples a polynomial with coefs in [Q-eta, Q+eta]
func polyGetNoise(eta int, seed []byte, nonce byte) Poly {
	outbuf := make([]byte, eta*n/4)
	state := sha3.NewShake256()
	state.Write(seed[:])
	state.Write([]byte{nonce})
	state.Read(outbuf[:])
	var p Poly
	if eta == 3 {
		p = polyCBD3(outbuf)
	}
	if eta == 2 {
		p = polyCBD2(outbuf)
	}
	return p
}

//polyCBD2 samples a poly using a centered binomial distribution
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

//polyCBD3 samples a poly using a centered binomial distribution
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

//polyBaseMul multiplies two polynomials
func polyBaseMul(a, b Poly) Poly {
	var r Poly
	for i := 0; i < n/4; i++ {
		copy(r[4*i:4*i+2], basemul(a[4*i:4*i+2], b[4*i:4*i+2], zetas[64+i]))
		copy(r[4*i+2:4*i+4], basemul(a[4*i+2:4*i+4], b[4*i+2:4*i+4], -zetas[64+i]))
	}
	return r
}

//tomont converts a poly to its montgomery representation
func (p *Poly) toMont() {
	var f int16 = int16((uint64(1) << 32) % uint64(q))
	for i := 0; i < n; i++ {
		p[i] = montgomeryReduce(int32(p[i]) * int32(f))
	}
}

//polyFromMsg converts a msg into polynomial representation
func polyFromMsg(msg []byte) Poly {
	var p Poly
	for i := 0; i < n/8; i++ {
		for j := 0; j < 8; j++ {
			mask := -int16((msg[i] >> j) & 1)
			p[8*i+j] = mask & int16((q+1)/2)
		}
	}
	return p
}

//polyToMsg converts a polynomial to a byte array
func polyToMsg(p Poly) []byte {
	msg := make([]byte, 32)
	var t uint16
	var tmp byte
	p.reduce()
	for i := 0; i < n/8; i++ {
		tmp = 0
		for j := 0; j < 8; j++ {
			t = (((uint16(p[8*i+j]) << 1) + uint16(q/2)) / uint16(q)) & 1
			tmp |= byte(t << j)
		}
		msg[i] = tmp
	}
	return msg
}

//compress packs a polynomial into a byte array using d bits per coefficient
func (p *Poly) compress(d int) []byte {
	c := make([]byte, n*d/8)
	switch d {

	case 3:
		var t [8]uint16
		id := 0
		for i := 0; i < n/8; i++ {
			for j := 0; j < 8; j++ {
				t[j] = uint16(((uint32(p[8*i+j])<<3)+uint32(q)/2)/
					uint32(q)) & ((1 << 3) - 1)
			}
			c[id] = byte(t[0]) | byte(t[1]<<3) | byte(t[2]<<6)
			c[id+1] = byte(t[2]>>2) | byte(t[3]<<1) | byte(t[4]<<4) | byte(t[5]<<7)
			c[id+2] = byte(t[5]>>1) | byte(t[6]<<2) | byte(t[7]<<5)
			id += 3
		}

	case 4:
		var t [8]uint16
		id := 0
		for i := 0; i < n/8; i++ {
			for j := 0; j < 8; j++ {
				t[j] = uint16(((uint32(p[8*i+j])<<4)+uint32(q)/2)/
					uint32(q)) & ((1 << 4) - 1)
			}
			c[id] = byte(t[0]) | byte(t[1]<<4)
			c[id+1] = byte(t[2]) | byte(t[3]<<4)
			c[id+2] = byte(t[4]) | byte(t[5]<<4)
			c[id+3] = byte(t[6]) | byte(t[7]<<4)
			id += 4
		}

	case 5:
		var t [8]uint16
		id := 0
		for i := 0; i < n/8; i++ {
			for j := 0; j < 8; j++ {
				t[j] = uint16(((uint32(p[8*i+j])<<5)+uint32(q)/2)/
					uint32(q)) & ((1 << 5) - 1)
			}
			c[id] = byte(t[0]) | byte(t[1]<<5)
			c[id+1] = byte(t[1]>>3) | byte(t[2]<<2) | byte(t[3]<<7)
			c[id+2] = byte(t[3]>>1) | byte(t[4]<<4)
			c[id+3] = byte(t[4]>>4) | byte(t[5]<<1) | byte(t[6]<<6)
			c[id+4] = byte(t[6]>>2) | byte(t[7]<<3)
			id += 5
		}

	case 6:
		var t [4]uint16
		id := 0
		for i := 0; i < n/4; i++ {
			for j := 0; j < 4; j++ {
				t[j] = uint16(((uint32(p[4*i+j])<<6)+uint32(q)/2)/
					uint32(q)) & ((1 << 6) - 1)
			}
			c[id] = byte(t[0]) | byte(t[1]<<6)
			c[id+1] = byte(t[1]>>2) | byte(t[2]<<4)
			c[id+2] = byte(t[2]>>2) | byte(t[3]<<2)
			id += 3
		}

	case 10:
		var t [4]uint16
		id := 0
		for i := 0; i < n/4; i++ {
			for j := 0; j < 4; j++ {
				t[j] = uint16(((uint32(p[4*i+j])<<10)+uint32(q)/2)/
					uint32(q)) & ((1 << 10) - 1)
			}
			c[id] = byte(t[0])
			c[id+1] = byte(t[0]>>8) | byte(t[1]<<2)
			c[id+2] = byte(t[1]>>6) | byte(t[2]<<4)
			c[id+3] = byte(t[2]>>4) | byte(t[3]<<6)
			c[id+4] = byte(t[3] >> 2)
			id += 5
		}
	case 11:
		var t [8]uint16
		id := 0
		for i := 0; i < n/8; i++ {
			for j := 0; j < 8; j++ {
				t[j] = uint16(((uint32(p[8*i+j])<<11)+uint32(q)/2)/
					uint32(q)) & ((1 << 11) - 1)
			}
			c[id] = byte(t[0])
			c[id+1] = byte(t[0]>>8) | byte(t[1]<<3)
			c[id+2] = byte(t[1]>>5) | byte(t[2]<<6)
			c[id+3] = byte(t[2] >> 2)
			c[id+4] = byte(t[2]>>10) | byte(t[3]<<1)
			c[id+5] = byte(t[3]>>7) | byte(t[4]<<4)
			c[id+6] = byte(t[4]>>4) | byte(t[5]<<7)
			c[id+7] = byte(t[5] >> 1)
			c[id+8] = byte(t[5]>>9) | byte(t[6]<<2)
			c[id+9] = byte(t[6]>>6) | byte(t[7]<<5)
			c[id+10] = byte(t[7] >> 3)
			id += 11
		}
	default:
		panic("bad d value")
	}
	return c[:]
}

//decompressPoly creates a polynomial based on a compressed array, using d bits per coefficients
func decompressPoly(c []byte, d int) Poly {
	var p Poly
	switch d {
	case 3:
		var t [8]uint16
		id := 0
		for i := 0; i < n/8; i++ {
			t[0] = uint16(c[id])
			t[1] = uint16(c[id]) >> 3
			t[2] = (uint16(c[id]) >> 6) | (uint16(c[id+1]) << 2)
			t[3] = uint16(c[id+1]) >> 1
			t[4] = uint16(c[id+1]) >> 4
			t[5] = (uint16(c[id+1]) >> 7) | (uint16(c[id+2]) << 1)
			t[6] = uint16(c[id+2]) >> 2
			t[7] = uint16(c[id+2]) >> 5

			for j := 0; j < 8; j++ {
				p[8*i+j] = int16(((1 << 2) +
					uint32(t[j]&((1<<3)-1))*uint32(q)) >> 3)
			}
			id += 3
		}
	case 4:
		for i := 0; i < n/2; i++ {
			p[2*i] = int16(((1 << 3) +
				uint32(c[i]&15)*uint32(q)) >> 4)
			p[2*i+1] = int16(((1 << 3) +
				uint32(c[i]>>4)*uint32(q)) >> 4)
		}
	case 5:
		var t [8]uint16
		id := 0
		for i := 0; i < n/8; i++ {
			t[0] = uint16(c[id])
			t[1] = (uint16(c[id]) >> 5) | (uint16(c[id+1] << 3))
			t[2] = uint16(c[id+1]) >> 2
			t[3] = (uint16(c[id+1]) >> 7) | (uint16(c[id+2] << 1))
			t[4] = (uint16(c[id+2]) >> 4) | (uint16(c[id+3] << 4))
			t[5] = uint16(c[id+3]) >> 1
			t[6] = (uint16(c[id+3]) >> 6) | (uint16(c[id+4] << 2))
			t[7] = uint16(c[id+4]) >> 3

			for j := 0; j < 8; j++ {
				p[8*i+j] = int16(((1 << 4) +
					uint32(t[j]&((1<<5)-1))*uint32(q)) >> 5)
			}
			id += 5
		}

	case 6:
		var t [4]uint16
		id := 0
		for i := 0; i < n/4; i++ {
			t[0] = uint16(c[id])
			t[1] = (uint16(c[id]) >> 6) | (uint16(c[id+1] << 2))
			t[2] = (uint16(c[id+1]) >> 4) | (uint16(c[id+2]) << 4)
			t[3] = uint16(c[id+2]) >> 2

			for j := 0; j < 4; j++ {
				p[4*i+j] = int16(((1 << 5) +
					uint32(t[j]&((1<<6)-1))*uint32(q)) >> 6)
			}
			id += 3
		}

	case 10:
		var t [4]uint16
		id := 0
		for i := 0; i < n/4; i++ {
			t[0] = uint16(c[id]) | (uint16(c[id+1]) << 8)
			t[1] = (uint16(c[id+1]) >> 2) | (uint16(c[id+2]) << 6)
			t[2] = (uint16(c[id+2]) >> 4) | (uint16(c[id+3]) << 4)
			t[3] = (uint16(c[id+3]) >> 6) | (uint16(c[id+4]) << 2)

			for j := 0; j < 4; j++ {
				p[4*i+j] = int16(((1 << 9) +
					uint32(t[j]&((1<<10)-1))*uint32(q)) >> 10)
			}

			id += 5
		}
	case 11:
		var t [8]uint16
		id := 0
		for i := 0; i < n/8; i++ {
			t[0] = uint16(c[id]) | (uint16(c[id+1]) << 8)
			t[1] = (uint16(c[id+1]) >> 3) | (uint16(c[id+2]) << 5)
			t[2] = (uint16(c[id+2]) >> 6) | (uint16(c[id+3]) << 2) | (uint16(c[id+4]) << 10)
			t[3] = (uint16(c[id+4]) >> 1) | (uint16(c[id+5]) << 7)
			t[4] = (uint16(c[id+5]) >> 4) | (uint16(c[id+6]) << 4)
			t[5] = (uint16(c[id+6]) >> 7) | (uint16(c[id+7]) << 1) | (uint16(c[id+8]) << 9)
			t[6] = (uint16(c[id+8]) >> 2) | (uint16(c[id+9]) << 6)
			t[7] = (uint16(c[id+9]) >> 5) | (uint16(c[id+10]) << 3)

			for j := 0; j < 8; j++ {
				p[8*i+j] = int16(((1 << 10) +
					uint32(t[j]&((1<<11)-1))*uint32(q)) >> 11)
			}

			id += 11
		}
	default:
		panic("bad d value")
	}
	return p
}
