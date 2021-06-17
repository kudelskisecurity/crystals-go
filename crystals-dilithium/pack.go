package dilithium

// packT1 returns the byte representation of v.
func packT1(v Vec, k int) []byte {
	r := make([]byte, k*polySizeT1)

	for j := 0; j < k; j++ {
		for i := 0; i < n/4; i++ {
			r[j*polySizeT1+5*i+0] = byte(v[j][4*i+0] >> 0)
			r[j*polySizeT1+5*i+1] = byte(v[j][4*i+0]>>8) | byte(v[j][4*i+1]<<2)
			r[j*polySizeT1+5*i+2] = byte(v[j][4*i+1]>>6) | byte(v[j][4*i+2]<<4)
			r[j*polySizeT1+5*i+3] = byte(v[j][4*i+2]>>4) | byte(v[j][4*i+3]<<6)
			r[j*polySizeT1+5*i+4] = byte(v[j][4*i+3] >> 2)
		}
	}
	return r
}

// pnpackT1 reverses the packing operation.
func unpackT1(r []byte, k int) Vec {
	v := make(Vec, k)
	for j := 0; j < k; j++ {
		for i := 0; i < n/4; i++ {
			v[j][4*i+0] = (int32(r[j*polySizeT1+5*i+0]) >> 0) | (int32(r[j*polySizeT1+5*i+1])<<8)&0x3FF
			v[j][4*i+1] = (int32(r[j*polySizeT1+5*i+1]) >> 2) | (int32(r[j*polySizeT1+5*i+2])<<6)&0x3FF
			v[j][4*i+2] = (int32(r[j*polySizeT1+5*i+2]) >> 4) | (int32(r[j*polySizeT1+5*i+3])<<4)&0x3FF
			v[j][4*i+3] = (int32(r[j*polySizeT1+5*i+3]) >> 6) | (int32(r[j*polySizeT1+5*i+4])<<2)&0x3FF
		}
	}
	return v
}

// packT0 packs t0.
func packT0(v Vec, k int) []byte {
	r := make([]byte, k*polySizeT0)
	t := make([]uint32, 8)
	for j := 0; j < k; j++ {
		for i := 0; i < n/8; i++ {
			t[0] = uint32((1 << (d - 1)) - v[j][8*i+0])
			t[1] = uint32((1 << (d - 1)) - v[j][8*i+1])
			t[2] = uint32((1 << (d - 1)) - v[j][8*i+2])
			t[3] = uint32((1 << (d - 1)) - v[j][8*i+3])
			t[4] = uint32((1 << (d - 1)) - v[j][8*i+4])
			t[5] = uint32((1 << (d - 1)) - v[j][8*i+5])
			t[6] = uint32((1 << (d - 1)) - v[j][8*i+6])
			t[7] = uint32((1 << (d - 1)) - v[j][8*i+7])

			r[j*polySizeT0+13*i+0] = byte(t[0])
			r[j*polySizeT0+13*i+1] = byte(t[0] >> 8)
			r[j*polySizeT0+13*i+1] |= byte(t[1] << 5)
			r[j*polySizeT0+13*i+2] = byte(t[1] >> 3)
			r[j*polySizeT0+13*i+3] = byte(t[1] >> 11)
			r[j*polySizeT0+13*i+3] |= byte(t[2] << 2)
			r[j*polySizeT0+13*i+4] = byte(t[2] >> 6)
			r[j*polySizeT0+13*i+4] |= byte(t[3] << 7)
			r[j*polySizeT0+13*i+5] = byte(t[3] >> 1)
			r[j*polySizeT0+13*i+6] = byte(t[3] >> 9)
			r[j*polySizeT0+13*i+6] |= byte(t[4] << 4)
			r[j*polySizeT0+13*i+7] = byte(t[4] >> 4)
			r[j*polySizeT0+13*i+8] = byte(t[4] >> 12)
			r[j*polySizeT0+13*i+8] |= byte(t[5] << 1)
			r[j*polySizeT0+13*i+9] = byte(t[5] >> 7)
			r[j*polySizeT0+13*i+9] |= byte(t[6] << 6)
			r[j*polySizeT0+13*i+10] = byte(t[6] >> 2)
			r[j*polySizeT0+13*i+11] = byte(t[6] >> 10)
			r[j*polySizeT0+13*i+11] |= byte(t[7] << 3)
			r[j*polySizeT0+13*i+12] = byte(t[7] >> 5)
		}
	}
	return r
}

// unpackT0 reverses the packing operation.
func unpackT0(a []byte, k int) Vec {
	v := make(Vec, k)
	for j := 0; j < k; j++ {
		for i := 0; i < n/8; i++ {
			v[j][8*i+0] = int32(uint32(a[j*polySizeT0+13*i+0])|uint32(a[j*polySizeT0+13*i+1])<<8) & 0x1FFF
			v[j][8*i+1] = int32(uint32(a[j*polySizeT0+13*i+1])>>5|uint32(a[j*polySizeT0+13*i+2])<<3|uint32(a[j*polySizeT0+13*i+3])<<11) & 0x1FFF
			v[j][8*i+2] = int32(uint32(a[j*polySizeT0+13*i+3])>>2|uint32(a[j*polySizeT0+13*i+4])<<6) & 0x1FFF
			v[j][8*i+3] = int32(uint32(a[j*polySizeT0+13*i+4])>>7|uint32(a[j*polySizeT0+13*i+5])<<1|uint32(a[j*polySizeT0+13*i+6])<<9) & 0x1FFF
			v[j][8*i+4] = int32(uint32(a[j*polySizeT0+13*i+6]>>4)|uint32(a[j*polySizeT0+13*i+7])<<4|uint32(a[j*polySizeT0+13*i+8])<<12) & 0x1FFF
			v[j][8*i+5] = int32(uint32(a[j*polySizeT0+13*i+8])>>1|uint32(a[j*polySizeT0+13*i+9])<<7) & 0x1FFF
			v[j][8*i+6] = int32(uint32(a[j*polySizeT0+13*i+9])>>6|uint32(a[j*polySizeT0+13*i+10])<<2|uint32(a[j*polySizeT0+13*i+11])<<10) & 0x1FFF
			v[j][8*i+7] = int32(uint32(a[j*polySizeT0+13*i+11])>>3|uint32(a[j*polySizeT0+13*i+12])<<5) & 0x1FFF

			v[j][8*i+0] = (1 << (d - 1)) - v[j][8*i+0]
			v[j][8*i+1] = (1 << (d - 1)) - v[j][8*i+1]
			v[j][8*i+2] = (1 << (d - 1)) - v[j][8*i+2]
			v[j][8*i+3] = (1 << (d - 1)) - v[j][8*i+3]
			v[j][8*i+4] = (1 << (d - 1)) - v[j][8*i+4]
			v[j][8*i+5] = (1 << (d - 1)) - v[j][8*i+5]
			v[j][8*i+6] = (1 << (d - 1)) - v[j][8*i+6]
			v[j][8*i+7] = (1 << (d - 1)) - v[j][8*i+7]
		}
	}
	return v
}

// packW1 packs a w1 poly.
func packW1(v Vec, l, polySizeW1 int, gamma2 int32) []byte {
	r := make([]byte, l*polySizeW1)
	if gamma2 == (q-1)/88 {
		for j := 0; j < l; j++ {
			for i := 0; i < n/4; i++ {
				r[j*polySizeW1+3*i+0] = byte(v[j][4*i+0] | v[j][4*i+1]<<6)
				r[j*polySizeW1+3*i+1] = byte(v[j][4*i+1]>>2 | v[j][4*i+2]<<4)
				r[j*polySizeW1+3*i+2] = byte(v[j][4*i+2]>>4 | v[j][4*i+3]<<2)
			}
		}
		return r
	}
	for j := 0; j < l; j++ {
		for i := 0; i < n/2; i++ {
			r[j*polySizeW1+i] = byte(v[j][2*i+0] | (v[j][2*i+1] << 4))
		}
	}
	return r
}

// packS packs a S vec.
func packS(v Vec, l, polysizes int, eta int32) []byte {
	r := make([]byte, l*polysizes)
	if eta == 4 {
		t := make([]byte, 2)
		for j := 0; j < l; j++ {
			for i := 0; i < n/2; i++ {
				t[0] = byte(eta - v[j][2*i+0])
				t[1] = byte(eta - v[j][2*i+1])
				r[j*polysizes+i] = t[0] | (t[1] << 4)
			}
		}
	}
	if eta == 2 {
		t := make([]byte, 8)
		for j := 0; j < l; j++ {
			for i := 0; i < n/8; i++ {
				t[0] = byte(eta - v[j][8*i+0])
				t[1] = byte(eta - v[j][8*i+1])
				t[2] = byte(eta - v[j][8*i+2])
				t[3] = byte(eta - v[j][8*i+3])
				t[4] = byte(eta - v[j][8*i+4])
				t[5] = byte(eta - v[j][8*i+5])
				t[6] = byte(eta - v[j][8*i+6])
				t[7] = byte(eta - v[j][8*i+7])

				r[j*polysizes+3*i+0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6)
				r[j*polysizes+3*i+1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7)
				r[j*polysizes+3*i+2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5)
			}
		}
	}
	return r
}

// unpackS reverses the packing of an S vec.
func unpackS(r []byte, l, polysizes int, eta int32) Vec {
	v := make(Vec, l)
	if eta == 4 {
		for j := 0; j < l; j++ {
			for i := 0; i < n/2; i++ {
				v[j][2*i+0] = int32(uint32(r[j*polysizes+i]) & 0x0F)
				v[j][2*i+1] = int32(uint32(r[j*polysizes+i]) >> 4)
				v[j][2*i+0] = eta - v[j][2*i+0]
				v[j][2*i+1] = eta - v[j][2*i+1]
			}
		}
	}
	if eta == 2 {
		for j := 0; j < l; j++ {
			for i := 0; i < n/8; i++ {
				v[j][8*i+0] = eta - int32(r[j*polysizes+3*i])&7
				v[j][8*i+1] = eta - int32(r[j*polysizes+3*i])>>3&7
				v[j][8*i+2] = eta - (int32(r[j*polysizes+3*i])>>6 | (int32(r[j*polysizes+3*i+1])<<2)&7)
				v[j][8*i+3] = eta - (int32(r[j*polysizes+3*i+1])>>1)&7
				v[j][8*i+4] = eta - (int32(r[j*polysizes+3*i+1])>>4)&7
				v[j][8*i+5] = eta - (int32(r[j*polysizes+3*i+1])>>7 | (int32(r[j*polysizes+3*i+2])<<1)&7)
				v[j][8*i+6] = eta - (int32(r[j*polysizes+3*i+2])>>2)&7
				v[j][8*i+7] = eta - (int32(r[j*polysizes+3*i+2])>>5)&7
			}
		}
	}
	return v
}

// packZ packs a Z vec.
func packZ(v Vec, l, polysizeZ int, gamma1 int32) []byte {
	r := make([]byte, l*polysizeZ)
	if gamma1 == (1 << 17) {
		t := make([]int32, 4)
		for j := 0; j < l; j++ {
			for i := 0; i < n/4; i++ {
				t[0] = gamma1 - v[j][4*i+0]
				t[1] = gamma1 - v[j][4*i+1]
				t[2] = gamma1 - v[j][4*i+2]
				t[3] = gamma1 - v[j][4*i+3]

				r[j*polysizeZ+9*i+0] = byte(t[0])
				r[j*polysizeZ+9*i+1] = byte(t[0] >> 8)
				r[j*polysizeZ+9*i+2] = byte(t[0]>>16) | byte(t[1]<<2)
				r[j*polysizeZ+9*i+3] = byte(t[1] >> 6)
				r[j*polysizeZ+9*i+4] = byte(t[1]>>14) | byte(t[2]<<4)
				r[j*polysizeZ+9*i+5] = byte(t[2] >> 4)
				r[j*polysizeZ+9*i+6] = byte(t[2]>>12) | byte(t[3]<<6)
				r[j*polysizeZ+9*i+7] = byte(t[3] >> 2)
				r[j*polysizeZ+9*i+8] = byte(t[3] >> 10)
			}
		}
		return r
	}
	t := make([]int32, 2)
	for j := 0; j < l; j++ {
		for i := 0; i < n/2; i++ {
			t[0] = gamma1 - v[j][2*i+0]
			t[1] = gamma1 - v[j][2*i+1]

			r[j*polysizeZ+5*i+0] = byte(t[0])
			r[j*polysizeZ+5*i+1] = byte(t[0] >> 8)
			r[j*polysizeZ+5*i+2] = byte(t[0]>>16) | byte(t[1]<<4)
			r[j*polysizeZ+5*i+3] = byte(t[1] >> 4)
			r[j*polysizeZ+5*i+4] = byte(t[1] >> 12)
		}
	}
	return r
}

// unpackZ reverses the packing operation.
func unpackZ(buf []byte, l, polysizeZ int, gamma1 int32) Vec {
	v := make(Vec, l)
	if gamma1 == (1 << 17) {
		for j := 0; j < l; j++ {
			for i := 0; i < n/4; i++ {
				v[j][4*i+0] = int32(buf[j*polysizeZ+9*i+0]) | (int32(buf[j*polysizeZ+9*i+1]) << 8) | (int32(buf[j*polysizeZ+9*i+2])<<16)&0x3FFFF
				v[j][4*i+1] = (int32(buf[j*polysizeZ+9*i+2]) >> 2) | (int32(buf[j*polysizeZ+9*i+3]) << 6) | (int32(buf[j*polysizeZ+9*i+4])<<14)&0x3FFFF
				v[j][4*i+2] = (int32(buf[j*polysizeZ+9*i+4]) >> 4) | (int32(buf[j*polysizeZ+9*i+5]) << 4) | (int32(buf[j*polysizeZ+9*i+6])<<12)&0x3FFFF
				v[j][4*i+3] = (int32(buf[j*polysizeZ+9*i+6]) >> 6) | (int32(buf[j*polysizeZ+9*i+7]) << 2) | (int32(buf[j*polysizeZ+9*i+8])<<10)&0x3FFFF

				v[j][4*i+0] = gamma1 - v[j][4*i+0]
				v[j][4*i+1] = gamma1 - v[j][4*i+1]
				v[j][4*i+2] = gamma1 - v[j][4*i+2]
				v[j][4*i+3] = gamma1 - v[j][4*i+3]
			}
		}
		return v
	}
	for j := 0; j < l; j++ {
		for i := 0; i < n/2; i++ {
			v[j][2*i+0] = int32(buf[j*polysizeZ+5*i+0]) | (int32(buf[j*polysizeZ+5*i+1]) << 8) | (int32(buf[j*polysizeZ+5*i+2])<<16)&0xFFFFF
			v[j][2*i+1] = (int32(buf[j*polysizeZ+5*i+2]) >> 4) | (int32(buf[j*polysizeZ+5*i+3]) << 4) | (int32(buf[j*polysizeZ+5*i+4])<<12)&0xFFFFF
			v[j][2*i+0] = gamma1 - v[j][2*i+0]
			v[j][2*i+1] = gamma1 - v[j][2*i+1]
		}
	}
	return v
}

// packH packs an H vec.
func packH(v Vec, k int, omega int) []byte {
	buf := make([]byte, omega+k)
	off := 0
	for i := 0; i < k; i++ {
		for j := 0; j < n; j++ {
			if v[i][j] != 0 {
				buf[off] = byte(j)
				off++
			}
		}
		buf[omega+i] = byte(off)
	}
	return buf
}

// unpackH reverses the packing operation.
func unpackH(buf []byte, l int, omega int) Vec {
	v := make(Vec, l)
	k := uint8(0)
	for i := 0; i < l; i++ {
		SOP := buf[omega+i]
		if SOP < k || SOP > uint8(omega) {
			return make(Vec, l)
		}
		for j := k; j < SOP; j++ {
			if j > k && buf[j] <= buf[j-1] {
				return make(Vec, l)
			}
			v[i][buf[j]] = 1
		}
		k = SOP
	}
	for j := k; j < uint8(omega); j++ {
		if buf[j] != 0 {
			return make(Vec, l)
		}
	}
	return v
}

// PackSig packs a dilithium signature into a byte array.
func (d *Dilithium) PackSig(z Vec, h Vec, hc []byte) []byte {
	K := d.params.K
	L := d.params.L
	OMEGA := d.params.OMEGA
	POLYSIZEZ := d.params.POLYSIZEZ
	sigP := make([]byte, d.params.SIZESIG)
	copy(sigP[:32], hc)
	copy(sigP[32:], packZ(z, L, POLYSIZEZ, d.params.GAMMA1))
	copy(sigP[32+L*POLYSIZEZ:], packH(h, K, OMEGA))
	return sigP
}

// UnpackSig unpacks a byte array into a signature. If the format is incorrect, nil objects are returned.
func (d *Dilithium) UnpackSig(sig []byte) (Vec, Vec, []byte) {
	K := d.params.K
	L := d.params.L
	if len(sig) != d.SIZESIG() {
		return nil, nil, nil
	}
	OMEGA := d.params.OMEGA
	POLYSIZEZ := d.params.POLYSIZEZ
	id := 32
	z := unpackZ(sig[id:], L, POLYSIZEZ, d.params.GAMMA1)
	id += L * POLYSIZEZ
	h := unpackH(sig[id:], K, OMEGA)
	return z, h, sig[:32]
}
