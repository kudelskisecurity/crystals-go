package dilithium

//packT1 returns the byte representation of v
func packT1(v Vec, K int) []byte {
	r := make([]byte, K*polySizeT1)

	for j := 0; j < K; j++ {
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

//pnpackT1 reverses the packing operation
func unpackT1(r []byte, K int) Vec {
	v := make(Vec, K)
	for j := 0; j < K; j++ {
		for i := 0; i < n/4; i++ {
			v[j][4*i+0] = (int32(r[j*polySizeT1+5*i+0]) >> 0) | (int32(r[j*polySizeT1+5*i+1])<<8)&0x3FF
			v[j][4*i+1] = (int32(r[j*polySizeT1+5*i+1]) >> 2) | (int32(r[j*polySizeT1+5*i+2])<<6)&0x3FF
			v[j][4*i+2] = (int32(r[j*polySizeT1+5*i+2]) >> 4) | (int32(r[j*polySizeT1+5*i+3])<<4)&0x3FF
			v[j][4*i+3] = (int32(r[j*polySizeT1+5*i+3]) >> 6) | (int32(r[j*polySizeT1+5*i+4])<<2)&0x3FF
		}
	}
	return v
}

//packT0 packs t0
func packT0(v Vec, K int) []byte {
	r := make([]byte, K*polySizeT0)
	t := make([]uint32, 8)
	for j := 0; j < K; j++ {
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

//unpackT0 reverses the packing operation
func unpackT0(a []byte, K int) Vec {
	v := make(Vec, K)
	for j := 0; j < K; j++ {
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

//packW1 packs a w1 poly
func packW1(v Vec, L, POLYSIZEW1 int, GAMMA2 int32) []byte {
	r := make([]byte, L*POLYSIZEW1)
	if GAMMA2 == (q-1)/88 {
		for j := 0; j < L; j++ {
			for i := 0; i < n/4; i++ {
				r[j*POLYSIZEW1+3*i+0] = byte(v[j][4*i+0] | v[j][4*i+1]<<6)
				r[j*POLYSIZEW1+3*i+1] = byte(v[j][4*i+1]>>2 | v[j][4*i+2]<<4)
				r[j*POLYSIZEW1+3*i+2] = byte(v[j][4*i+2]>>4 | v[j][4*i+3]<<2)
			}
		}
		return r
	}
	for j := 0; j < L; j++ {
		for i := 0; i < n/2; i++ {
			r[j*POLYSIZEW1+i] = byte(v[j][2*i+0] | (v[j][2*i+1] << 4))
		}
	}
	return r
}

//packS packs a S vec
func packS(v Vec, L, POLYSIZES int, ETA int32) []byte {
	r := make([]byte, L*POLYSIZES)
	if ETA == 4 {
		t := make([]byte, 2)
		for j := 0; j < L; j++ {
			for i := 0; i < n/2; i++ {
				t[0] = byte(ETA - v[j][2*i+0])
				t[1] = byte(ETA - v[j][2*i+1])
				r[j*POLYSIZES+i] = t[0] | (t[1] << 4)
			}
		}
	}
	if ETA == 2 {
		t := make([]byte, 8)
		for j := 0; j < L; j++ {
			for i := 0; i < n/8; i++ {
				t[0] = byte(ETA - v[j][8*i+0])
				t[1] = byte(ETA - v[j][8*i+1])
				t[2] = byte(ETA - v[j][8*i+2])
				t[3] = byte(ETA - v[j][8*i+3])
				t[4] = byte(ETA - v[j][8*i+4])
				t[5] = byte(ETA - v[j][8*i+5])
				t[6] = byte(ETA - v[j][8*i+6])
				t[7] = byte(ETA - v[j][8*i+7])

				r[j*POLYSIZES+3*i+0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6)
				r[j*POLYSIZES+3*i+1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7)
				r[j*POLYSIZES+3*i+2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5)
			}
		}
	}
	return r
}

//unpackS reverses the packing of an S vec
func unpackS(r []byte, L, POLYSIZES int, ETA int32) Vec {
	v := make(Vec, L)
	if ETA == 4 {
		for j := 0; j < L; j++ {
			for i := 0; i < n/2; i++ {
				v[j][2*i+0] = int32(uint32(r[j*POLYSIZES+i]) & 0x0F)
				v[j][2*i+1] = int32(uint32(r[j*POLYSIZES+i]) >> 4)
				v[j][2*i+0] = ETA - v[j][2*i+0]
				v[j][2*i+1] = ETA - v[j][2*i+1]
			}
		}
	}
	if ETA == 2 {
		for j := 0; j < L; j++ {
			for i := 0; i < n/8; i++ {
				v[j][8*i+0] = ETA - int32(r[j*POLYSIZES+3*i])&7
				v[j][8*i+1] = ETA - int32(r[j*POLYSIZES+3*i])>>3&7
				v[j][8*i+2] = ETA - (int32(r[j*POLYSIZES+3*i])>>6 | (int32(r[j*POLYSIZES+3*i+1])<<2)&7)
				v[j][8*i+3] = ETA - (int32(r[j*POLYSIZES+3*i+1])>>1)&7
				v[j][8*i+4] = ETA - (int32(r[j*POLYSIZES+3*i+1])>>4)&7
				v[j][8*i+5] = ETA - (int32(r[j*POLYSIZES+3*i+1])>>7 | (int32(r[j*POLYSIZES+3*i+2])<<1)&7)
				v[j][8*i+6] = ETA - (int32(r[j*POLYSIZES+3*i+2])>>2)&7
				v[j][8*i+7] = ETA - (int32(r[j*POLYSIZES+3*i+2])>>5)&7
			}
		}
	}
	return v
}

//packZ packs a Z vec
func packZ(v Vec, L, POLYSIZEZ int, GAMMA1 int32) []byte {
	r := make([]byte, L*POLYSIZEZ)
	if GAMMA1 == (1 << 17) {
		t := make([]int32, 4)
		for j := 0; j < L; j++ {
			for i := 0; i < n/4; i++ {
				t[0] = GAMMA1 - v[j][4*i+0]
				t[1] = GAMMA1 - v[j][4*i+1]
				t[2] = GAMMA1 - v[j][4*i+2]
				t[3] = GAMMA1 - v[j][4*i+3]

				r[j*POLYSIZEZ+9*i+0] = byte(t[0])
				r[j*POLYSIZEZ+9*i+1] = byte(t[0] >> 8)
				r[j*POLYSIZEZ+9*i+2] = byte(t[0]>>16) | byte(t[1]<<2)
				r[j*POLYSIZEZ+9*i+3] = byte(t[1] >> 6)
				r[j*POLYSIZEZ+9*i+4] = byte(t[1]>>14) | byte(t[2]<<4)
				r[j*POLYSIZEZ+9*i+5] = byte(t[2] >> 4)
				r[j*POLYSIZEZ+9*i+6] = byte(t[2]>>12) | byte(t[3]<<6)
				r[j*POLYSIZEZ+9*i+7] = byte(t[3] >> 2)
				r[j*POLYSIZEZ+9*i+8] = byte(t[3] >> 10)
			}
		}
		return r
	}
	t := make([]int32, 2)
	for j := 0; j < L; j++ {
		for i := 0; i < n/2; i++ {
			t[0] = GAMMA1 - v[j][2*i+0]
			t[1] = GAMMA1 - v[j][2*i+1]

			r[j*POLYSIZEZ+5*i+0] = byte(t[0])
			r[j*POLYSIZEZ+5*i+1] = byte(t[0] >> 8)
			r[j*POLYSIZEZ+5*i+2] = byte(t[0]>>16) | byte(t[1]<<4)
			r[j*POLYSIZEZ+5*i+3] = byte(t[1] >> 4)
			r[j*POLYSIZEZ+5*i+4] = byte(t[1] >> 12)
		}
	}
	return r
}

//unpackZ reverses the packing operation
func unpackZ(buf []byte, L, POLYSIZEZ int, GAMMA1 int32) Vec {
	v := make(Vec, L)
	if GAMMA1 == (1 << 17) {
		for j := 0; j < L; j++ {
			for i := 0; i < n/4; i++ {
				v[j][4*i+0] = int32(buf[j*POLYSIZEZ+9*i+0]) | (int32(buf[j*POLYSIZEZ+9*i+1]) << 8) | (int32(buf[j*POLYSIZEZ+9*i+2])<<16)&0x3FFFF
				v[j][4*i+1] = (int32(buf[j*POLYSIZEZ+9*i+2]) >> 2) | (int32(buf[j*POLYSIZEZ+9*i+3]) << 6) | (int32(buf[j*POLYSIZEZ+9*i+4])<<14)&0x3FFFF
				v[j][4*i+2] = (int32(buf[j*POLYSIZEZ+9*i+4]) >> 4) | (int32(buf[j*POLYSIZEZ+9*i+5]) << 4) | (int32(buf[j*POLYSIZEZ+9*i+6])<<12)&0x3FFFF
				v[j][4*i+3] = (int32(buf[j*POLYSIZEZ+9*i+6]) >> 6) | (int32(buf[j*POLYSIZEZ+9*i+7]) << 2) | (int32(buf[j*POLYSIZEZ+9*i+8])<<10)&0x3FFFF

				v[j][4*i+0] = GAMMA1 - v[j][4*i+0]
				v[j][4*i+1] = GAMMA1 - v[j][4*i+1]
				v[j][4*i+2] = GAMMA1 - v[j][4*i+2]
				v[j][4*i+3] = GAMMA1 - v[j][4*i+3]
			}
		}
		return v
	}
	for j := 0; j < L; j++ {
		for i := 0; i < n/2; i++ {
			v[j][2*i+0] = int32(buf[j*POLYSIZEZ+5*i+0]) | (int32(buf[j*POLYSIZEZ+5*i+1]) << 8) | (int32(buf[j*POLYSIZEZ+5*i+2])<<16)&0xFFFFF
			v[j][2*i+1] = (int32(buf[j*POLYSIZEZ+5*i+2]) >> 4) | (int32(buf[j*POLYSIZEZ+5*i+3]) << 4) | (int32(buf[j*POLYSIZEZ+5*i+4])<<12)&0xFFFFF
			v[j][2*i+0] = GAMMA1 - v[j][2*i+0]
			v[j][2*i+1] = GAMMA1 - v[j][2*i+1]
		}
	}
	return v
}

//packH packs an H vec
func packH(v Vec, K int, OMEGA int) []byte {
	buf := make([]byte, OMEGA+K)
	off := 0
	for i := 0; i < K; i++ {
		for j := 0; j < n; j++ {
			if v[i][j] != 0 {
				buf[off] = byte(j)
				off++
			}
		}
		buf[OMEGA+i] = byte(off)
	}
	return buf[:]
}

//unpackH reverses the packing operation
func unpackH(buf []byte, L int, OMEGA int) Vec {
	v := make(Vec, L)
	k := uint8(0)
	for i := 0; i < L; i++ {
		SOP := buf[OMEGA+i]
		if SOP < k || SOP > uint8(OMEGA) {
			return make(Vec, L)
		}
		for j := k; j < SOP; j++ {
			if j > k && buf[j] <= buf[j-1] {
				return make(Vec, L)
			}
			v[i][buf[j]] = 1
		}
		k = SOP
	}
	for j := k; j < uint8(OMEGA); j++ {
		if buf[j] != 0 {
			return make(Vec, L)
		}
	}
	return v
}

//PackSig packs a dilithium signature into a byte array
func (d *Dilithium) PackSig(z Vec, h Vec, hc []byte) []byte {
	K := d.params.K
	L := d.params.L
	OMEGA := d.params.OMEGA
	POLYSIZEZ := d.params.POLYSIZEZ
	sigP := make([]byte, d.params.SIZESIG)
	copy(sigP[:32], hc[:])
	copy(sigP[32:], packZ(z, L, POLYSIZEZ, d.params.GAMMA1))
	copy(sigP[32+L*POLYSIZEZ:], packH(h, K, OMEGA))
	return sigP[:]
}

//UnpackSig unpacks a byte array into a signature. If the format is incorrect, nil objects are returned.
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
