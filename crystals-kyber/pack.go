package kyber

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

func (p *Poly) compress(d int, polylen int) []byte {
	c := make([]byte, polylen)
	switch d { //4,5,10,11 or ?

	//size of the poly is N*3/8
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

func pack(v Vec, K int) []byte {
	var t0, t1 uint16
	r := make([]byte, K*polysize)
	for i := 0; i < K; i++ {
		for j := 0; j < n/2; j++ {
			v[i].freeze()
			t0 = uint16(v[i][2*j])
			t1 = uint16(v[i][2*j+1])
			r[i*polysize+3*j+0] = byte(t0 >> 0)
			r[i*polysize+3*j+1] = byte(t0>>8) | byte(t1<<4)
			r[i*polysize+3*j+2] = byte(t1 >> 4)
		}
	}
	return r
}

func unpack(r []byte, K int) Vec {
	v := make(Vec, K)
	for i := 0; i < K; i++ {
		for j := 0; j < n/2; j++ {
			v[i][2*j] = int16(r[3*j+i*polysize]) | ((int16(r[3*j+1+i*polysize]) << 8) & 0xfff)
			v[i][2*j+1] = int16(r[3*j+1+i*polysize]>>4) | (int16(r[3*j+2+i*polysize]) << 4)
		}
	}
	return v
}

func (v Vec) compress(d int, polylen int, K int) []byte {
	c := make([]byte, K*polylen)
	for i := 0; i < K; i++ {
		copy(c[i*polylen:], v[i].compress(d, polylen))
	}
	return c[:]
}

func decompressVec(c []byte, d int, buflen, K int) Vec {
	v := make(Vec, K)
	for i := 0; i < K; i++ {
		v[i] = decompressPoly(c[i*buflen:], d)
	}
	return v
}
