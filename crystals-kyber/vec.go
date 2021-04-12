package kyber

type Vec []Poly //K poly exactement

func vecPointWise(u, v Vec, K int) Poly {
	var r Poly
	for i := 0; i < K; i++ {
		t := polyBaseMul(u[i], v[i])
		r = add(r, t)
	}
	return r
}

func (v Vec) equal(u Vec, K int) bool {
	for i := 0; i < K; i++ {
		for j := 0; j < n; j++ {
			if v[i][j] != u[i][j] {
				return false
			}
		}
	}
	return true
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
