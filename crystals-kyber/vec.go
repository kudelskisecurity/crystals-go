package kyber

//Vec is an array of K polynomials
type Vec []Poly

//vecPointWise multiplies two vectors together
func vecPointWise(u, v Vec, K int) Poly {
	var r Poly
	for i := 0; i < K; i++ {
		t := polyBaseMul(u[i], v[i])
		r = add(r, t)
	}
	return r
}

//equal returns true iff u and v have the same coefficients
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

//compress calls compress on each poly of the vec and concatenates their representation in a byte array
func (v Vec) compress(d int, K int) []byte {
	polylen := n * d / 8
	c := make([]byte, K*polylen)
	for i := 0; i < K; i++ {
		copy(c[i*polylen:], v[i].compress(d))
	}
	return c[:]
}

//decompressVec creates K polynomials from their byte representation
func decompressVec(c []byte, d int, K int) Vec {
	v := make(Vec, K)
	for i := 0; i < K; i++ {
		v[i] = decompressPoly(c[i*n*d/8:], d)
	}
	return v
}

//pack compress v in a byte array in a loss-less manner
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

//unpack reverses the packing operation
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
