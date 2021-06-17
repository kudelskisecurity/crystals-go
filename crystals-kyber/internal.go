package kyber

//Mat is used to hold A
type Mat []Vec

//expandSeed generated a KxK array of polynomials woth coefficients in [0, Q)
func expandSeed(rho []byte, transpose bool, K int) Mat {
	m := make(Mat, K)
	for i := 0; i < K; i++ {
		m[i] = make(Vec, K)
		for j := 0; j < K; j++ {
			if transpose {
				m[i][j] = polyUniform(rho, []byte{uint8(i), uint8(j)})
			} else {
				m[i][j] = polyUniform(rho, []byte{uint8(j), uint8(i)})
			}
		}
	}
	return m
}

//load32LE loads 4 bytes into a 32-bit integer in little-endian order
func load32LE(x []byte) uint32 {
	var r uint32
	r = uint32(x[0])
	r |= uint32(x[1]) << 8
	r |= uint32(x[2]) << 16
	r |= uint32(x[3]) << 24
	return r
}

//load24LE loads 3 bytes into a 32-bit integer in little-endian order
func load24LE(x []byte) uint32 {
	var r uint32
	r = uint32(x[0])
	r |= uint32(x[1]) << 8
	r |= uint32(x[2]) << 16
	return r
}

//freeze maps x to [0, Q)
func freeze(x int16) int16 {
	a := x - int16(q)
	a = a + ((a >> 15) & int16(q))
	return a
}
