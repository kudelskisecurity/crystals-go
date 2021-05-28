package kyber

type Mat []Vec

func expandSeed(rho []byte, transpose bool, k int) Mat {
	m := make(Mat, k)
	for i := 0; i < k; i++ {
		m[i] = make(Vec, k)
		for j := 0; j < k; j++ {
			if transpose {
				m[i][j] = polyUniform(rho, []byte{uint8(i), uint8(j)})
			} else {
				m[i][j] = polyUniform(rho, []byte{uint8(j), uint8(i)})
			}
		}
	}
	return m
}

// Loads 4 bytes into a 32-bit integer in little-endian order.
func load32LE(x []byte) uint32 {
	var r uint32
	r = uint32(x[0])
	r |= uint32(x[1]) << 8
	r |= uint32(x[2]) << 16
	r |= uint32(x[3]) << 24
	return r
}

// loads 3 bytes into a 32-bit integer in little-endian order.
func load24LE(x []byte) uint32 {
	var r uint32
	r = uint32(x[0])
	r |= uint32(x[1]) << 8
	r |= uint32(x[2]) << 16
	return r
}

// freeze reduces input mod Q.
func freeze(x int16) int16 {
	a := x - int16(q)
	a += (a >> 15) & int16(q)
	return a
}
