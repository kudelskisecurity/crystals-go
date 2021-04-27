package kyber

var zetas = [128]int16{
	-1044, -758, -359, -1517, 1493, 1422, 287, 202,
	-171, 622, 1577, 182, 962, -1202, -1474, 1468,
	573, -1325, 264, 383, -829, 1458, -1602, -130,
	-681, 1017, 732, 608, -1542, 411, -205, -1571,
	1223, 652, -552, 1015, -1293, 1491, -282, -1544,
	516, -8, -320, -666, -1618, -1162, 126, 1469,
	-853, -90, -271, 830, 107, -1421, -247, -951,
	-398, 961, -1508, -725, 448, -1065, 677, -1275,
	-1103, 430, 555, 843, -1251, 871, 1550, 105,
	422, 587, 177, -235, -291, -460, 1574, 1653,
	-246, 778, 1159, -147, -777, 1483, -602, 1119,
	-1590, 644, -872, 349, 418, 329, -156, -75,
	817, 1097, 603, 610, 1322, -1285, -1465, 384,
	-1215, -136, 1218, -1335, -874, 220, -1187, -1659,
	-1185, -1530, -1278, 794, -1510, -854, -870, 478,
	-108, -308, 996, 991, 958, -1460, 1522, 1628,
}

var f = int16(1441)

//NTT performs in place forward NTT
func (p *Poly) ntt() {
	var len, start, j, k uint
	var zeta, t int16

	k = 1
	for len = 128; len > 1; len >>= 1 {
		for start = 0; start < n; start = j + len {
			zeta = zetas[k]
			k++
			for j = start; j < start+len; j++ {
				t = fqmul(zeta, p[j+len])
				p[j+len] = p[j] - t
				p[j] = p[j] + t
			}
		}
	}
}

//InvNTT perfors in place backward NTT and multiplication by Montgomery factor 2^32.
func (p *Poly) invntt() {
	var len, start, j, k uint
	var zeta, t int16

	k = 127
	for len = 2; len < n; len <<= 1 {
		for start = 0; start < n; start = j + len {
			zeta = zetas[k]
			k--
			for j = start; j < start+len; j++ {
				t = p[j]
				p[j] = barretReduce(t + p[j+len])
				p[j+len] = p[j+len] - t
				p[j+len] = fqmul(zeta, p[j+len])
			}
		}
	}

	for j = 0; j < n; j++ {
		p[j] = fqmul(f, p[j])
	}
}

func (v Vec) ntt(K int) {
	for i := 0; i < K; i++ {
		v[i].ntt()
	}
}

//Computes the integer in {-(q-1)/2,...,(q-1)/2} congruent to a modulo q
func barretReduce(a int16) int16 {
	v := int16(((uint32(1) << 26) + uint32(q/2)) / uint32(q))

	t := int16(int32(v) * int32(a) >> 26)
	//t := int16((int32(v)*int32(a) + (1 << 25)) >> 26)
	t *= int16(q)
	return a - t
}

//Computes the integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q
func montgomeryReduce(a int32) int16 {
	u := int16(a * int32(qInv))
	t := int32(u) * int32(q)
	v := uint32(a - t)
	v >>= 16
	return int16(v)
}

func (p *Poly) fromMont() {
	inv := uint32(169)
	for i := uint(0); i < n; i++ {
		p[i] = int16((uint32(p[i]) * inv) % q)
	}
}

//Multiplication folowed by Montgomery reduction
func fqmul(a, b int16) int16 {
	return montgomeryReduce(int32(a) * int32(b))
}

//Multiplication of elements in Rq in NTT domain
func basemul(a, b []int16, zeta int16) []int16 {
	r := make([]int16, 2)
	r[0] = fqmul(a[1], b[1])
	r[0] = fqmul(r[0], zeta)
	r[0] += fqmul(a[0], b[0])
	r[1] = fqmul(a[0], b[1])
	r[1] += fqmul(a[1], b[0])
	return r
}
