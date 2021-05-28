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
