package kyber

type Vec []Poly // K poly exactement

func vecPointWise(u, v Vec, k int) Poly {
	var r Poly
	for i := 0; i < k; i++ {
		t := polyBaseMul(u[i], v[i])
		r = add(r, t)
	}
	return r
}

func (v Vec) equal(u Vec, k int) bool {
	for i := 0; i < k; i++ {
		for j := 0; j < n; j++ {
			if v[i][j] != u[i][j] {
				return false
			}
		}
	}
	return true
}
