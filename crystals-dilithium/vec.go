package dilithium

// Vec holds L or K polynomials.
type Vec []Poly

// copy creates a deep copy of a polynomial.
func (v Vec) copy() Vec {
	u := make(Vec, len(v))
	copy(u, v)
	return u
}

// vecAdd ads two Vec polynomial-wise.
func vecAdd(u, v Vec, l int) Vec {
	w := make(Vec, l)
	for i := 0; i < l; i++ {
		w[i] = add(u[i], v[i])
	}
	return w
}

// vecAccPointWise performs multiplication of two vec.
func vecAccPointWise(u, v Vec, l int) Poly {
	var w, t Poly
	for i := 0; i < l; i++ {
		t = montMul(u[i], v[i])
		w = add(w, t)
	}
	return w
}

// vecIsBelow return true if all coefs are in [Q-bound, Q+bound].
func (v Vec) vecIsBelow(bound int32, l int) bool {
	res := true
	for i := 0; i < l; i++ {
		res = res && v[i].isBelow(bound)
	}
	return res
}

// vecMakeHint calls MakeHint on each poly, and returns the hints and the number of +/-1's.
func vecMakeHint(u, v Vec, l int, gamma2 int32) (Vec, int) {
	h := make(Vec, l)
	s := int32(0)
	for i := 0; i < l; i++ {
		for j := 0; j < n; j++ {
			h[i][j] = makeHint(u[i][j], v[i][j], gamma2)
			s += h[i][j]
		}
	}
	return h, int(s)
}

// equal returns true if u is equal to v.
func (v Vec) equal(u Vec, l int) bool {
	for i := 0; i < l; i++ {
		for j := 0; j < n; j++ {
			if v[i][j] != u[i][j] {
				return false
			}
		}
	}
	return true
}

// sum computes the number of +/-1's in v.
func (v Vec) sum(l int) int {
	sum := 0
	for i := 0; i < l; i++ {
		for j := 0; j < n; j++ {
			if v[i][j] != 0 {
				sum++
			}
		}
	}
	return sum
}
