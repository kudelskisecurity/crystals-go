package dilithium

// Vec holds L or K Poly.
type Vec []Poly

func (v Vec) copy() Vec {
	u := make(Vec, len(v))
	copy(u, v)
	return u
}

// VecAdd ads two Vec.
func vecAdd(u, v Vec, l int) Vec {
	w := make(Vec, l)
	for i := 0; i < l; i++ {
		w[i] = add(u[i], v[i])
	}
	return w
}

// VecPointWise performs point wise mult (to be used with NTT).
func vecAccPointWise(u, v Vec, l int) Poly {
	var w, t Poly
	for i := 0; i < l; i++ {
		t = montMul(u[i], v[i])
		w = add(w, t)
	}
	return w
}

// VecIsBelow return true if all coefs are in [Q-bound, Q+bound].
func (v Vec) vecIsBelow(bound int32, l int) bool {
	res := true
	for i := 0; i < l; i++ {
		res = res && v[i].isBelow(bound)
	}
	return res
}

// VecShift mult all poly by 2^D.
func (v Vec) VecShift(l int) {
	for i := 0; i < l; i++ {
		v[i].shift()
	}
}

// VecKMakeHint calls MakeHint on each poly, and returns the hints and the number of 1's.
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

// Equal return true if u is equal to v (all poly are equal).
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

// Sum computes the sum of all coefs in the VecK.
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
