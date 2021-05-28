package kyber

import (
	"crypto/rand"
	"testing"
)

var K = 2

func TestExpand(t *testing.T) {
	t.Parallel()
	var seed [32]byte
	copy(seed[:], "very random seed that I will use")
	A := expandSeed(seed[:], false, K)
	Abis := expandSeed(seed[:], false, K)
	for i := 0; i < K; i++ {
		for j := 0; j < K; j++ {
			if A[i][j] != Abis[i][j] {
				t.Fatalf("Seed did not work")
			}
		}
	}
	for j := 1; j < K; j++ {
		if A[0][0] == A[0][j] {
			t.Fatalf("Poly is repeating %v against %d: %v\n", A[0][0], j, A[0][j])
		}
	}
}

func randVec() Vec {
	v := make(Vec, K)
	var seed [32]byte
	for i := 0; i < K; i++ {
		rand.Read(seed[:])
		v[i] = polyUniform(seed[:], []byte{0})
	}
	return v
}

func TestPacking(t *testing.T) {
	t.Parallel()
	v := randVec()
	pv := pack(v, K)
	v2 := unpack(pv, K)
	if !v.equal(v2, K) {
		t.Fatal("Pack is lossy")
	}
}

func TestEqual(t *testing.T) {
	t.Parallel()
	u, v := randVec(), randVec()
	if u.equal(v, K) {
		t.Fatal("equal failed")
	}
}
