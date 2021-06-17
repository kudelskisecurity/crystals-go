package dilithium

import (
	cRand "crypto/rand"
	"io"
	"math/rand"
	"testing"
)

/** Test Poly **/

func TestPoly(t *testing.T) {
	var seed [32]byte
	rand := cRand.Reader
	io.ReadFull(rand, seed[:])

	p := polyUniform(seed, 0)
	p2 := polyUniform(seed, 1)

	a := add(p, p2)

	for i := uint(0); i < n; i++ {
		if a[i] != (p[i] + p2[i]) {
			t.Fatalf("Add failed")
		}
	}

	b := sub(p, p2)
	for i := uint(0); i < n; i++ {
		if b[i] != (p[i] - p2[i]) {
			t.Fatalf("Sub failed")
		}
	}
}

func TestFreeze(t *testing.T) {

	a := int32(q + 1)
	if freeze(a) != 1 {
		t.Fatal("Freeze did not work")
	}

	var seed [32]byte
	rand := cRand.Reader
	io.ReadFull(rand, seed[:])

	var p, b Poly
	p = polyUniform(seed, 0)
	b = add(p, p)
	//some coefs must be > Q
	c := b
	c.freeze()
	for i := uint(0); i < n; i++ {
		if c[i] != (b[i] % q) {
			t.Fatalf("Freeze failed")
		}
	}
}

func TestRandPoly(t *testing.T) {
	var seed [32]byte
	copy(seed[:], []byte("very random seed that I will use"))
	var p, p2 Poly
	p = polyUniform(seed, 0)
	p2 = polyUniform(seed, 0)
	for i := uint(0); i < n; i++ {
		if p[i] != p2[i] {
			t.Fatalf("Seed did not work")
		}
	}
	p2 = polyUniform(seed, 1)
	counter := 0
	for i := uint(0); i < n; i++ {
		if p[i] == p2[i] {
			counter++
		}
		if counter == n {
			t.Fatalf("Seed did not work")
		}
	}
}

func TestSamples(t *testing.T) {
	var seed [64]byte
	rand := cRand.Reader
	io.ReadFull(rand, seed[:])

	ETA := int32(2)

	var p, p2 Poly
	p = polyUniformEta(seed, 1, ETA)
	if !p.isBelow(ETA + 1) { //i > eta
		t.Fatalf("PolyUniformEta sampled failed %v\n", p)
	}
	var rhoP [64]byte
	io.ReadFull(rand, rhoP[:])
	GAMMA1 := int32(1 << 17)
	p2 = polyUniformGamma1(rhoP, 0, GAMMA1)
	if !p2.isBelow(GAMMA1 + 1) { //if stritcly above
		t.Fatalf("PolyUnifromGamma1 sampled failed  %v\n", p2)
	}
}

func TestExpand(t *testing.T) {
	var seed [32]byte
	copy(seed[:], []byte("very random seed that I will use"))
	K, L := 6, 5
	A := expandSeed(seed, K, L)
	Abis := expandSeed(seed, K, L)
	for i := 0; i < K; i++ {
		for j := 0; j < L; j++ {
			if A[i][j] != Abis[i][j] {
				t.Fatalf("Seed did not work")
			}
		}
	}
	for j := 1; j < L; j++ {
		if A[0][0] == A[0][j] {
			t.Fatalf("Poly is repeating %v against %d: %v\n", A[0][0], j, A[0][j])
		}
	}
}

func TestMult(t *testing.T) {
	var p, p2 Poly

	p[0] = 1
	p2[0] = 1
	p.ntt()
	p2.ntt()
	res := montMul(p, p2)
	p.invntt()
	p2.invntt()
	res.invntt()
	res.freeze()
	if res[0] != 1 {
		t.Fatalf("Mult did not work %v\n", res)
	}
	for i := 1; i < n; i++ {
		if res[i] != 0 {
			t.Fatal("Mult did not work")
		}
	}
}

/** Test Utils **/

func TestPow2Round(t *testing.T) {
	r := int32(rand.Intn(q - 1))
	r1, r0 := power2Round(r)
	if (-(1 << (d - 1)) >= r0) || (r0 >= 1<<(d-1)) {
		t.Fatalf("Power2Round failed r0 not in the bounds")
	}
	if int32(r1)*(1<<d)+r0 != int32(r) {
		t.Fatal("Power2Round failed")
	}
}

func TestDecompose(t *testing.T) {
	g2 := int32(q-1) / 88
	r := int32(rand.Intn(int(g2 + 1)))
	r1, r0 := decompose(r, g2)

	if r1*g2+r0 != r {
		println(r)
		println(r1*g2 + freeze(r0))
		println(r0)
		t.Fatal("Decompose failed")
	}
}

/** Test Hints **/

func TestMakeHints(t *testing.T) {
	d := NewDilithium3(false)
	r := int32(rand.Intn(q))
	g2 := int32(d.params.GAMMA2)
	r1, r0 := decompose(r, g2)
	//useHint( r - f, makeHint( r0 - f, r1 ) ) = r1.
	if makeHint(r1, r0, g2) != 0 {
		t.Fatal("Make hint failed")
	}
	r0 = int32(1 + d.params.GAMMA2)
	if makeHint(r1, r0, g2) != 1 {
		t.Fatal("Make hint failed")
	}
}

func TestUseHints(t *testing.T) {
	d := NewDilithium3(false)
	r := int32(rand.Intn(q))
	g2 := d.params.GAMMA2
	r1, r0PQ := decompose(r, g2)
	r0 := r0PQ
	//useHint( r - f, makeHint( r0 - f, r1 ) ) = r1.
	if useHint(r, makeHint(r1, r0, g2), g2) != r1 {
		t.Fatal("Use hint failed")
	}
	if useHint(r, makeHint(r1, r0+n, g2), g2) != r1 {
		t.Fatal("Use hint failed")
	}
	z := int32(d.params.GAMMA2 + 1)
	if useHint(r, makeHint(r1, z, g2), g2) == r1 {
		t.Fatal("Use hint failed")
	}
}

//test wether we can pack (NTT(s)) the same way as s: answer is no...
/**
func OneTimeRunTestPackSNTT(t *testing.T) {
	var seed [64]byte
	seed[0] = 1
	L := 6
	ETA := int32(2)
	SIZES := 640
	s1 := make(Vec, L)
	for i := 0; i < L; i++ {
		s1[i] = polyUniformEta(seed, uint16(i), 4)
	}
	s1.ntt(L)
	ps1 := packS(s1, L, SIZES, ETA)
	s1Rec := unpackS(ps1, L, SIZES, ETA)
	if !s1[0].equal(s1Rec[0]) {
		t.Fatal("could not reconstruct after NTT")
	}
}**/

func TestNTT1(t *testing.T) {
	var seed [SEEDBYTES]byte
	for i := 0; i < 100; i++ {
		cRand.Read(seed[:])
		p := polyUniform(seed, uint16(0))
		expected := p
		expected.addQ()

		p.ntt()
		p.invntt()
		p.addQ()
		p.fromMont()
		p.addQ()

		for i := uint(0); i < n; i++ {
			if p[i] != expected[i] {
				t.Fatalf("Failed")
			}
		}
	}
}

func TestNTT0(t *testing.T) {
	var seed [SEEDBYTES]byte
	for i := 0; i < 100; i++ {
		cRand.Read(seed[:])
		p := polyUniform(seed, uint16(0))

		expected := p

		p.ntt()
		p.tomont()
		p.invntt()
		p.addQ()

		for i := uint(0); i < n; i++ {
			if p[i] != expected[i] {
				t.Fatalf("Failed")
			}
		}
	}
}

func TestNTTAdd(t *testing.T) {
	var seed [SEEDBYTES]byte
	cRand.Read(seed[:])
	p := polyUniform(seed, uint16(0))
	p2 := polyUniform(seed, uint16(1))

	expected := add(p, p2)
	expected.freeze()

	p.ntt()
	p2.ntt()
	res := add(p, p2)
	res.invntt()
	res.addQ()
	res.fromMont()

	if !res.equal(expected) {
		t.Fatal("Failed")
	}
}

func TestNTTAdd0(t *testing.T) {
	var seed [SEEDBYTES]byte
	cRand.Read(seed[:])
	p := polyUniform(seed, uint16(0))
	p2 := polyUniform(seed, uint16(1))
	p3 := add(p, p2)
	p3.freeze()

	expected := add(p, p3)
	expected.freeze()

	p.ntt()
	p3.ntt()
	p.tomont()
	p3.tomont()
	res := add(p, p3)
	res.invntt()
	res.addQ()

	if !res.equal(expected) {
		t.Fatal("Failed")
	}
}
