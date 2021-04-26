package dilithium

import (
	"crypto/rand"
	"testing"
)

func TestNTT(t *testing.T) {
	var seed [SEEDBYTES]byte
	for i := 0; i < 100; i++ {
		rand.Read(seed[:])
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

func TestNTT1(t *testing.T) {

	var seed [SEEDBYTES]byte
	for i := 0; i < 100; i++ {
		rand.Read(seed[:])
		p := polyUniform(seed, uint16(0))
		q := polyUniform(seed, uint16(1))

		expected := add(p, q)
		expected.addQ()

		p.ntt()
		q.ntt()
		p.tomont()
		q.tomont()

		res := add(p, q)
		res.reduce()
		res.invntt()
		res.addQ()
		res.fromMont()
		res.addQ()

		if !res.equal(expected) {
			t.Fatal("Failed")
		}
	}
}

func TestNTT2(t *testing.T) {

	var seed [SEEDBYTES]byte
	seed[0] = 1
	p := polyUniform(seed, uint16(0))
	q := polyUniform(seed, uint16(1))

	expected := add(p, q)
	expected.addQ()

	p.ntt()
	q.ntt()
	p.reduce()
	q.reduce()
	res := add(p, q)
	res.invntt()
	res.addQ()
	res.fromMont()

	if !res.equal(expected) {
		t.Fatal("Failed")
	}
}

func TestNTT3(t *testing.T) {

	var seed [SEEDBYTES]byte
	seed[0] = 1
	p := polyUniform(seed, uint16(0))
	q := polyUniform(seed, uint16(1))

	expected := add(p, q)
	expected.addQ()

	p.ntt()
	q.ntt()
	res := add(p, q)
	res.reduce()
	res.invntt()
	res.fromMont()

	if !res.equal(expected) {
		t.Fatal("Failed")
	}
}
func TestNTT4(t *testing.T) {

	var seed [SEEDBYTES]byte
	seed[0] = 1
	p := polyUniform(seed, uint16(0))
	q := polyUniform(seed, uint16(1))

	expected := add(p, q)
	expected.addQ()

	p.ntt()
	q.ntt()
	res := add(p, q)
	res.reduce()
	res.invntt()
	res.fromMont()
	res.addQ()

	if !res.equal(expected) {
		t.Fatal("Failed")
	}
}

func TestNTT5(t *testing.T) {

	var seed [SEEDBYTES]byte
	seed[0] = 1
	p := polyUniform(seed, uint16(0))
	q := polyUniform(seed, uint16(1))

	expected := add(p, q)
	expected.addQ()

	p.ntt()
	q.ntt()

	res := add(p, q)
	res.freeze()
	res.invntt()
	res.addQ()
	res.fromMont()

	if !res.equal(expected) {
		t.Fatal("Failed")
	}
}

func TestNTT6(t *testing.T) {

	var seed [SEEDBYTES]byte
	seed[0] = 1
	p := polyUniform(seed, uint16(0))
	q := polyUniform(seed, uint16(1))

	expected := add(p, q)
	expected.addQ()

	p.ntt()
	q.ntt()

	p.tomont()
	q.tomont()
	res := add(p, q)
	res.reduce()
	res.invntt()
	res.addQ()
	res.fromMont()

	if !res.equal(expected) {
		t.Fatal("Failed")
	}
}

func TestNTT7(t *testing.T) {
	var seed [SEEDBYTES]byte
	seed[0] = 1
	p := polyUniform(seed, uint16(0))
	q := polyUniform(seed, uint16(1))

	expected := add(p, q)
	expected.addQ()

	p.ntt()
	q.ntt()
	res := add(p, q)
	res.addQ()
	res.invntt()
	res.addQ()
	res.fromMont()

	if !res.equal(expected) {
		t.Fatal("Failed")
	}
}

func TestNTT8(t *testing.T) {
	var seed [SEEDBYTES]byte
	seed[0] = 1
	p := polyUniform(seed, uint16(0))
	q := polyUniform(seed, uint16(1))

	expected := add(p, q)
	expected.addQ()

	p.ntt()
	q.ntt()
	res := add(p, q)
	res.freeze()
	res.invntt()
	res.addQ()
	res.fromMont()

	if !res.equal(expected) {
		t.Fatal("Failed")
	}
}

func TestNTT9(t *testing.T) {
	var seed [SEEDBYTES]byte
	seed[0] = 1
	p := polyUniform(seed, uint16(0))
	q := polyUniform(seed, uint16(1))

	expected := add(p, q)
	expected.addQ()

	p.ntt()
	q.ntt()
	res := add(p, q)
	res.invntt()
	res.addQ()
	res.fromMont()

	if !res.equal(expected) {
		t.Fatal("Failed")
	}
}
