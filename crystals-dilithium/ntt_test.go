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

func TestNTT0(t *testing.T) {
	var seed [SEEDBYTES]byte
	for i := 0; i < 100; i++ {
		rand.Read(seed[:])
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
	rand.Read(seed[:])
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
	rand.Read(seed[:])
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
