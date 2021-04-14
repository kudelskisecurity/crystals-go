package dilithium

import (
	cRand "crypto/rand"
	"io"
	"testing"
)

func BenchmarkExpand(b *testing.B) {
	var rho [32]byte
	rand := cRand.Reader
	d := NewDilithium3(false)
	K := d.params.K
	L := d.params.L
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		io.ReadFull(rand, rho[:])
		b.StartTimer()
		expandSeed(rho, K, L)
	}
}

func BenchmarkOverheadRandPoly(b *testing.B) {
	var seed [32]byte
	rand := cRand.Reader
	for n := 0; n < b.N; n++ {
		io.ReadFull(rand, seed[:])
		polyUniform(seed, 0)
	}
}

func BenchmarkPolyNTT(b *testing.B) {
	var seed [32]byte
	rand := cRand.Reader
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		io.ReadFull(rand, seed[:])
		p := polyUniform(seed, 0)
		b.StartTimer()
		p.ntt()
	}
}

func BenchmarkPolyInvNTT(b *testing.B) {
	var seed [32]byte
	rand := cRand.Reader
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		io.ReadFull(rand, seed[:])
		p := polyUniform(seed, 0)
		p.ntt()
		b.StartTimer()
		p.invntt()
	}
}

func BenchmarkPointWise(b *testing.B) {
	var seed [32]byte
	rand := cRand.Reader
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		io.ReadFull(rand, seed[:])
		p := polyUniform(seed, 0)
		q := polyUniform(seed, 0)
		b.StartTimer()
		montMul(p, q)
	}
}
