package dilithium

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func BenchmarkECDSA(b *testing.B) {
	for n := 0; n < b.N; n++ {
		ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	}
}

func BenchmarkECDSASign(b *testing.B) {
	msg := "message to sign"
	hash := sha256.Sum256([]byte(msg))
	sk, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	for n := 0; n < b.N; n++ {
		ecdsa.SignASN1(rand.Reader, sk, hash[:])
	}
}

func BenchmarkECDSAVerify(b *testing.B) {
	msg := "message to sign"
	hash := sha256.Sum256([]byte(msg))
	sk, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	sig, _ := ecdsa.SignASN1(rand.Reader, sk, hash[:])
	for n := 0; n < b.N; n++ {
		ecdsa.VerifyASN1(&sk.PublicKey, hash[:], sig)
	}
}

func BenchmarkKeyGen2(b *testing.B)        { benchmarkKeyGen(b, NewDilithium2(false)) }
func BenchmarkSign2(b *testing.B)          { benchmarkSign(b, NewDilithium2(false)) }
func BenchmarkVerify2(b *testing.B)        { benchmarkVerify(b, NewDilithium2(false)) }

func BenchmarkKeyGen3(b *testing.B)        { benchmarkKeyGen(b, NewDilithium3(false)) }
func BenchmarkSign3(b *testing.B)          { benchmarkSign(b, NewDilithium3(false)) }
func BenchmarkVerify3(b *testing.B)        { benchmarkVerify(b, NewDilithium3(false)) }

func BenchmarkKeyGen5(b *testing.B)        { benchmarkKeyGen(b, NewDilithium5(false)) }
func BenchmarkSign5(b *testing.B)          { benchmarkSign(b, NewDilithium5(false)) }
func BenchmarkVerify5(b *testing.B)        { benchmarkVerify(b, NewDilithium5(false)) }

func benchmarkKeyGen(b *testing.B, d *Dilithium) {
	var seed [32]byte
	for n := 0; n < b.N; n++ {
		d.KeyGen(seed[:])
	}
}

func benchmarkSign(b *testing.B, d *Dilithium) {
	var msg [59]byte
	var seed [32]byte
	_, sk := d.KeyGen(seed[:])
	for n := 0; n < b.N; n++ {
		d.Sign(msg[:], sk)
	}
}

func benchmarkVerify(b *testing.B, d *Dilithium) {
	var msg [59]byte
	var seed [32]byte
	pk, sk := d.KeyGen(seed[:])
	sig := d.Sign(msg[:], sk)
	for n := 0; n < b.N; n++ {
		d.Verify(msg[:], sig, pk)
	}
}
