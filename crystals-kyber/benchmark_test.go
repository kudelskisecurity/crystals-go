package kyber

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

var nbits = 3072

func BenchmarkRSA(b *testing.B) {
	for n := 0; n < b.N; n++ {
		rsa.GenerateKey(rand.Reader, nbits)
	}
}

func BenchmarkRSAEnc(b *testing.B) {
	sk, _ := rsa.GenerateKey(rand.Reader, nbits)
	var msg [50]byte
	rand.Read(msg[:])
	for n := 0; n < b.N; n++ {
		rsa.EncryptOAEP(sha256.New(), rand.Reader, &sk.PublicKey, msg[:], nil)
	}
}

func BenchmarkRSADec(b *testing.B) {
	sk, _ := rsa.GenerateKey(rand.Reader, nbits)
	var msg [50]byte
	rand.Read(msg[:])
	c, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &sk.PublicKey, msg[:], nil)
	for n := 0; n < b.N; n++ {
		rsa.DecryptOAEP(sha256.New(), rand.Reader, sk, c, nil)
	}
}

func BenchmarkPKEKeyGen512(b *testing.B) { benchmarkPKEKeyGen(b, NewKyber512()) }
func BenchmarkEncrypt512(b *testing.B)   { benchmarkEncrypt(b, NewKyber512()) }
func BenchmarkDecrypt512(b *testing.B)   { benchmarkDecrypt(b, NewKyber512()) }
func BenchmarkKeyGen512(b *testing.B)    { benchmarkKeyGen(b, NewKyber512()) }
func BenchmarkEncaps512(b *testing.B)    { benchmarkEncaps(b, NewKyber512()) }
func BenchmarkDecaps512(b *testing.B)    { benchmarkDecaps(b, NewKyber512()) }

func BenchmarkPKEKeyGen768(b *testing.B) { benchmarkPKEKeyGen(b, NewKyber768()) }
func BenchmarkEncrypt768(b *testing.B)   { benchmarkEncrypt(b, NewKyber768()) }
func BenchmarkDecrypt768(b *testing.B)   { benchmarkDecrypt(b, NewKyber768()) }
func BenchmarkKeyGen768(b *testing.B)    { benchmarkKeyGen(b, NewKyber768()) }
func BenchmarkEncaps768(b *testing.B)    { benchmarkEncaps(b, NewKyber768()) }
func BenchmarkDecaps768(b *testing.B)    { benchmarkDecaps(b, NewKyber768()) }

func BenchmarkPKEKeyGen1024(b *testing.B) { benchmarkPKEKeyGen(b, NewKyber1024()) }
func BenchmarkEncrypt1024(b *testing.B)   { benchmarkEncrypt(b, NewKyber1024()) }
func BenchmarkDecrypt1024(b *testing.B)   { benchmarkDecrypt(b, NewKyber1024()) }
func BenchmarkKeyGen1024(b *testing.B)    { benchmarkKeyGen(b, NewKyber1024()) }
func BenchmarkEncaps1024(b *testing.B)    { benchmarkEncaps(b, NewKyber1024()) }
func BenchmarkDecaps1024(b *testing.B)    { benchmarkDecaps(b, NewKyber1024()) }

func benchmarkPKEKeyGen(b *testing.B, k *Kyber) {
	var seed [32]byte
	for n := 0; n < b.N; n++ {
		k.PKEKeyGen(seed[:])
	}
}

func benchmarkEncrypt(b *testing.B, k *Kyber) {
	pk := make([]byte, k.SIZEPK())
	var r [32]byte
	msg := []byte("Very random message to sign in the benchmark")
	for n := 0; n < b.N; n++ {
		k.Encrypt(pk, msg, r[:])
	}
}

func benchmarkDecrypt(b *testing.B, k *Kyber) {
	sk := make([]byte, k.SIZEPKESK())
	c := make([]byte, k.SIZEC())
	for n := 0; n < b.N; n++ {
		k.Decrypt(sk, c)
	}
}

func benchmarkKeyGen(b *testing.B, k *Kyber) {
	var seed [SIZEZ + SEEDBYTES]byte
	for n := 0; n < b.N; n++ {
		k.KeyGen(seed[:])
	}
}
func benchmarkEncaps(b *testing.B, k *Kyber) {
	pk := make([]byte, k.SIZEPK())
	var r [SEEDBYTES]byte
	for n := 0; n < b.N; n++ {
		k.Encaps(pk, r[:])
	}
}

func benchmarkDecaps(b *testing.B, k *Kyber) {
	sk := make([]byte, k.SIZESK())
	c := make([]byte, k.SIZEC())
	for n := 0; n < b.N; n++ {
		k.Decaps(sk, c)
	}
}
