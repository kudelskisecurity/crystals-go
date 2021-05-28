package kyber

import (
	"crypto/rand"

	"golang.org/x/crypto/sha3"
)

func (k *Kyber) PKEKeyGen(seed []byte) ([]byte, []byte) {
	if seed == nil || len(seed) != SEEDBYTES {
		seed = make([]byte, SEEDBYTES)
		rand.Read(seed)
	}

	K := k.params.K
	ETA1 := k.params.ETA1

	var rho, sseed [SEEDBYTES]byte
	state := sha3.New512()
	state.Write(seed)
	hash := state.Sum(nil)
	copy(rho[:], hash[:32])
	copy(sseed[:], hash[32:])

	Ahat := expandSeed(rho[:], false, K)

	// var shat Vec
	shat := make(Vec, K)
	for i := 0; i < K; i++ {
		shat[i] = polyGetNoise(ETA1, sseed[:], byte(i))
		shat[i].ntt()
		shat[i].reduce()
	}

	ehat := make(Vec, K)
	for i := 0; i < K; i++ {
		ehat[i] = polyGetNoise(ETA1, sseed[:], byte(i+K))
		ehat[i].ntt()
	}

	t := make(Vec, K)
	for i := 0; i < K; i++ {
		t[i] = vecPointWise(Ahat[i], shat, K)
		t[i].toMont()
		t[i] = add(t[i], ehat[i])
		t[i].reduce()
	}

	return k.PackPK(&PublicKey{T: t, Rho: rho[:]}), k.PackPKESK(&PKEPrivateKey{S: shat})
}

func (k *Kyber) Encrypt(packedPK, msg, r []byte) []byte {

	if len(msg) < n/8 {
		println("Message is too short to be encrypted.")
		return nil
	}

	if len(packedPK) != k.SIZEPK() {
		println("Cannot encrypt with this public key.")
		return nil
	}

	if len(r) != SEEDBYTES {
		r = make([]byte, SEEDBYTES)
		rand.Read(r)
	}

	K := k.params.K
	pk := k.UnpackPK(packedPK)
	Ahat := expandSeed(pk.Rho, true, K)

	// var sp, ep Vec
	sp := make(Vec, K)
	for i := 0; i < K; i++ {
		sp[i] = polyGetNoise(k.params.ETA1, r, byte(i)) // use i
		sp[i].ntt()
		sp[i].reduce()
	}
	ep := make(Vec, K)
	for i := 0; i < K; i++ {
		ep[i] = polyGetNoise(eta2, r, byte(i+K))
		ep[i].ntt()
	}
	epp := polyGetNoise(eta2, r, byte(2*K))
	epp.ntt()

	// var u Vec
	u := make(Vec, K)
	for i := 0; i < K; i++ {
		u[i] = vecPointWise(Ahat[i], sp, K)
		u[i].toMont()
		u[i] = add(u[i], ep[i])
		u[i].invntt()
		u[i].reduce()
		u[i].fromMont()
	}

	m := polyFromMsg(msg)
	m.ntt()

	v := vecPointWise(pk.T, sp, K)
	v.toMont()
	v = add(v, epp)
	v = add(v, m)
	v.invntt()
	v.reduce()
	v.fromMont()

	c := make([]byte, k.params.SIZEC)
	copy(c, u.compress(k.params.DU, k.params.COMPPOLYSIZE_DU, K))
	copy(c[K*k.params.COMPPOLYSIZE_DU:], v.compress(k.params.DV, k.params.COMPPOLYSIZE_DV))
	return c
}

func (k *Kyber) Decrypt(packedSK, c []byte) []byte {
	if len(c) != k.SIZEC() || len(packedSK) != k.SIZEPKESK() {
		println("Cannot decrypt, inputs do not have correct size.")
		return nil
	}
	sk := k.UnpackPKESK(packedSK)
	K := k.params.K
	COMPPOLYSIZE_DU := k.params.COMPPOLYSIZE_DU
	uhat := decompressVec(c[:K*COMPPOLYSIZE_DU], k.params.DU, COMPPOLYSIZE_DU, K)
	uhat.ntt(K)
	v := decompressPoly(c[K*COMPPOLYSIZE_DU:], k.params.DV)
	v.ntt()

	m := vecPointWise(sk.S, uhat, K)
	m.toMont()
	m = sub(v, m)
	m.invntt()
	m.reduce()
	m.fromMont()

	return polyToMsg(m)
}
