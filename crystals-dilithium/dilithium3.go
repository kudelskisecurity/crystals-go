package dilithium

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"

	"golang.org/x/crypto/sha3"
)

//KeyGen creates a public and private key pair.
//A 32 byte long seed can be given as argument. If a nil seed is given, the seed is generated using Go crypto's random number generator.
//The keys returned are packed into byte arrays.
func (d *Dilithium) KeyGen(seed []byte) ([]byte, []byte) {

	if seed == nil || len(seed) != SEEDBYTES {
		seed = make([]byte, SEEDBYTES)
		rand.Read(seed)
	}

	var tr, rho, key [SEEDBYTES]byte
	var rhoprime [2 * SEEDBYTES]byte

	state := sha3.NewShake256()
	state.Write(seed)
	state.Read(rho[:])
	state.Read(rhoprime[:])
	state.Read(key[:])
	state.Reset()

	K := d.params.K
	L := d.params.L
	ETA := d.params.ETA

	Ahat := expandSeed(rho, K, L)

	s1 := make(Vec, L)
	for i := 0; i < L; i++ {
		s1[i] = polyUniformEta(rhoprime, uint16(i), ETA)
	}
	s2 := make(Vec, K)
	for i := 0; i < K; i++ {
		s2[i] = polyUniformEta(rhoprime, uint16(i+L), ETA)
	}
	s1hat := s1.copy()
	s1hat.ntt(L)
	s2hat := s2.copy()
	s2hat.ntt(K)

	t, t1, t0 := make(Vec, K), make(Vec, K), make(Vec, K)
	for i := 0; i < K; i++ {
		t[i] = vecAccPointWise(Ahat[i], s1hat, L)
		s2hat[i].tomont()
		t[i] = add(t[i], s2hat[i])
		t[i].invntt()
		t[i].addQ()
		t1[i], t0[i] = polyPower2Round(t[i])
	}
	state.Write(append(rho[:], packT1(t1, K)...))
	state.Read(tr[:])

	return d.PackPK(PublicKey{T1: t1, Rho: rho}), d.PackSK(PrivateKey{Rho: rho, Key: key, Tr: tr, S1: s1, S2: s2, T0: t0})
}

//Sign produces a signature on the given msg using the secret signing key.
//The signing key must be given as packed byte array.
//The message should also be a byte array.
//The returned signature is packed into a byte array. If an error occurs during the signature process, a nil signature is returned.
func (d *Dilithium) Sign(packedSK, msg []byte) []byte {
	if len(packedSK) != d.SIZESK() {
		println("Cannot sign with this key.")
		return nil
	}
	K := d.params.K
	L := d.params.L
	BETA := d.params.BETA

	sk := d.UnpackSK(packedSK)
	Ahat := expandSeed(sk.Rho, K, L)

	var mu [2 * SEEDBYTES]byte
	state := sha3.NewShake256()
	state.Write(sk.Tr[:])
	state.Write(msg)
	state.Read(mu[:])
	state.Reset()

	var rhoP, rhoPRand [2 * SEEDBYTES]byte
	state.Write(append(sk.Key[:], mu[:]...))
	state.Read(rhoP[:])
	state.Reset()

	rand.Read(rhoPRand[:])
	subtle.ConstantTimeCopy(d.params.RANDOMIZED, rhoP[:], rhoPRand[:])

	s1hat := sk.S1.copy()
	s2hat := sk.S2.copy()
	t0hat := sk.T0.copy()
	s1hat.ntt(L)
	s2hat.ntt(K)
	t0hat.ntt(K)

	var nonce uint16
	y, z := make(Vec, L), make(Vec, L)
	var c Poly

rej:
	if nonce > 500 { //Failing after 500 trials happens with probability close to 2^(-128).
		println("Sign ran out of trials.")
		return nil
	}

	for i := 0; i < L; i++ {
		y[i] = polyUniformGamma1(rhoP, nonce, d.params.GAMMA1)
		nonce++
	}

	yhat := y.copy()
	yhat.ntt(L)

	w, w1, w0 := make(Vec, K), make(Vec, K), make(Vec, K)
	for i := 0; i < K; i++ {
		w[i] = vecAccPointWise(Ahat[i], yhat, L)
		w[i].reduce()
		w[i].invntt()
		w[i].addQ()
		w1[i], w0[i] = polyDecompose(w[i], d.params.GAMMA2)
	}

	var hc, zero [SEEDBYTES]byte
	state.Write(mu[:])
	state.Write(packW1(w1, K, d.params.POLYSIZEW1, d.params.GAMMA2))
	state.Read(hc[:])
	state.Reset()

	state.Write(mu[:])
	state.Write(packW1(w0, K, d.params.POLYSIZEW1, d.params.GAMMA2))
	state.Read(zero[:])
	if bytes.Equal(zero[:], hc[:]) {
		return nil
	}
	state.Reset()

	c = challenge(hc[:], d.params.T)

	chat := c
	chat.ntt()

	for i := 0; i < L; i++ {
		yhat[i].tomont()
		z[i] = montMul(chat, s1hat[i])
		z[i] = add(z[i], yhat[i])
		z[i].invntt()
		z[i].reduce()
	}
	if !z.vecIsBelow(d.params.GAMMA1-BETA, L) {
		goto rej
	}

	wcs2 := make(Vec, K)
	for i := 0; i < K; i++ {
		wcs2[i] = montMul(chat, s2hat[i])
		wcs2[i].invntt()
		wcs2[i] = sub(w0[i], wcs2[i])
		wcs2[i].reduce()
	}

	if !wcs2.vecIsBelow(d.params.GAMMA2-BETA, K) {
		goto rej
	}

	ct0 := make(Vec, K)
	for i := 0; i < K; i++ {
		ct0[i] = montMul(chat, t0hat[i])
		ct0[i].invntt()
		ct0[i].reduce()
	}

	if !ct0.vecIsBelow(d.params.GAMMA2, K) {
		goto rej
	}

	wcs2 = vecAdd(wcs2, ct0, K)
	h, n := vecMakeHint(w1, wcs2, K, d.params.GAMMA2)
	if n > d.params.OMEGA {
		goto rej
	}
	return d.PackSig(z, h, hc[:])
}

//Verify uses the verification key to verify a signature given a msg.
//The public key and signature must be given as packed byte arrays.
//The message should be a byte array.
//The result of the verificatino is returned as a boolean, true is the verificatino succeeded, false otherwise.
//If an error occurs during the verification, a false is returned.
func (d *Dilithium) Verify(packedPK, msg, sig []byte) bool {
	if len(sig) != d.SIZESIG() || len(packedPK) != d.SIZEPK() {
		return false
	}

	K := d.params.K
	L := d.params.L

	pk := d.UnpackPK(packedPK)
	z, h, hc := d.UnpackSig(sig)

	c := challenge(hc[:], d.params.T)
	Ahat := expandSeed(pk.Rho, K, L)
	var tr [SEEDBYTES]byte
	var mu [2 * SEEDBYTES]byte
	state := sha3.NewShake256()
	state.Write(append(pk.Rho[:], packT1(pk.T1, K)...))
	state.Read(tr[:])
	state.Reset()

	state.Write(tr[:])
	state.Write(msg)
	state.Read(mu[:])
	state.Reset()

	zhat := z.copy()
	zhat.ntt(L)

	chat := c
	chat.ntt()

	t1hat := pk.T1.copy()

	w1 := make(Vec, K)
	for i := 0; i < K; i++ {
		w1[i] = vecAccPointWise(Ahat[i], zhat, L)

		t1hat[i].shift()
		t1hat[i].ntt()
		t1hat[i] = montMul(chat, t1hat[i])

		w1[i] = sub(w1[i], t1hat[i])
		w1[i].reduce()
		w1[i].invntt()
		w1[i].addQ()
		w1[i] = polyUseHint(w1[i], h[i], d.params.GAMMA2)
	}
	var hc2 [SEEDBYTES]byte
	state.Write(mu[:])
	state.Write(packW1(w1, K, d.params.POLYSIZEW1, d.params.GAMMA2))
	state.Read(hc2[:])

	return z.vecIsBelow(d.params.GAMMA1-d.params.BETA, L) && bytes.Equal(hc, hc2[:]) && h.sum(K) <= d.params.OMEGA
}
