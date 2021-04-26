package dilithium

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"

	"golang.org/x/crypto/sha3"
)

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

	t, t1, t0 := make(Vec, K), make(Vec, K), make(Vec, K)
	for i := 0; i < K; i++ {
		t[i] = vecAccPointWise(Ahat[i], s1hat, L)
		t[i].reduce()
		t[i].invntt()
		t[i] = add(t[i], s2[i])
		t[i].addQ()
		t1[i], t0[i] = polyPower2Round(t[i])
	}
	state.Write(append(rho[:], packT1(t1, K)...))
	state.Read(tr[:])

	return d.PackPK(PublicKey{T1: t1, Rho: rho}), d.PackSK(PrivateKey{Rho: rho, Key: key, Tr: tr, S1: s1, S2: s2, T0: t0})
}

//Sign uses to PrivateKey to compute the signature om msg.
func (d *Dilithium) Sign(msg []byte, packedSK []byte) []byte {
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

	s1hat := sk.S1.copy() //what if we store the NTT transform in sk? sk.S1 isn't used
	//current PackS function is lossy on NTT(s1) because the coefs are too big - so does not work yet
	//Could remove the need for copy by changing the way we give sk (copy)
	s2hat := sk.S2.copy() //same question
	t0hat := sk.T0.copy() //same question
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
		z[i] = montMul(chat, s1hat[i])
		z[i].invntt() //can't we reverse, first Add yhat then invNTT?
		z[i] = add(z[i], y[i])
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

//Verify uses the public key to verify a dilithium signature on the msg
func (d *Dilithium) Verify(msg []byte, sig []byte, packedPK []byte) bool {
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

	t1hat := pk.T1.copy() //tmp2

	w1 := make(Vec, K)
	for i := 0; i < K; i++ {
		w1[i] = vecAccPointWise(Ahat[i], zhat, L)

		t1hat[i].shift()
		t1hat[i].ntt()
		t1hat[i] = montMul(chat, t1hat[i]) //ct1x2^d

		w1[i] = sub(w1[i], t1hat[i])
		w1[i].reduce()
		w1[i].invntt()
		w1[i].addQ() //Az-ct1x2^d
		w1[i] = polyUseHint(w1[i], h[i], d.params.GAMMA2)
	}
	var hc2 [SEEDBYTES]byte
	state.Write(mu[:])
	state.Write(packW1(w1, K, d.params.POLYSIZEW1, d.params.GAMMA2))
	state.Read(hc2[:])

	return z.vecIsBelow(d.params.GAMMA1-d.params.BETA, L) && bytes.Equal(hc, hc2[:]) && h.sum(K) <= d.params.OMEGA
}
