package dilithium

import (
	"bytes"
	cRand "crypto/rand"
	"io"
	"testing"

	"golang.org/x/crypto/sha3"
)

func TestKeyGen(t *testing.T) {
	d := NewDilithium2(false)
	K := d.params.K
	var seed [32]byte
	rand := cRand.Reader
	io.ReadFull(rand, seed[:])
	ppk, psk := d.KeyGen(seed[:])
	ppk2, psk2 := d.KeyGen(seed[:])
	pk, pk2, sk, sk2 := d.UnpackPK(ppk), d.UnpackPK(ppk2), d.UnpackSK(psk), d.UnpackSK(psk2)
	if pk.Rho != pk2.Rho || !pk.T1.equal(pk2.T1, K) {
		t.Fatal("KeyGen failed to reproduce")
	}
	if sk.Key != sk2.Key || sk.Rho != sk2.Rho || sk.Tr != sk2.Tr || !sk.S2.equal(sk2.S2, K) {
		t.Fatal("Key Gen failed to reproduce")
	}
	io.ReadFull(rand, seed[:])
	ppk3, psk3 := d.KeyGen(seed[:])
	pk3, sk3 := d.UnpackPK(ppk3), d.UnpackSK(psk3)
	if pk.Rho == pk3.Rho || pk.T1.equal(pk3.T1, K) {
		t.Fatal("KeyGen is repeating when it should not")
	}
	if sk.Key == sk3.Key || sk.Rho == sk3.Rho || sk.Tr == sk3.Tr || sk.S2.equal(sk3.S2, K) {
		t.Fatal("KeyGen is repeating when it should not")
	}
}

func TestSign(t *testing.T) {
	d := NewDilithium2(false)
	var seed [32]byte
	rand := cRand.Reader
	io.ReadFull(rand, seed[:])
	_, sk := d.KeyGen(seed[:])
	msg := []byte("Message to sign")
	sig := d.Sign(sk, msg)
	z, h, c := d.UnpackSig(sig)
	//var cNull Poly
	if z == nil || h == nil || c == nil { //}|| c.equal(cNull) {
		t.Fatal("sig failed")
	}
}

//Used for FA
func TestManySign(t *testing.T) {
	d := NewDilithium2(false)
	var seed [32]byte
	rand := cRand.Reader
	for i := 0; i < 1000; i++ {
		io.ReadFull(rand, seed[:])
		_, sk := d.KeyGen(seed[:])
		msg := []byte("Message to sign")
		sig := d.Sign(sk, msg)
		z, h, c := d.UnpackSig(sig)
		//var cNull Poly
		if z == nil || h == nil || c == nil { //}|| c.equal(cNull) {
			t.Fatal("sig failed")
		}
	}
}

func TestChallenge(t *testing.T) {

	d := NewDilithium3(false)
	K := d.params.K
	var key [32]byte
	var mu, mu2, rhoP [64]byte
	rand := cRand.Reader
	rand.Read(key[:])
	rand.Read(mu[:])
	rand.Read(mu2[:])
	rand.Read(rhoP[:])

	w, w2 := make(Vec, K), make(Vec, K)
	var nonce uint16
	for i := 0; i < K; i++ {
		w[i] = polyUniformGamma1(rhoP, nonce, d.params.GAMMA1)
		nonce++
	}
	for i := 0; i < K; i++ {
		w2[i] = polyUniformGamma1(rhoP, nonce, d.params.GAMMA1)
		nonce++
	}
	var hc [SEEDBYTES]byte
	state := sha3.NewShake256()
	state.Write(mu[:])
	state.Write(packW1(w, K, d.params.POLYSIZEW1, d.params.GAMMA2))
	state.Read(hc[:])
	state.Reset()
	c := challenge(hc[:], d.params.T)
	c1 := challenge(hc[:], d.params.T)

	state.Write(mu2[:])
	state.Write(packW1(w, K, d.params.POLYSIZEW1, d.params.GAMMA2))
	state.Read(hc[:])
	state.Reset()

	c2 := challenge(hc[:], d.params.T)

	state.Write(mu[:])
	state.Write(packW1(w2, K, d.params.POLYSIZEW1, d.params.GAMMA2))
	state.Read(hc[:])
	state.Reset()

	c3 := challenge(hc[:], d.params.T)

	if !c.equal(c1) {
		t.Fatal("challenge does not reprodux")
	}
	if c.equal(c2) || c.equal(c3) {
		t.Fatal("challenge repeats output")
	}
}

func TestVerify(t *testing.T) {
	d := NewDilithium2(false)
	var seed [32]byte
	rand := cRand.Reader
	io.ReadFull(rand, seed[:])
	pk, sk := d.KeyGen(seed[:])
	msg := []byte("Message to sign")
	sig := d.Sign(sk, msg)
	if !d.Verify(pk, msg, sig) {
		t.Fatal("Verify failed")
	}

}

func TestVerifAnotherMSG(t *testing.T) {
	d := NewDilithium2(false)
	var seed [32]byte
	rand := cRand.Reader
	io.ReadFull(rand, seed[:])
	pk, sk := d.KeyGen(seed[:])
	msg := []byte("Message to sign")
	sig := d.Sign(sk, msg)
	msg2 := []byte("Another message")
	if d.Verify(pk, msg2, sig) {
		t.Fatal("Signature verified on another msg")

	}
}

func TestPack(t *testing.T) {
	d := NewDilithium2(false)
	pk, sk := d.KeyGen(nil)
	pk2 := d.PackPK(d.UnpackPK(pk))
	sk2 := d.PackSK(d.UnpackSK(sk))
	if !bytes.Equal(pk[:], pk2[:]) {
		t.Fatal("Pack failed")
	}
	if !bytes.Equal(sk[:], sk2[:]) {
		t.Fatal("SK Pack failed")
	}
}

func TestRandomized(t *testing.T) {
	d := NewDilithium2()
	d2 := NewDilithium2(true)
	if d.params.RANDOMIZED+d2.params.RANDOMIZED != 2 {
		t.Fatal("Init did not work")
	}
	d3 := NewDilithium2(false)
	if d3.params.RANDOMIZED != 0 {
		t.Fatal("Init did not work")
	}
}

func TestBadSize(t *testing.T) {
	d := NewDilithium2()
	k := []byte("Hi")
	s := d.Sign(nil, k)
	if s != nil {
		t.Fatal("Sign accepts bad secret keys")
	}
	b := d.Verify(nil, nil, k)
	if b {
		t.Fatal("Verifies with wrong input")
	}
}

func TestYzero(t *testing.T) {
	d := NewDilithium3(false)
	K := d.params.K
	L := d.params.L

	var mu [2 * SEEDBYTES]byte
	cRand.Read(mu[:])

	var hc, zero, rho [SEEDBYTES]byte
	cRand.Read(rho[:])
	Ahat := expandSeed(rho, K, L)

	y := make(Vec, L)
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

	state := sha3.NewShake256()
	state.Write(mu[:])
	state.Write(packW1(w1, K, d.params.POLYSIZEW1, d.params.GAMMA2))
	state.Read(hc[:])
	state.Reset()

	state.Write(mu[:])
	state.Write(packW1(w0, K, d.params.POLYSIZEW1, d.params.GAMMA2))
	state.Read(zero[:])
	if !bytes.Equal(zero[:], hc[:]) {
		t.Fatal("We missed a fault")
	}
}
