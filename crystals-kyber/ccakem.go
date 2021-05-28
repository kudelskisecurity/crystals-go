package kyber

import (
	"crypto/rand"
	"crypto/subtle"

	"golang.org/x/crypto/sha3"
)

func (k *Kyber) KeyGen(seed []byte) ([]byte, []byte) {
	if seed == nil || len(seed) != SIZEZ+SEEDBYTES {
		seed = make([]byte, SIZEZ+SEEDBYTES)
		rand.Read(seed)
	}
	pk, skP := k.PKEKeyGen(seed[:SEEDBYTES])

	return pk, k.PackSK(&PrivateKey{SkP: skP, Pk: pk, Z: seed[SEEDBYTES:]})
}

func (k *Kyber) Encaps(packedPK, coins []byte) ([]byte, []byte) {
	if len(packedPK) != k.SIZEPK() {
		println("Public key does not have the correct size.")
		return nil, nil
	}
	if coins == nil || len(coins) != SEEDBYTES {
		coins = make([]byte, SEEDBYTES)
		rand.Read(coins)
	}
	var m, ss [32]byte
	hState := sha3.New256()
	hState.Write(coins)
	copy(m[:], hState.Sum(nil))

	hpk := make([]byte, 32)
	hState.Reset()
	hState.Write(packedPK)
	copy(hpk, hState.Sum(nil))

	var kr, kc [64]byte
	gState := sha3.New512()
	gState.Write(m[:])
	gState.Write(hpk)
	copy(kr[:], gState.Sum(nil))
	copy(kc[:32], kr[:32])

	c := k.Encrypt(packedPK, m[:], kr[32:])

	hState.Reset()
	hState.Write(c)
	copy(kc[32:], hState.Sum(nil))

	kdfState := sha3.NewShake256()
	kdfState.Write(kc[:])
	kdfState.Read(ss[:])
	return c, ss[:]
}

func (k *Kyber) Decaps(packedSK, c []byte) []byte {
	if len(c) != k.SIZEC() || len(packedSK) != k.SIZESK() {
		println("Cannot decapsulate, inputs do not have the correct size.")
		return nil
	}

	sk := k.UnpackSK(packedSK)
	m := k.Decrypt(sk.SkP, c)

	hpk := make([]byte, 32)
	hState := sha3.New256()
	hState.Write(sk.Pk)
	copy(hpk, hState.Sum(nil))

	var kr, kc [64]byte
	gState := sha3.New512()
	gState.Write(m)
	gState.Write(hpk)
	copy(kr[:], gState.Sum(nil))
	copy(kc[:], kr[:32])

	c2 := k.Encrypt(sk.Pk, m, kr[32:])
	hState.Reset()
	hState.Write(c2)
	copy(kc[32:], hState.Sum(nil))

	subtle.ConstantTimeCopy(1-subtle.ConstantTimeCompare(c, c2), kc[:32], sk.Z)

	var ss [32]byte
	kdfState := sha3.NewShake256()
	kdfState.Write(kc[:])
	kdfState.Read(ss[:])

	return ss[:]
}
