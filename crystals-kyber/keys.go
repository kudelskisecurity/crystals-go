package kyber

import (
	"crypto/subtle"

	"golang.org/x/crypto/sha3"
)

// PublicKey holds the pk struct.
type PublicKey struct {
	T   Vec    // NTT(t)
	Rho []byte // 32
}

// PKEPrivateKey holds the ak strct for Kyber's PKE scheme.
type PKEPrivateKey struct {
	S Vec // NTT(s)
}

// PrivateKey holds the sk struct.
type PrivateKey struct {
	Z   []byte
	SkP []byte
	Pk  []byte
}

// SIZEPK returns the size in bytes of the public key of a kyber instance.
func (k *Kyber) SIZEPK() int {
	return k.params.sizePK
}

// SIZESK returns the size in bytes of the secret key of a kyber instance.
func (k *Kyber) SIZESK() int {
	return k.params.sizeSK
}

// SIZEPKESK returns the size in bytes of the PKE secret key of a kyber instance.
func (k *Kyber) SIZEPKESK() int {
	return k.params.sizePKESK
}

// SIZEC returns the size in bytes of the ciphertext of a kyber instance.
func (k *Kyber) SIZEC() int {
	return k.params.sizeC
}

// PackPK packs a PublicKey into an array of bytes.
func (k *Kyber) PackPK(pk *PublicKey) []byte {
	ppk := make([]byte, k.params.sizePK)
	copy(ppk, pack(pk.T, k.params.K))
	copy(ppk[k.params.K*polysize:], pk.Rho)
	return ppk
}

// UnpackPK reverses the packing operation and outputs a PublicKey struct.
func (k *Kyber) UnpackPK(packedPK []byte) *PublicKey {
	if len(packedPK) != k.params.sizePK {
		println("cannot unpack this public key")
		return nil
	}
	return &PublicKey{Rho: packedPK[k.params.K*polysize:], T: unpack(packedPK, k.params.K)}
}

// PackPKESK packs a PKE PrivateKey into a byte array.
func (k *Kyber) PackPKESK(sk *PKEPrivateKey) []byte {
	psk := make([]byte, k.params.sizePKESK)
	copy(psk, pack(sk.S, k.params.K))
	return psk
}

// UnpackPKESK reverses the packing operation and outputs a PKEPrivateKey struct.
func (k *Kyber) UnpackPKESK(psk []byte) *PKEPrivateKey {
	if len(psk) != k.params.sizePKESK {
		println("cannot unpack this private key")
		return nil
	}
	return &PKEPrivateKey{S: unpack(psk, k.params.K)}
}

// PackSK packs a PrivateKey into a byte array.
func (k *Kyber) PackSK(sk *PrivateKey) []byte {
	psk := make([]byte, k.params.sizeSK)
	id := 0
	K := k.params.K
	subtle.ConstantTimeCopy(1, psk[id:id+K*polysize], sk.SkP)
	id += K * polysize
	hpk := sk.Pk
	copy(psk[id:], hpk)
	id += k.params.sizePK
	hState := sha3.New256()
	hState.Write(hpk)
	copy(psk[id:id+32], hState.Sum(nil))
	id += 32
	subtle.ConstantTimeCopy(1, psk[id:id+32], sk.Z)
	return psk
}

// UnpackSK reverses the packing operation and outputs a PrivateKey struct.
func (k *Kyber) UnpackSK(psk []byte) *PrivateKey {
	if len(psk) != k.params.sizeSK {
		println("cannot unpack this private key")
		return nil
	}
	SIZEPKESK := k.params.sizePKESK
	SIZEPK := k.params.sizePK
	return &PrivateKey{Z: psk[SIZEPKESK+SIZEPK : SIZEPKESK+SIZEPK+32], SkP: psk[:SIZEPKESK], Pk: psk[SIZEPKESK : SIZEPKESK+SIZEPK]}
}
