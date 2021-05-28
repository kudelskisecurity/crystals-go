package dilithium

import "crypto/subtle"

// PublicKey holds the pk struct.
type PublicKey struct {
	T1  Vec //K
	Rho [SEEDBYTES]byte
}

// PrivateKey holds the sk struct.
type PrivateKey struct {
	S1  Vec //L
	S2  Vec //K
	Rho [SEEDBYTES]byte
	Key [SEEDBYTES]byte
	Tr  [SEEDBYTES]byte
	T0  Vec //K
}

func (d *Dilithium) SIZEPK() int {
	return d.params.SIZEPK
}

func (d *Dilithium) SIZESK() int {
	return d.params.SIZESK
}

func (d *Dilithium) SIZESIG() int {
	return d.params.SIZESIG
}

//PackPK packs a PublicKey into an array of bytes.
func (d *Dilithium) PackPK(pk PublicKey) []byte {
	packedPK := make([]byte, d.params.SIZEPK)
	copy(packedPK[:SEEDBYTES], pk.Rho[:])
	copy(packedPK[SEEDBYTES:], packT1(pk.T1, d.params.K))
	return packedPK
}

//UnpackPK reverses the packing operation.
func (d *Dilithium) UnpackPK(packedPK []byte) PublicKey {
	var pk PublicKey
	copy(pk.Rho[:], packedPK[:SEEDBYTES])
	pk.T1 = unpackT1(packedPK[SEEDBYTES:], d.params.K)
	return pk
}

//PackSK packs a PrivateKey into a byte array.
func (d *Dilithium) PackSK(sk PrivateKey) []byte {
	packedSK := make([]byte, d.params.SIZESK)
	id := 0
	subtle.ConstantTimeCopy(1, packedSK[id:id+SEEDBYTES], sk.Rho[:])
	id += SEEDBYTES
	subtle.ConstantTimeCopy(1, packedSK[id:id+SEEDBYTES], sk.Key[:])
	id += SEEDBYTES
	subtle.ConstantTimeCopy(1, packedSK[id:id+SEEDBYTES], sk.Tr[:])
	id += SEEDBYTES
	L := d.params.L
	ETA := d.params.ETA
	POLYSIZES := d.params.POLYSIZES
	subtle.ConstantTimeCopy(1, packedSK[id:id+L*POLYSIZES], packS(sk.S1, L, POLYSIZES, ETA))
	id += L * POLYSIZES
	K := d.params.K
	subtle.ConstantTimeCopy(1, packedSK[id:id+K*POLYSIZES], packS(sk.S2, K, POLYSIZES, ETA))
	id += K * POLYSIZES
	subtle.ConstantTimeCopy(1, packedSK[id:], packT0(sk.T0, K))
	return packedSK
}

//PackSKNIST packs a PrivateKey into a byte array but reverses NTT of s1 before (not used for now).
func (d *Dilithium) PackSKNIST(sk PrivateKey) []byte {
	s1cpy := sk.S1
	s1cpy.invntt(d.params.L)
	return d.PackSK(PrivateKey{Key: sk.Key, Tr: sk.Tr, Rho: sk.Rho, T0: sk.T0, S2: sk.S2, S1: s1cpy})
}

//UnpackSK reverses the packing operation.
func (d *Dilithium) UnpackSK(packedSK []byte) PrivateKey {
	var sk PrivateKey
	id := 0
	subtle.ConstantTimeCopy(1, sk.Rho[:], packedSK[:SEEDBYTES])
	id += SEEDBYTES
	subtle.ConstantTimeCopy(1, sk.Key[:], packedSK[id:id+SEEDBYTES])
	id += SEEDBYTES
	subtle.ConstantTimeCopy(1, sk.Tr[:], packedSK[id:id+SEEDBYTES])
	id += SEEDBYTES
	L := d.params.L
	ETA := d.params.ETA
	POLYSIZES := d.params.POLYSIZES
	sk.S1 = unpackS(packedSK[id:id+L*POLYSIZES], L, POLYSIZES, ETA)
	id += L * POLYSIZES
	K := d.params.K
	sk.S2 = unpackS(packedSK[id:id+K*POLYSIZES], K, POLYSIZES, ETA)
	id += K * POLYSIZES
	sk.T0 = unpackT0(packedSK[id:], K)

	return sk
}
