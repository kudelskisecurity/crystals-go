package dilithium

//Recommended parameters and constants.
const (
	n            = 256
	q            = 8380417  // 2²³ - 2¹³ + 1
	qInv         = 58728449 // -q^(-1) mod 2^32
	d            = 13
	polySizeT1   = 320
	polySizeT0   = 416
	shake128Rate = 168
	shake256Rate = 136

	SEEDBYTES         = 32
	Dilithium2SizePK  = 1312
	Dilihtium2SizeSK  = 2528
	Dilithium2SizeSig = 2420

	Dilithium3SizePK  = 1952
	Dilihtium3SizeSK  = 4000
	Dilithium3SizeSig = 3293

	Dilithium5SizePK  = 2592
	Dilihtium5SizeSK  = 4864
	Dilithium5SizeSig = 4595
)

type Dilithium struct {
	Name   string
	params *parameters
}

type parameters struct {
	T          int //sizec
	K          int
	L          int
	GAMMA1     int32
	GAMMA2     int32
	ETA        int32
	BETA       int32
	OMEGA      int
	POLYSIZES  int
	POLYSIZEZ  int //= (N * (QBITS - 3)) / 8
	POLYSIZEW1 int //= ((N * 4) / 8)
	SIZEPK     int //= K*POLYSIZE + SEEDBYTES
	SIZESK     int //= SIZEZ + 32 + SIZEPK + K*POLYSIZE
	SIZESIG    int
	RANDOMIZED int
	//SIZEPKEPK       int //= SIZEPK
}

func NewDilithium2(randomized ...bool) *Dilithium {
	r := 1 //randomized by default
	if len(randomized) == 1 && !randomized[0] {
		r = 0
	}
	return &Dilithium{
		Name: "Dilithium2",
		params: &parameters{
			T:          39,
			K:          4,
			L:          4,
			GAMMA1:     131072,
			GAMMA2:     (q - 1) / 88,
			ETA:        2,
			BETA:       78,
			OMEGA:      80,
			POLYSIZES:  96,  //POLYETA,
			POLYSIZEZ:  576, //POLYGAMMA1
			POLYSIZEW1: 192, //POLYGAMMA2
			RANDOMIZED: r,
			SIZEPK:     32 + 4*polySizeT1,
			SIZESK:     32 + 32 + 32 + 4*polySizeT0 + (4+4)*96,
			SIZESIG:    32 + 4*576 + 4 + 80,
		}}
}

func NewDilithium3(randomized ...bool) *Dilithium {
	r := 1 //randomized by default
	if len(randomized) == 1 && !randomized[0] {
		r = 0
	}
	return &Dilithium{
		Name: "Dilithium3",
		params: &parameters{
			T:          49,
			K:          6,
			L:          5,
			GAMMA1:     524288,
			GAMMA2:     (q - 1) / 32,
			ETA:        4,
			BETA:       196,
			OMEGA:      55,
			RANDOMIZED: r,
			POLYSIZES:  128, //POLYETA,
			POLYSIZEZ:  640, //POLYGAMMA1
			POLYSIZEW1: 128,
			SIZEPK:     32 + 6*polySizeT1,
			SIZESK:     32 + 32 + 32 + 6*polySizeT0 + (5+6)*128,
			SIZESIG:    32 + 5*640 + 6 + 55,
		}}
}

func NewDilithium5(randomized ...bool) *Dilithium {
	r := 1 //randomized by default
	if len(randomized) == 1 && !randomized[0] {
		r = 0
	}
	return &Dilithium{
		Name: "Dilithium5",
		params: &parameters{
			T:          60,
			K:          8,
			L:          7,
			GAMMA1:     524288,
			GAMMA2:     (q - 1) / 32,
			ETA:        2,
			BETA:       120,
			OMEGA:      75,
			POLYSIZES:  96,
			POLYSIZEZ:  640,
			POLYSIZEW1: 128,
			RANDOMIZED: r,
			SIZEPK:     32 + 8*polySizeT1,
			SIZESK:     32 + 32 + 32 + 8*polySizeT0 + (8+7)*96,
			SIZESIG:    32 + 7*640 + 8 + 75,
		}}
}

func NewDilithiumUnsafe(q, d, tau, gamma1, gamma2, k, l, eta, omega int) *Dilithium {
	return &Dilithium{
		Name:   "Custom Dilithium",
		params: &parameters{}}
}
