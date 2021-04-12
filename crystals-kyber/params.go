package kyber

//const K = 2 //change this to 2,3 or 4 to get Kyber512, 768 or 1012

const (
	n            = 256
	q            = 3329
	qInv         = 62209
	eta2         = 2
	shake128Rate = 168
	polysize     = 384

	SIZEZ             = 32
	SEEDBYTES         = 32
	Kyber512SizePK    = 800
	Kyber512SizeSK    = 1632
	Kyber512SizePKESK = 768
	Kyber512SizeC     = 768 //2*320 + 128

	Kyber768SizePK    = 1184
	Kyber768SizeSK    = 2400
	Kyber768SizePKESK = 1152
	Kyber768SizeC     = 1088 //3*320 + 128

	Kyber1024SizePK    = 1568
	Kyber1024SizeSK    = 3168
	Kyber1024SizePKESK = 1536
	Kyber1024SizeC     = 1568 //4*352 + 160
)

type Kyber struct {
	Name   string
	params *parameters
}

type parameters struct {
	K               int
	ETA1            int
	DU              int
	DV              int
	COMPPOLYSIZE_DU int
	COMPPOLYSIZE_DV int
	SIZEPK          int //= K*POLYSIZE + SEEDBYTES
	SIZESK          int //= SIZEZ + 32 + SIZEPK + K*POLYSIZE
	SIZEPKESK       int //= K * POLYSIZE
	SIZEC           int
	//SIZEPKEPK       int //= SIZEPK
}

func NewKyber512() *Kyber {
	return &Kyber{
		Name: "Kyber512",
		params: &parameters{
			K:               2,
			ETA1:            3,
			DU:              10,
			DV:              4,
			COMPPOLYSIZE_DU: 320,
			COMPPOLYSIZE_DV: 128,
			SIZEPK:          800,
			SIZESK:          1632,
			SIZEPKESK:       768,
			SIZEC:           2*320 + 128,
		}}
}

func NewKyber768() *Kyber {
	return &Kyber{
		Name: "Kyber768",
		params: &parameters{
			K:               3,
			ETA1:            2,
			DU:              10,
			DV:              4,
			COMPPOLYSIZE_DU: 320,
			COMPPOLYSIZE_DV: 128,
			SIZEPK:          1184,
			SIZESK:          2400,
			SIZEPKESK:       1152,
			SIZEC:           3*320 + 128,
		}}
}

func NewKyber1024() *Kyber {
	return &Kyber{
		Name: "Kyber1024",
		params: &parameters{
			K:               4,
			ETA1:            2,
			DU:              11,
			DV:              5,
			COMPPOLYSIZE_DU: 352,
			COMPPOLYSIZE_DV: 160,
			SIZEPK:          1568,
			SIZESK:          3168,
			SIZEPKESK:       1536,
			SIZEC:           4*352 + 160,
		}}
}

/**
func NewKyberUnsafe(n, k, q, eta1, et2, du, dv int) *Kyber {
	return &Kyber{
		Name:"Custom Kyber",
		params: &parameters{}
	}
}
**/
