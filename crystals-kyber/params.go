package kyber

// const K = 2 //change this to 2,3 or 4 to get Kyber512, 768 or 1012

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
	Kyber512SizeC     = 768 // 2*320 + 128

	Kyber768SizePK    = 1184
	Kyber768SizeSK    = 2400
	Kyber768SizePKESK = 1152
	Kyber768SizeC     = 1088 // 3*320 + 128

	Kyber1024SizePK    = 1568
	Kyber1024SizeSK    = 3168
	Kyber1024SizePKESK = 1536
	Kyber1024SizeC     = 1568 // 4*352 + 160
)

type Kyber struct {
	Name   string
	params *parameters
}

type parameters struct {
	K              int
	ETA1           int
	DU             int
	DV             int
	compPolysizeDU int
	compPolysizeDV int
	sizePK         int // = K*POLYSIZE + SEEDBYTES
	sizeSK         int // = SIZEZ + 32 + sizePK + K*POLYSIZE
	sizePKESK      int // = K * POLYSIZE
	sizeC          int
	// SIZEPKEPK       int //= sizePK
}

func NewKyber512() *Kyber {
	return &Kyber{
		Name: "Kyber512",
		params: &parameters{
			K:              2,
			ETA1:           3,
			DU:             10,
			DV:             4,
			compPolysizeDU: 320,
			compPolysizeDV: 128,
			sizePK:         800,
			sizeSK:         1632,
			sizePKESK:      768,
			sizeC:          2*320 + 128,
		}}
}

func NewKyber768() *Kyber {
	return &Kyber{
		Name: "Kyber768",
		params: &parameters{
			K:              3,
			ETA1:           2,
			DU:             10,
			DV:             4,
			compPolysizeDU: 320,
			compPolysizeDV: 128,
			sizePK:         1184,
			sizeSK:         2400,
			sizePKESK:      1152,
			sizeC:          3*320 + 128,
		}}
}

func NewKyber1024() *Kyber {
	return &Kyber{
		Name: "Kyber1024",
		params: &parameters{
			K:              4,
			ETA1:           2,
			DU:             11,
			DV:             5,
			compPolysizeDU: 352,
			compPolysizeDV: 160,
			sizePK:         1568,
			sizeSK:         3168,
			sizePKESK:      1536,
			sizeC:          4*352 + 160,
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
