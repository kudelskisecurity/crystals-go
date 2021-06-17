package kyber

// The first block of constants define internal parameters.
// SEEDBYTES holds the length in byte of the random number to give as input, if wanted.
// The remaining constants are exported to allow for fixed-length array instantiation.
// For a given security level, the consts are the same as the output of the k.SIZEX() functions defined in keys.go.
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

// Kyber struct defines the internal parameters to be used given a security level.
type Kyber struct {
	Name   string
	params *parameters
}

// parameters hold all internal varying parameters used in a kyber scheme.
type parameters struct {
	K         int
	ETA1      int
	DU        int
	DV        int
	sizePK    int // = K*POLYSIZE + SEEDBYTES
	sizeSK    int // = SIZEZ + 32 + sizePK + K*POLYSIZE
	sizePKESK int // = K * POLYSIZE
	sizeC     int
}

// NewKyber512 defines a kyber instance with a light security level.
func NewKyber512() *Kyber {
	return &Kyber{
		Name: "Kyber512",
		params: &parameters{
			K:         2,
			ETA1:      3,
			DU:        10,
			DV:        4,
			sizePK:    800,
			sizeSK:    1632,
			sizePKESK: 768,
			sizeC:     2*320 + 128,
		}}
}

// NewKyber768 defines a kyber instance with a medium security level.
func NewKyber768() *Kyber {
	return &Kyber{
		Name: "Kyber768",
		params: &parameters{
			K:         3,
			ETA1:      2,
			DU:        10,
			DV:        4,
			sizePK:    1184,
			sizeSK:    2400,
			sizePKESK: 1152,
			sizeC:     3*320 + 128,
		}}
}

// NewKyber1024 defines a kyber instance with a very high security level.
func NewKyber1024() *Kyber {
	return &Kyber{
		Name: "Kyber1024",
		params: &parameters{
			K:         4,
			ETA1:      2,
			DU:        11,
			DV:        5,
			sizePK:    1568,
			sizeSK:    3168,
			sizePKESK: 1536,
			sizeC:     4*352 + 160,
		}}
}

// NewKyberUnsafe is a skeleton function to be used for research purposes when wanting to use a kyber instance with parameters that differ from the recommended ones.
func NewKyberUnsafe(n, k, q, eta1, et2, du, dv int) *Kyber {
	return &Kyber{
		Name:   "Custom Kyber",
		params: &parameters{},
	}
}
