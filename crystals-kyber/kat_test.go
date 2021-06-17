package kyber

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

//helpers (see NIST's PQCgenKAT.c)
type randomBytes struct {
	key [32]byte
	v   [16]byte
}

func (g *randomBytes) incV() {
	for j := 15; j >= 0; j-- {
		if g.v[j] == 255 {
			g.v[j] = 0
		} else {
			g.v[j]++
			break
		}
	}
}

// AES256_CTR_randomBytes_update(pd, &g.key, &g.v)
func (g *randomBytes) randombyteUpdate(pd *[48]byte) {
	var buf [48]byte
	b, _ := aes.NewCipher(g.key[:])
	for i := 0; i < 3; i++ {
		g.incV()
		b.Encrypt(buf[i*16:(i+1)*16], g.v[:])
	}
	if pd != nil {
		for i := 0; i < 48; i++ {
			buf[i] ^= pd[i]
		}
	}
	copy(g.key[:], buf[:32])
	copy(g.v[:], buf[32:])
}

// randombyte_init(seed, NULL, 256)
func randombyteInit(seed *[48]byte) (g randomBytes) {
	g.randombyteUpdate(seed)
	return
}

// randombytes()
func (g *randomBytes) randombytes(x []byte) {
	var block [16]byte

	b, _ := aes.NewCipher(g.key[:])
	for len(x) > 0 {
		g.incV()
		b.Encrypt(block[:], g.v[:])
		if len(x) < 16 {
			copy(x[:], block[:len(x)])
			break
		}
		copy(x[:], block[:])
		x = x[16:]
	}
	g.randombyteUpdate(nil)
}

func TestKAT(t *testing.T) {
	/**
		GOLDEN_ZIP := "https://pq-crystals.org/kyber/data/kyber-submission-nist-round3.zip"
		os.Mkdir("testdata", 0755)
		cached := "testdata/" + path.Base(GOLDEN_ZIP)
		zipfile, err := zip.OpenReader(cached)
		if err != nil {
			t.Logf("Retrieving golden KAT zip from %s", GOLDEN_ZIP)
			resp, _ := http.Get(GOLDEN_ZIP)
			body, _ := ioutil.ReadAll(resp.Body)
			ioutil.WriteFile(cached, body, 0644)
			zipfile, _ = zip.OpenReader(cached)
			resp.Body.Close()
		}
		testKAT(t, zipfile, NewKyber512())
		testKAT(t, zipfile, NewKyber768())
		testKAT(t, zipfile, NewKyber1024())
	}
	**/

	testKAT(t, NewKyber512())
	testKAT(t, NewKyber768())
	testKAT(t, NewKyber1024())
}

func testKAT(t *testing.T, k *Kyber) {
	//	func testKAT(t *testing.T, zipfile *zip.ReadCloser, k *Kyber) {

	/**
	var katfile io.ReadCloser
		gotkat := false
		for _, f := range zipfile.File {
			goldenKAT := fmt.Sprintf("PQCkemKAT_%d.rsp", k.params.SIZESK)
			if strings.HasSuffix(f.Name, goldenKAT) {
				katfile, _ = f.Open()
				gotkat = true
				break
			}
		}
	**/
	goldenKAT := fmt.Sprintf("PQCkemKAT_%d.rsp", k.params.SIZESK)
	katfile, err := os.Open("testdata/" + goldenKAT)
	if err != nil {
		t.Fatal(err)
	}

	r := bufio.NewReader(katfile)

	smlen := 0
	mlen := 0
	//count := 0
	var seed [48]byte
	for i := 0; i < 48; i++ {
		seed[i] = byte(i) //entropy_input
	}
	kseed := make([]byte, 2*SEEDBYTES)
	eseed := make([]byte, SEEDBYTES)

	g := randombyteInit(&seed)
	opk, pk := make([]byte, k.SIZEPK()), make([]byte, k.SIZEPK())
	osk, sk := make([]byte, k.SIZESK()), make([]byte, k.SIZESK())
	var msg []byte
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		fields := strings.Split(line, " ")
		if len(fields) != 3 {
			continue
		}
		val := strings.TrimSpace(fields[2])
		bval := []byte(val)
		hval := make([]byte, hex.DecodedLen(len(bval)))
		hex.Decode(hval, bval)
		switch fields[0] {
		case "smlen":
			smlen, _ = strconv.Atoi(val)
		case "mlen":
			mlen, _ = strconv.Atoi(val)
		case "msg":
			if len(hval) != mlen {
				t.Fatal("mlen != len(msg)")
			}
			msg = hval
			_ = msg
		case "seed":
			{
				if len(hval) != 48 {
					t.Fatal("expected 48 byte seed")
				}
				g.randombytes(seed[:])
				g2 := randombyteInit(&seed)
				g2.randombytes(kseed[:32])
				g2.randombytes(kseed[32:])
				g2.randombytes(eseed)

				opk, osk = k.KeyGen(kseed[:])
			}
		case "sk":
			if len(hval) != k.params.SIZESK {
				t.Fatal("sk size mismatch")
			}
			if !bytes.Equal(osk[:], hval) {
				t.Fatal("sk mismatch")
			}
		case "pk":
			{
				if len(hval) != k.params.SIZEPK {
					t.Fatal("pk size mismatch")
				}
				if !bytes.Equal(opk[:], hval) {
					t.Fatal("pk mismatch")
				}
			}
		case "sm":
			if len(hval) != smlen {
				t.Fatal("smlen != len(sm)")
			}
			ct, ss := k.Encaps(eseed, pk)
			if !bytes.Equal(ss, hval) {
				t.Fatal("signed data mismatch")
			}
			if !bytes.Equal(k.Decaps(ct, sk), ss) {
				t.Fatal("failed to validate")
			}
		}
	}
}
