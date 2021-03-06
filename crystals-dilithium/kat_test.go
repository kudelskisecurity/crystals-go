package dilithium

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

// See NIST's PQCgenKAT.c.
type DRBG struct {
	key [32]byte
	v   [16]byte
}

func (g *DRBG) incV() {
	for j := 15; j >= 0; j-- {
		if g.v[j] == 255 {
			g.v[j] = 0
		} else {
			g.v[j]++
			break
		}
	}
}

// AES256_CTR_DRBG_Update(pd, &g.key, &g.v)
func (g *DRBG) update(pd *[48]byte) {
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
func NewDRBG(seed *[48]byte) (g DRBG) {
	g.update(seed)
	return
}

// randombytes()
func (g *DRBG) Fill(x []byte) {
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
	g.update(nil)
}

func TestKAT(t *testing.T) {
	testKAT(t, NewDilithium2(false), "Dilithium2")
	testKAT(t, NewDilithium3(false), "Dilithium3")
	testKAT(t, NewDilithium5(false), "Dilithium5")
}

func testKAT(t *testing.T, d *Dilithium, name string) {

	goldenKAT := fmt.Sprintf("PQCsignKAT_%s.rsp", name)
	/**
	GOLDEN_ZIP := "https://pq-crystals.org/dilithium/data/dilithium-submission-nist-round3.zip"
	os.Mkdir("testdata", 0755)
	cached := "testdata/" + path.Base(GOLDEN_ZIP)
	zipfile, err := zip.OpenReader(cached)
	if err != nil {
		t.Logf("Retrieving golden KAT zip from %s", GOLDEN_ZIP)
		resp, _ := http.Get(GOLDEN_ZIP)
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		ioutil.WriteFile(cached, body, 0644)
		zipfile, _ = zip.OpenReader(cached)
	}
	if d.params.RANDOMIZED == 0 {
		goldenKAT = fmt.Sprintf("PQCsignKAT_impldeter%d.rsp", d.SIZESK())
	}

	var katfile io.ReadCloser
	gotkat := false
	for _, f := range zipfile.File {
		if strings.HasSuffix(f.Name, goldenKAT) {
			katfile, _ = f.Open()
			gotkat = true
			break
		}
	}
	if !gotkat {
		t.Fatalf("no file names %s\n", goldenKAT)
	}**/
	katfile, err := os.Open("testdata/" + goldenKAT)
	if err != nil {
		t.Fatal(err)
	}

	r := bufio.NewReader(katfile)

	smlen := 0
	mlen := 0
	count := 0
	pk := make([]byte, d.SIZEPK())
	sk := make([]byte, d.SIZESK())
	var msg []byte

	var seed [48]byte
	for i := 0; i < 48; i++ {
		seed[i] = byte(i) //entropy_input
	}

	//randombytes_init(entropy_input, NULL, 256);
	g := NewDRBG(&seed)
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
		case "count":
			count, _ = strconv.Atoi(val)
		case "seed":
			{
				if len(hval) != 48 {
					t.Fatal("expected 48 byte seed")
				}
				g.Fill(seed[:])
				if !bytes.Equal(seed[:], hval[:]) {
					t.Fatal("Seed not well crafted")
				}
				g2 := NewDRBG(&seed)
				var extSeed [32]byte
				g2.Fill(extSeed[:])
				pk, sk = d.KeyGen(extSeed[:])
			}
		case "mlen":
			mlen, _ = strconv.Atoi(val)
			if mlen != 33*(count+1) {
				t.Fatal("mlen != 33*(i+1)")
			}
			msg = make([]byte, mlen)
			g.Fill(msg[:])
		case "msg":
			if len(hval) != mlen {
				t.Fatal("mlen != len(msg)")
			}
			if !bytes.Equal(msg[:], hval[:]) {
				t.Fatal("Msg is not correct")
			}
		case "pk":
			{
				if len(hval) != d.params.SIZEPK {
					t.Fatal("pk size mismatch")
				}
				if !bytes.Equal(pk[:], hval[:]) {
					t.Fatal("pk mismatch")
				}
			}
		case "sk":
			if len(hval) != d.params.SIZESK {
				t.Fatal("sk size mismatch")
			}
			if !bytes.Equal(sk[:], hval[:]) {
				t.Fatal("sk mismatch")
			}
		case "smlen":
			smlen, _ = strconv.Atoi(val)
			if smlen != mlen+d.params.SIZESIG {
				fmt.Printf("smlen: %d vs %d\n", smlen, mlen+d.params.SIZESIG)
				t.Fatal("smlen != mlen + sig_size")
			}
		case "sm":
			if len(hval) != smlen {
				fmt.Printf("smlen: %d vs %d\n", smlen, len(hval))
				t.Fatal("smlen != len(sm)")
			}
			sig := d.Sign(sk, msg)
			if !bytes.Equal(append(sig, msg...), hval) {
				t.Fatal("signature mismatch")
			}
			if !d.Verify(pk, msg, sig) {
				t.Fatal("failed to validate")
			}
			//println("one iter ok")
		}
	}
}

func TestInterOp(t *testing.T) {
	pk := []byte{28, 14, 225, 17, 27, 8, 0, 63, 40, 230, 94, 139, 59, 222, 176, 55, 207, 143, 34, 29, 252, 218, 245, 149, 14, 219, 56, 213, 6, 216, 91, 239, 97, 119, 227, 222, 13, 79, 30, 245, 132, 119, 53, 148, 123, 86, 208, 142, 132, 29, 178, 68, 79, 162, 183, 41, 173, 235, 20, 23, 202, 122, 223, 66, 161, 73, 12, 90, 9, 127, 0, 39, 96, 193, 252, 65, 155, 232, 50, 90, 173, 1, 151, 197, 44, 237, 128, 211, 223, 24, 231, 119, 66, 101, 178, 137, 145, 44, 236, 161, 190, 58, 144, 216, 164, 253, 230, 92, 132, 198, 16, 134, 78, 71, 222, 236, 174, 62, 234, 68, 48, 185, 144, 149, 89, 64, 141, 17, 166, 171, 219, 125, 185, 51, 109, 247, 249, 110, 171, 72, 100, 166, 87, 151, 145, 38, 95, 165, 108, 52, 140, 183, 210, 221, 201, 14, 19, 58, 149, 195, 246, 177, 54, 1, 66, 159, 84, 8, 189, 153, 154, 164, 121, 193, 1, 129, 89, 85, 14, 197, 90, 17, 60, 73, 59, 230, 72, 244, 224, 54, 221, 79, 140, 128, 158, 3, 107, 79, 187, 145, 140, 44, 72, 74, 216, 225, 116, 122, 224, 85, 133, 171, 67, 63, 223, 70, 26, 240, 60, 37, 167, 115, 112, 7, 33, 170, 5, 247, 55, 159, 231, 245, 237, 150, 23, 93, 64, 33, 7, 110, 127, 82, 182, 3, 8, 239, 245, 212, 43, 166, 224, 147, 179, 208, 129, 94, 179, 73, 102, 70, 228, 146, 48, 169, 179, 92, 141, 65, 144, 12, 43, 184, 211, 180, 70, 162, 49, 39, 247, 224, 150, 216, 90, 28, 121, 74, 212, 200, 146, 119, 144, 79, 198, 191, 236, 87, 177, 205, 216, 13, 249, 149, 80, 48, 253, 202, 116, 26, 251, 218, 200, 39, 177, 60, 205, 84, 3, 88, 138, 244, 100, 64, 3, 194, 38, 93, 250, 77, 65, 157, 188, 205, 32, 100, 137, 35, 134, 81, 139, 233, 213, 28, 22, 73, 130, 117, 235, 236, 245, 205, 199, 168, 32, 242, 194, 147, 20, 172, 74, 111, 8, 178, 37, 42, 211, 207, 177, 153, 170, 66, 254, 11, 79, 181, 113, 151, 92, 16, 32, 217, 73, 225, 148, 238, 30, 173, 147, 123, 251, 85, 11, 179, 186, 142, 53, 122, 2, 156, 41, 240, 119, 85, 70, 2, 225, 202, 47, 34, 137, 203, 145, 105, 148, 28, 58, 175, 219, 142, 88, 199, 242, 172, 119, 41, 31, 180, 20, 124, 101, 246, 176, 49, 211, 235, 164, 47, 42, 207, 217, 68, 138, 91, 194, 43, 71, 110, 7, 204, 206, 218, 35, 6, 197, 84, 236, 155, 122, 182, 85, 241, 215, 49, 140, 43, 126, 103, 213, 246, 155, 237, 245, 96, 0, 253, 169, 137, 134, 181, 171, 27, 58, 34, 216, 223, 214, 104, 22, 151, 178, 58, 85, 201, 110, 135, 16, 243, 249, 140, 4, 79, 177, 95, 96, 99, 19, 238, 86, 192, 241, 245, 202, 15, 81, 46, 8, 72, 79, 203, 53, 142, 110, 82, 143, 250, 137, 248, 168, 102, 204, 255, 60, 12, 88, 19, 20, 126, 197, 154, 240, 71, 12, 74, 173, 1, 65, 211, 79, 16, 29, 162, 229, 225, 189, 82, 208, 212, 201, 177, 59, 62, 61, 135, 209, 88, 97, 5, 121, 103, 84, 231, 151, 140, 161, 198, 138, 125, 133, 223, 17, 43, 122, 185, 33, 179, 89, 169, 240, 60, 189, 39, 167, 234, 200, 122, 154, 128, 176, 178, 107, 76, 150, 87, 237, 133, 173, 127, 162, 97, 106, 179, 69, 235, 130, 38, 246, 159, 192, 244, 129, 131, 255, 87, 75, 205, 118, 123, 86, 118, 65, 58, 219, 18, 234, 33, 80, 160, 233, 118, 131, 238, 84, 36, 60, 37, 183, 234, 138, 113, 134, 6, 248, 105, 147, 216, 208, 218, 206, 131, 78, 211, 65, 238, 183, 36, 254, 61, 95, 240, 188, 139, 138, 123, 129, 4, 186, 38, 157, 52, 19, 58, 76, 248, 48, 10, 45, 104, 132, 150, 181, 155, 111, 203, 198, 26, 233, 96, 98, 234, 29, 142, 91, 65, 12, 86, 113, 244, 36, 65, 126, 214, 147, 50, 156, 217, 131, 0, 31, 252, 209, 0, 35, 213, 152, 133, 159, 183, 173, 95, 210, 99, 84, 113, 23, 16, 6, 144, 198, 206, 116, 56, 149, 110, 108, 197, 127, 27, 93, 229, 59, 176, 220, 114, 206, 155, 109, 234, 168, 87, 137, 89, 154, 112, 240, 5, 31, 26, 14, 37, 232, 109, 136, 139, 0, 223, 54, 189, 188, 147, 239, 114, 23, 196, 90, 206, 17, 192, 121, 13, 112, 233, 149, 62, 91, 65, 123, 162, 253, 154, 76, 175, 130, 241, 252, 230, 244, 95, 83, 226, 21, 184, 53, 94, 246, 29, 137, 29, 241, 199, 148, 35, 28, 22, 45, 210, 65, 100, 181, 52, 169, 212, 132, 103, 205, 195, 35, 98, 76, 47, 149, 212, 64, 47, 249, 214, 106, 177, 25, 26, 129, 36, 20, 74, 250, 53, 212, 227, 29, 200, 108, 170, 121, 124, 49, 246, 139, 133, 133, 76, 217, 89, 196, 250, 197, 236, 83, 179, 181, 109, 55, 75, 136, 138, 158, 151, 154, 101, 118, 182, 52, 94, 200, 82, 44, 150, 6, 153, 2, 129, 191, 62, 247, 197, 148, 93, 16, 253, 33, 162, 161, 210, 229, 64, 76, 92, 242, 18, 32, 100, 19, 145, 185, 139, 207, 130, 83, 152, 48, 91, 86, 229, 139, 97, 31, 229, 37, 50, 3, 227, 223, 13, 34, 70, 106, 115, 179, 240, 251, 228, 59, 154, 98, 146, 128, 145, 137, 139, 138, 14, 91, 38, 157, 181, 134, 176, 228, 221, 239, 80, 214, 130, 161, 45, 44, 27, 232, 36, 20, 154, 162, 84, 198, 56, 27, 180, 18, 215, 124, 63, 154, 169, 2, 182, 136, 200, 23, 21, 165, 156, 131, 149, 88, 85, 109, 53, 237, 79, 200, 59, 74, 177, 129, 129, 244, 15, 115, 220, 215, 104, 96, 216, 216, 191, 148, 82, 2, 55, 194, 172, 14, 70, 59, 160, 158, 60, 151, 130, 56, 13, 192, 127, 228, 252, 186, 52, 12, 194, 0, 52, 57, 253, 35, 20, 97, 6, 56, 7, 13, 108, 158, 234, 10, 112, 186, 232, 59, 93, 93, 60, 93, 63, 222, 38, 221, 1, 96, 108, 140, 82, 1, 88, 231, 229, 16, 64, 32, 242, 72, 206, 170, 102, 100, 87, 193, 10, 235, 240, 104, 248, 163, 189, 92, 231, 181, 44, 106, 240, 171, 213, 148, 74, 241, 173, 71, 82, 201, 17, 57, 118, 8, 60, 3, 182, 195, 78, 29, 71, 237, 105, 100, 76, 173, 120, 44, 47, 125, 5, 248, 161, 72, 150, 29, 150, 95, 162, 225, 114, 58, 141, 222, 188, 34, 169, 12, 215, 131, 221, 31, 77, 179, 143, 185, 174, 90, 103, 20, 179, 217, 70, 120, 22, 67, 211, 23, 183, 221, 121, 56, 28, 247, 137, 169, 88, 139, 179, 225, 147, 185, 42, 11, 96, 214, 176, 125, 4, 127, 105, 132, 176, 96, 158, 197, 117, 67, 195, 148, 202, 141, 94, 91, 204, 42, 115, 26, 121, 97, 139, 209, 226, 224, 218, 135, 4, 175, 152, 242, 15, 95, 143, 84, 82, 221, 246, 70, 185, 91, 52, 29, 215, 240, 210, 204, 31, 161, 91, 217, 137, 92, 213, 182, 90, 161, 203, 148, 181, 226, 231, 136, 253, 169, 130, 91, 101, 102, 57, 25, 61, 152, 50, 129, 84, 164, 242, 195, 84, 149, 163, 139, 110, 160, 210, 255, 170, 163, 93, 249, 44, 32, 60, 127, 49, 203, 188, 167, 189, 3, 195, 194, 48, 33, 144, 206, 205, 22, 31, 212, 146, 55, 228, 248, 57, 227, 243}

	msg := []byte{216, 28, 77, 141, 115, 79, 203, 251, 234, 222, 61, 63, 138, 3, 159, 170, 42, 44, 153, 87, 232, 53, 173, 85, 178, 46, 117, 191, 87, 187, 85, 106, 200}

	sig := []byte{175, 89, 32, 119, 70, 3, 210, 14, 152, 167, 154, 163, 171, 250, 50, 182, 226, 37, 25, 230, 115, 227, 122, 196, 172, 115, 254, 133, 52, 30, 44, 41, 35, 193, 153, 46, 27, 11, 190, 56, 115, 215, 200, 252, 86, 98, 242, 7, 191, 88, 234, 56, 28, 212, 163, 160, 192, 98, 222, 196, 91, 218, 248, 186, 10, 165, 43, 239, 111, 161, 79, 63, 108, 242, 143, 118, 32, 191, 148, 169, 44, 194, 125, 4, 84, 20, 166, 77, 101, 192, 20, 150, 48, 82, 128, 36, 40, 191, 57, 135, 162, 212, 117, 22, 202, 92, 120, 170, 185, 107, 123, 225, 27, 202, 95, 44, 90, 38, 243, 252, 227, 162, 110, 142, 9, 162, 115, 143, 56, 111, 117, 212, 72, 249, 55, 239, 25, 168, 70, 189, 77, 217, 73, 202, 175, 54, 219, 86, 41, 136, 74, 245, 58, 2, 62, 63, 24, 15, 228, 192, 250, 255, 123, 229, 223, 228, 232, 154, 222, 48, 149, 166, 86, 0, 66, 20, 97, 173, 8, 193, 41, 214, 206, 168, 81, 187, 57, 192, 215, 167, 209, 81, 64, 86, 137, 160, 145, 250, 77, 235, 172, 55, 60, 245, 74, 224, 120, 240, 175, 117, 87, 187, 198, 240, 106, 83, 90, 232, 148, 158, 12, 101, 48, 138, 89, 132, 0, 114, 55, 82, 149, 128, 45, 14, 44, 233, 163, 218, 152, 66, 106, 0, 255, 3, 254, 128, 33, 140, 14, 236, 142, 254, 88, 28, 185, 204, 154, 125, 102, 178, 6, 69, 168, 205, 4, 144, 211, 206, 79, 126, 111, 234, 233, 201, 235, 122, 87, 249, 100, 208, 235, 199, 201, 11, 122, 159, 134, 48, 11, 62, 128, 149, 230, 77, 18, 148, 207, 196, 180, 217, 226, 114, 232, 250, 141, 181, 112, 125, 112, 4, 175, 34, 219, 255, 156, 253, 72, 99, 223, 87, 63, 224, 4, 52, 29, 163, 205, 74, 48, 130, 83, 44, 38, 32, 69, 95, 163, 124, 86, 43, 175, 213, 104, 78, 161, 40, 175, 199, 158, 1, 252, 155, 49, 232, 67, 59, 173, 124, 2, 159, 47, 19, 204, 16, 89, 45, 35, 50, 227, 224, 139, 128, 211, 80, 70, 61, 231, 39, 80, 177, 248, 6, 244, 147, 225, 67, 189, 95, 202, 125, 22, 152, 8, 27, 49, 191, 135, 107, 42, 27, 201, 223, 80, 149, 45, 19, 182, 193, 50, 27, 17, 17, 23, 33, 69, 166, 39, 174, 11, 68, 39, 185, 137, 117, 203, 255, 247, 214, 130, 117, 117, 75, 69, 182, 130, 215, 9, 225, 104, 82, 46, 132, 254, 167, 221, 59, 176, 244, 21, 5, 255, 113, 146, 100, 49, 209, 169, 13, 76, 191, 154, 82, 122, 212, 226, 132, 151, 111, 255, 139, 217, 214, 34, 74, 79, 38, 3, 145, 169, 135, 251, 109, 166, 238, 66, 194, 164, 144, 15, 64, 124, 225, 240, 46, 50, 36, 117, 211, 19, 251, 235, 182, 140, 46, 5, 115, 8, 9, 68, 138, 116, 40, 165, 148, 1, 57, 235, 223, 27, 85, 86, 252, 197, 212, 46, 26, 19, 243, 34, 48, 203, 111, 7, 36, 131, 29, 13, 7, 27, 186, 90, 103, 4, 128, 111, 71, 91, 116, 186, 145, 182, 227, 133, 212, 134, 32, 149, 141, 10, 177, 191, 43, 24, 78, 16, 243, 231, 83, 183, 19, 55, 190, 158, 182, 83, 120, 103, 133, 180, 58, 199, 229, 196, 148, 172, 27, 203, 4, 61, 70, 20, 37, 179, 96, 152, 172, 147, 5, 90, 1, 5, 171, 133, 35, 182, 29, 2, 74, 110, 155, 86, 164, 45, 60, 4, 114, 101, 18, 174, 76, 254, 5, 113, 4, 70, 176, 111, 105, 66, 52, 238, 79, 168, 254, 237, 221, 197, 242, 138, 101, 237, 226, 235, 88, 233, 101, 254, 54, 39, 165, 113, 188, 69, 179, 151, 237, 9, 42, 180, 190, 0, 4, 23, 41, 196, 209, 146, 254, 48, 103, 130, 121, 210, 35, 168, 72, 207, 67, 102, 233, 43, 63, 104, 222, 233, 124, 155, 74, 127, 242, 47, 147, 123, 230, 197, 102, 57, 150, 29, 178, 159, 163, 207, 236, 255, 242, 147, 20, 8, 134, 255, 185, 46, 188, 121, 218, 181, 156, 234, 248, 105, 198, 79, 142, 175, 88, 92, 233, 125, 214, 183, 143, 137, 39, 114, 219, 136, 169, 88, 207, 10, 181, 87, 167, 250, 168, 63, 230, 33, 71, 126, 43, 132, 73, 122, 181, 168, 236, 244, 167, 189, 50, 223, 185, 2, 240, 93, 44, 163, 16, 71, 208, 241, 145, 154, 221, 225, 238, 109, 253, 88, 229, 155, 196, 218, 179, 204, 187, 163, 106, 170, 246, 175, 204, 199, 176, 149, 202, 148, 161, 149, 190, 154, 40, 149, 38, 181, 136, 195, 169, 197, 104, 118, 252, 65, 93, 82, 29, 68, 43, 172, 2, 152, 211, 2, 65, 154, 213, 39, 218, 36, 156, 42, 102, 12, 208, 100, 33, 63, 250, 213, 99, 24, 63, 55, 151, 37, 120, 238, 185, 247, 10, 198, 122, 238, 108, 194, 183, 31, 40, 58, 149, 147, 11, 85, 71, 56, 85, 87, 145, 194, 94, 122, 57, 158, 104, 86, 54, 213, 141, 105, 203, 107, 231, 147, 180, 92, 25, 105, 231, 213, 97, 86, 39, 235, 195, 46, 237, 69, 68, 15, 135, 136, 13, 40, 41, 250, 79, 200, 113, 134, 97, 100, 210, 89, 237, 149, 210, 115, 24, 113, 1, 127, 245, 24, 148, 6, 111, 174, 31, 250, 111, 75, 74, 111, 132, 252, 255, 218, 9, 231, 24, 250, 23, 19, 94, 219, 63, 72, 85, 141, 91, 166, 127, 158, 111, 9, 0, 52, 11, 208, 77, 254, 89, 183, 189, 103, 116, 88, 132, 251, 132, 174, 63, 142, 231, 99, 210, 2, 116, 54, 82, 212, 247, 51, 52, 80, 88, 4, 144, 185, 199, 68, 147, 91, 25, 193, 213, 251, 13, 181, 251, 180, 97, 65, 19, 98, 131, 128, 55, 235, 126, 195, 246, 63, 38, 200, 147, 231, 204, 28, 59, 63, 71, 103, 171, 174, 0, 254, 183, 187, 153, 177, 66, 11, 178, 158, 166, 20, 116, 120, 150, 217, 237, 207, 129, 7, 254, 80, 76, 156, 48, 138, 130, 100, 218, 206, 49, 141, 135, 207, 228, 118, 24, 3, 233, 166, 13, 239, 166, 20, 74, 171, 193, 241, 10, 69, 177, 64, 222, 215, 84, 231, 53, 134, 196, 103, 187, 123, 241, 158, 222, 242, 91, 224, 198, 94, 147, 197, 229, 235, 143, 136, 12, 206, 74, 133, 135, 87, 248, 255, 86, 6, 43, 16, 103, 244, 16, 111, 118, 183, 0, 127, 110, 166, 249, 69, 4, 126, 133, 189, 15, 173, 157, 38, 153, 79, 103, 138, 6, 18, 184, 124, 207, 156, 12, 249, 164, 51, 216, 137, 201, 110, 76, 18, 190, 55, 34, 119, 0, 91, 6, 173, 18, 113, 5, 209, 109, 143, 177, 66, 174, 174, 83, 115, 171, 214, 29, 154, 220, 252, 85, 80, 214, 35, 202, 59, 136, 36, 176, 226, 224, 140, 43, 244, 226, 132, 30, 172, 76, 93, 197, 108, 248, 149, 76, 242, 7, 194, 99, 242, 124, 159, 48, 159, 16, 48, 124, 13, 132, 166, 88, 120, 66, 80, 49, 55, 93, 216, 16, 210, 215, 229, 16, 152, 163, 129, 67, 80, 121, 92, 74, 7, 127, 164, 13, 212, 79, 15, 167, 81, 15, 124, 63, 99, 20, 7, 207, 52, 246, 4, 199, 179, 53, 99, 42, 32, 210, 173, 65, 155, 215, 204, 109, 66, 66, 177, 198, 108, 53, 229, 165, 237, 204, 177, 60, 163, 125, 59, 80, 70, 95, 59, 74, 175, 247, 227, 22, 30, 121, 54, 8, 138, 224, 132, 1, 253, 44, 55, 214, 122, 47, 249, 29, 62, 111, 8, 104, 109, 100, 188, 47, 198, 197, 113, 6, 228, 159, 163, 132, 172, 34, 33, 159, 7, 238, 137, 150, 202, 61, 255, 89, 220, 197, 9, 42, 75, 173, 190, 135, 174, 222, 127, 105, 160, 76, 121, 179, 59, 223, 53, 212, 160, 228, 203, 75, 85, 1, 156, 176, 191, 39, 82, 149, 185, 59, 218, 190, 165, 22, 202, 43, 97, 106, 86, 145, 134, 0, 183, 36, 190, 122, 1, 236, 78, 245, 67, 18, 179, 13, 102, 245, 7, 129, 95, 39, 128, 255, 238, 124, 48, 248, 66, 90, 146, 37, 44, 229, 80, 250, 180, 233, 2, 231, 179, 130, 212, 109, 189, 32, 239, 225, 187, 14, 248, 164, 150, 135, 60, 9, 196, 206, 176, 48, 60, 127, 29, 171, 160, 16, 45, 233, 65, 144, 182, 172, 109, 200, 16, 247, 43, 202, 58, 162, 146, 255, 56, 189, 81, 167, 250, 184, 80, 158, 196, 251, 224, 234, 163, 201, 134, 22, 106, 103, 75, 120, 113, 21, 92, 52, 140, 71, 126, 248, 206, 220, 131, 43, 90, 190, 231, 26, 141, 24, 208, 109, 208, 245, 34, 17, 96, 171, 235, 113, 230, 232, 44, 250, 191, 115, 30, 163, 81, 90, 118, 239, 7, 178, 193, 108, 99, 179, 127, 122, 183, 59, 103, 240, 5, 146, 154, 117, 62, 69, 59, 147, 12, 10, 244, 50, 39, 127, 215, 125, 138, 30, 184, 2, 44, 222, 150, 101, 118, 59, 1, 79, 10, 103, 42, 4, 22, 11, 10, 6, 245, 84, 15, 76, 38, 75, 127, 34, 116, 6, 144, 162, 53, 45, 200, 99, 181, 136, 48, 58, 213, 31, 10, 225, 98, 191, 121, 121, 127, 7, 181, 52, 80, 28, 187, 253, 183, 19, 167, 36, 170, 152, 225, 149, 50, 24, 113, 128, 204, 250, 220, 110, 190, 49, 66, 250, 125, 182, 108, 212, 222, 123, 159, 189, 76, 130, 53, 104, 109, 182, 140, 175, 72, 154, 250, 78, 30, 135, 174, 240, 206, 253, 128, 55, 227, 165, 120, 238, 98, 235, 127, 148, 237, 91, 192, 181, 142, 234, 75, 76, 69, 252, 86, 211, 29, 41, 148, 77, 9, 90, 201, 108, 41, 8, 61, 162, 199, 113, 129, 217, 122, 85, 254, 110, 144, 58, 47, 39, 131, 222, 11, 170, 95, 71, 215, 4, 120, 92, 51, 232, 213, 200, 126, 214, 30, 101, 69, 145, 103, 49, 14, 183, 169, 149, 116, 239, 129, 154, 233, 22, 26, 59, 208, 150, 52, 128, 61, 158, 30, 78, 199, 56, 109, 121, 70, 152, 69, 23, 33, 58, 185, 207, 102, 174, 165, 81, 204, 69, 124, 57, 248, 106, 242, 148, 207, 123, 7, 63, 86, 62, 212, 218, 185, 65, 155, 223, 0, 75, 208, 92, 146, 180, 232, 14, 195, 207, 234, 201, 126, 29, 218, 85, 79, 218, 98, 92, 75, 155, 3, 155, 170, 124, 90, 47, 111, 151, 5, 119, 146, 72, 60, 245, 248, 82, 212, 195, 172, 113, 173, 80, 247, 121, 149, 61, 207, 226, 246, 62, 210, 53, 216, 225, 213, 52, 93, 108, 109, 240, 85, 92, 194, 99, 29, 234, 217, 183, 20, 188, 76, 22, 80, 30, 1, 38, 19, 129, 243, 103, 151, 21, 52, 81, 35, 56, 140, 133, 45, 87, 220, 241, 148, 29, 9, 17, 212, 159, 234, 113, 67, 253, 47, 195, 67, 165, 7, 91, 100, 204, 164, 130, 145, 220, 40, 184, 63, 118, 7, 69, 137, 234, 178, 23, 199, 132, 120, 64, 101, 44, 14, 58, 226, 120, 179, 182, 251, 13, 128, 12, 94, 125, 183, 157, 92, 185, 204, 26, 135, 69, 12, 0, 183, 103, 120, 18, 210, 46, 226, 15, 222, 140, 23, 83, 167, 251, 147, 186, 139, 187, 133, 149, 166, 57, 61, 245, 74, 169, 205, 182, 224, 135, 154, 38, 228, 155, 211, 176, 21, 19, 198, 5, 58, 7, 70, 200, 89, 108, 229, 229, 178, 37, 207, 202, 38, 171, 139, 241, 47, 31, 224, 166, 71, 169, 228, 69, 48, 57, 161, 34, 97, 148, 196, 110, 139, 152, 172, 215, 16, 241, 143, 183, 236, 5, 71, 108, 28, 216, 252, 49, 18, 204, 221, 177, 88, 43, 136, 23, 193, 143, 227, 21, 53, 62, 122, 71, 200, 33, 233, 238, 58, 67, 202, 222, 27, 128, 217, 42, 10, 232, 220, 235, 77, 255, 118, 106, 84, 223, 54, 101, 254, 254, 60, 37, 43, 114, 218, 215, 177, 227, 53, 158, 127, 162, 85, 98, 195, 227, 157, 181, 33, 206, 24, 116, 17, 31, 176, 144, 219, 211, 139, 49, 128, 173, 3, 75, 87, 176, 49, 220, 77, 214, 175, 124, 26, 138, 243, 246, 206, 126, 219, 26, 158, 75, 109, 74, 89, 32, 227, 98, 8, 24, 130, 6, 89, 118, 46, 247, 164, 36, 63, 81, 223, 45, 138, 144, 7, 55, 213, 129, 5, 105, 155, 78, 16, 203, 203, 53, 156, 127, 58, 64, 7, 105, 124, 72, 32, 80, 236, 51, 207, 128, 65, 145, 106, 59, 145, 154, 80, 217, 110, 240, 245, 137, 253, 69, 86, 243, 13, 189, 217, 66, 234, 183, 157, 250, 151, 192, 126, 48, 36, 112, 116, 53, 46, 27, 249, 142, 52, 156, 199, 239, 165, 161, 184, 252, 228, 241, 143, 31, 175, 111, 7, 201, 156, 50, 20, 72, 176, 57, 92, 138, 156, 188, 70, 100, 18, 248, 156, 26, 152, 191, 87, 21, 132, 40, 68, 240, 232, 35, 111, 164, 105, 108, 70, 88, 184, 253, 228, 66, 93, 9, 214, 122, 56, 172, 114, 88, 229, 213, 150, 111, 45, 63, 246, 106, 12, 12, 231, 110, 127, 107, 129, 161, 188, 208, 71, 253, 58, 32, 91, 240, 204, 174, 163, 177, 16, 121, 144, 156, 108, 229, 105, 143, 50, 225, 243, 64, 150, 88, 255, 160, 30, 174, 203, 74, 226, 176, 146, 183, 137, 137, 218, 173, 102, 35, 187, 17, 244, 159, 15, 143, 134, 153, 236, 5, 102, 21, 2, 255, 202, 208, 60, 244, 21, 25, 26, 34, 45, 60, 76, 123, 138, 176, 181, 185, 187, 194, 217, 220, 239, 247, 32, 45, 63, 66, 68, 73, 79, 82, 83, 100, 102, 105, 116, 196, 217, 230, 245, 250, 0, 1, 4, 25, 39, 55, 61, 90, 118, 128, 184, 193, 201, 254, 32, 41, 56, 59, 60, 72, 77, 86, 95, 101, 121, 157, 158, 166, 169, 173, 210, 222, 229, 231, 247, 249, 0, 0, 0, 0, 0, 0, 0, 0, 18, 36, 50, 72}

	d := NewDilithium2(false)

	if !d.Verify(pk, msg, sig) {
		t.Fatal("could not verify signature generated with reference files")
	}
}
