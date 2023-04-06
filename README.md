# Go Post Quantum Safe Lib

This library offers a fast, secure, and easy to use implementation of the post-quantum candidates of the CRYSTALS suite.
It contains Kyber, a key-encapsulation mechanism whose goal is to securely transmit symmetric key material over an insecure channel, and Dilithium, a digital signature algorithm that produces a signature that can be verified against a key, and can be used towards authentication or integrity. 

## API

To begin with, the crystal-go module can be installed via:
```shell
go get -u github.com/kudelskisecurity/crystals-go
```

The API of Kyber and Dilihtium is very similar, and can be divided in two steps:

The user first has to define which level of security they want to work with by creating an instance of Kyber or Dilithium among (in increasing level of security) Kyber512, Kyber768, Kyber1024 and Dilithium2, Dilithium3, Dilithium5. For example:

```go
k := NewKyber512() //Creates a Kyber instance with light security level 
d := Dilithium3() //Creates a Dilithium instance with recommended/medium security level
```

The newly created instance defines all parameters used internally. In a second step, the user can now invoke our generic methods on an instance of Kyber or Dilithium. 

### Kyber
The core functions of Kyber, a KEM, are a tuple KeyGen, Encaps, and Decaps. The key generation function returns a public key that can be openly disclosed, and a secret key that should remain private. The encapsulation function is used to generate and encrypt a shared secret given a public key. Secret that can be recovered using the associated secret key. No one except the secret key holder can recover the value of the shared secret.

Translated to code, a KEM protocol between Alice and Bob using our API looks like this:

Alice and Bob agreed on using the recommended security level. Alice can now generate a public and private key pair by calling:
```go
k := NewKyber768()
pk, sk := k.KeyGen(seed)
```
Once the keys are generated, Alice can send her public key to Bob, who encapsulates a shared secret using:
```go
k := NewKyber768()
c, ss := k.Encaps(pk, coins)
```
The ciphertext is transmitted to Alice for her to recover the value of ss with:
```go
ss := k.Decaps(sk, c) //Matches the value held by Bob
```

### Dilithium

For Dilithium, the DSA, the main methods are KeyGen, Sign, and Verify, which very intuitively, correspond to the verification key (public) and signing key (secret) generation, the signature algorithm, and the verification algorithm. The signature, given a message and a signing key, produces a signature that is verifiable against the associated public verification key. Dilithium signatures are said to be unforgeable, meaning that it is extremely hard to create a valid signature without actually holding the signing key. In that case, Dilithium can be used as an authentication mechanism, as a valid signature is the proof that the signer is the secret key holder. If the message is tampered, the signature will not verify anymore, so Dilithium can also be used to enforce message integrity.

Similarly, we can translate the Dilithium protocol to code. W.L.O.G, we choose Alice to be the signer, and Bob the verifier, and assume that they agreed on using the light security level.

Alice starts by generating a key pair:
```go
d := Dilithium3() //Creates a Dilithium instance with recommended security level
pk, sk := d.KeyGen()
```
She can then sign a message of her choice using:
```go
msg := []byte("This is a message.")
sig := d.Sign(sk, msg)
```
Then transmit her public key, message, and signature to Bob for him to verify it with:
```go
d := Dilithium3()
verified := d.Verify(pk, sig, msg) //verified is true for honest executions
```

A feature of Dilithium is to be available both in randomized or deterministic mode. When creating a Dilithium instance, a boolean is given as parameter to indicate which one to use. By default, the boolean is set to true, setting Dilithium to the randomized mode, but passing *false* as parameter will choose the deterministic mode.
For example, `d := NewDilithium3(false)` will create a Dilithium instance with parameters set to the security level 3, and a deterministic signature.
The signing and verification procedure is the same for both and follows the aforementioned flow.

### Random inputs

This leads us to the final feature of the API regarding randomization. Both Kyber and Dilithium use random numbers. The concerned methods accept as argument seed or coins of 32 bytes to be used as random material, which allows for reproducibility for example, or is useful if the user does not trust the environment to generate good randomness and wants to use randomness from their own source.
They can also be *nil*, in which case the randomness will be generated during using Go's official crypto/rand library.

### Helpers

The output sizes of Kyber and Dilithium (keys, signature,...) vary based on the security level.
We provide for both schemes getter functions that return the size of the keys and ciphertext or signature structures based on the security level of the instance used.
They can be called as follows:

```go
sizePk := k.SizePk()
sizeSk := k.SizeSk()
sizeC := k.SizeC()
```
for Kyber, or 
```go
sizePk := k.SizePk()
sizeSk := k.SizeSk()
sizeSig := d.SizeSig()
```
for Dilithium.

Finally, we noticed that some packages (for example: [binary](https://golang.org/pkg/encoding/binary/) are only compatible with constant-size objects.
Our API outputs slices, which are variable-sized arrays, and function calls in Go return non-constant values, breaking the compatibility with such packages.
For applications where resources need to be allocated using constant-size structures, we hardcode the size of our scheme's outputs for each security level, and expose them as constants as part of the Kyber/Dilithium packages. Have a look at the [param.go](https://github.com/kudelskisecurity/crystals-go/blob/main/crystals-dilithium/params.go#L19) file for an example.

### Errors

In order to keep the API pretty simple, any error will result in a *nil* output (*false* is the case or *Verify*). For now the error is printed, but we are working on Log Levels.

## Security

Our library stands out because of its security properties. Among the vulnerabilities reported on the original implementation, we integrate countermeasures for most of them, providing a library that is both *theoretically* and *practically* secure. We predict that new attacks will be published as the candidates are refined, and expect changes in the code to occur as the security of our library is treated as a continuous process. 

We recall that side-channel attacks are high-risk threats and encourage users to prefer libraries with strong implementation security, such as our library, over implementations that lack these guarantees.

### Dashboard SCA (work in progress)

|    | Alg | Attack            | Paper                   | 
| -- | ---- |----------------- |:----------------------- |
|    | | TA                |                         |
| ✔️| D | Timing of decryption                  | [:link:][dan19]          |
| ✔️| D | Timing of re-encryption check                  | [:link:][guo20]          |
|    | | CM                |                         |
| ✖️| KG | Cache access monitoring                  | [:link:][fac18]          |
| ✖️| S | Cache access monitoring                  | [:link:][fac18]          |
| ✔️| D|  Cache access monitoring                | [:link:][rav20]          |
|    | | FA                |                         |
| ✔️| KG |  Skip of secret addition               | [:link:][bbk19]          |
| ✔️| S |   Skip of mask addition             | [:link:][rav19]          |
| ✖️| D |   Skip of decryption check              | [:link:][pp21]          |
| ✖️| D |   Skip of +Q/2 instruction              | [:link:][pp21]          |
| ✖️| KG |  Zero of secret               | [:link:][bbk19]          |
| ✖️| KG |  Zero of noise               | [:link:][val17]          |
| ✖️| KG |  Zero of A               | [:link:][val17]          |
| ✖️| S |  Zero of randomness               | [:link:][bbk19]          |
| ✖️| KG |  Zero of noise               | [:link:][val17]          |
| ✔️| KG |  Zero of nonce               | [:link:][rav18]          |
| ✔️| E |  Zero of nonce               | [:link:][rav18]          |
| ✔️| S |  Zero of mask               | [:link:][esp18]          |
| ✔️| S |  Loop-abort of mask addition                | [:link:][bbk19]          |
| ✔️| KG |  Loop abort of noise addition               | [:link:][esp18]          |
| ✔️| S |  Err. in hash polynomial               | [:link:][bp18]          |
| ✔️| S |  Err. in expand function               | [:link:][bp18]          |



Attacks marked with a gray cross are the ones left, a green checkmark implies that a defense is implemented.

[dan19]: https://doi.org/10.1145/3338467.3358948
[guo20]: https://eprint.iacr.org/2020/743
[fac18]: https://ieeexplore.ieee.org/document/8494855
[rav20]: https://eprint.iacr.org/2020/1559
[bbk19]: https://eprint.iacr.org/2016/415
[rav19]: https://eprint.iacr.org/2019/769
[rav18]: https://eprint.iacr.org/2018/211
[val17]: https://doi.org/10.1145/3178291.3178294
[pp21]: https://eprint.iacr.org/2021/064
[esp18]: https://eprint.iacr.org/2016/449.pdf
[bp18]: https://eprint.iacr.org/2018/355
