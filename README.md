# Go Post Quantum Safe Lib

Kyber and Dilithium are implemented in this library.

Kyber512, Kyber768 and Kyber1024.
Dilithium2, Dilithium3 and Dilithium5.

## API

After creating a Kyber instance `k := NewKyber512()`, one can generate public/private key pair with `k.KeyGen(seed)`. `k.Encaps(seed, pk)` and `k.Decaps(c, sk)` will output the same shared secret (shared key). All seeds can be `nil` which will result in a call to Go's crypto random number generator, or given by the user, for reproducibility for example.

When creating a Dilithium instance, a boolean is given as parameter to indicate whether the signature is going to be randomized. By default, the boolean is set to true.

For example, `d := NewDilithium3(false)` will create a Dilithium instance with parameters set to the security level 3, and a deterministic signature.
Then, calling `d.Sign(msg, sk)` will produce a signature that can be verified by a public key holder with `d.Verify(msg, sig, pk)`.

## Useful links

 - NIST main page: https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization
 - Report: https://gitlab.kudelski.com/raynal/pdm-pqs-ks / https://www.overleaf.com/9177217519hdfmqtfqjftc
 - Planning: https://docs.google.com/spreadsheets/d/1YVRPUMhHPuHq88FCPMVFGGxTSWeBKc2plH3mqTFtd-I/edit?usp=sharing
 - Slides: https://docs.google.com/presentation/d/1q3WEXPQ8ifaNpDrz3pTqSVzDzXIgrifaIAuUT8WHO0s/edit?usp=sharing
