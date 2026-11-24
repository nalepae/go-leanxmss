# go-leanxmss

A Go implementation of **leanXMSS**, the post-quantum hash-based signature scheme
of Ethereum's PQ consensus specification, over Keccak-256.

Specification: [leanXMSS](https://github.com/leanEthereum/leanVM/blob/f7ba4999ae523b94c8d0969b32762c3effea4cbd/doc/lean_xmss/main.tex)
(leanVM's `doc/lean_xmss`).

> [!CAUTION]
> **This library is a proof of concept only. Do NOT use it in production.**
> It has not been audited, it is not formally verified, and the leanXMSS
> specification and parameters it follows may still change. Never use it to
> protect real funds or real validator keys.

```sh
go get github.com/nalepae/go-leanxmss
```

```go
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"

	leanxmss "github.com/nalepae/go-leanxmss"
)

func main() {
	// The seed is the whole private key: generate it once, and keep it secret.
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		log.Fatal(err)
	}

	sk := leanxmss.NewKeyFromSeed(seed)
	pk := sk.PublicKey()

	// Messages are 32 bytes: sign a hash of longer data.
	message := sha256.Sum256([]byte("Dear quantum computer: nice try."))

	// Never sign two different messages at the same leaf index.
	const leafIndex = 42
	sig, err := sk.Sign(leafIndex, message)
	if err != nil {
		log.Fatal(err)
	}

	// Keys and signatures travel as bytes.
	pkBytes, sigBytes := pk.Bytes(), sig.Bytes()
	fmt.Printf("public key: %d bytes, signature: %d bytes\n", len(pkBytes), len(sigBytes))

	decodedPK, err := leanxmss.PublicKeyFromBytes(pkBytes)
	if err != nil {
		log.Fatal(err)
	}

	decodedSig, err := leanxmss.SignatureFromBytes(sigBytes)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("leaf index:", decodedSig.LeafIndex())
	fmt.Println("valid:", leanxmss.Verify(decodedPK, leafIndex, message, decodedSig))
	fmt.Println("valid at another leaf index:", leanxmss.Verify(decodedPK, leafIndex+1, message, decodedSig))
}
```

It prints:

```text
public key: 32 bytes, signature: 2404 bytes
leaf index: 42
valid: true
valid at another leaf index: false
```

## Disabling the SHA3 or AVX2 instructions

Signing permutes Keccak states in assembly: two at a time with the Armv8.2 SHA3
instructions on arm64, four at a time with AVX2 on amd64. With AVX2, building a
tree also hashes four leaves at a time. These instructions change only the speed:
keys and signatures are the same byte for byte. To use the pure Go permutations
instead in a program such as the example at the top of this page, built with
`go build -o example .`, either set `GODEBUG` when running it, with no rebuild:

```sh
GODEBUG=cpu.sha3=off ./example # arm64
GODEBUG=cpu.avx2=off ./example # amd64
```

or build it without the assembly:

```sh
go build -tags purego -o example .
./example
```

Either way, signing is slower.

## API

### `PrivateKey`

Safe for concurrent use.

| Function                                                                          | Description                                                                                     |
| --------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `NewKeyFromSeed(seed [32]byte) *PrivateKey`                                       | Returns the private key of a seed. Builds the top tree.                                         |
| `NewKeyFromCache(seed [32]byte, pk PublicKey, cache []byte) (*PrivateKey, error)` | Returns the private key of a seed with its trees loaded from a tree cache checked against `pk`. |
| `(*PrivateKey).PublicKey() PublicKey`                                             | Returns the public key.                                                                         |
| `(*PrivateKey).Sign(leafIndex uint32, message [32]byte) (*Signature, error)`      | Signs a message at a leaf index. Never sign two different messages at the same leaf index.      |
| `(*PrivateKey).Prepare(leafIndex uint32) error`                                   | Builds the bottom tree of a leaf index ahead of time.                                           |
| `(*PrivateKey).TreeCache() []byte`                                                | Encodes the top tree and the cached bottom trees, in the reference implementation's format.     |
| `SeedPublicParam(seed [32]byte) [16]byte`                                         | Returns the public parameter of a seed's key, the last 16 bytes of its public key, cheaply.     |

#### Tree cache

`TreeCache` returns, and `NewKeyFromCache` takes, the top tree followed by the
cached bottom trees, least recently used first: 4,096 bytes plus 5,300 per bottom
tree. A tree is stored as its 256 nodes of level 8.

```text
cache       = top tree | bottom tree | bottom tree | ...

top tree    = 256 nodes of level 8, 16 bytes each                4,096 bytes

bottom tree = index, uint32 little endian                            4 bytes
              randomizer                                            16 bytes
              chain values, 58 × 16 bytes                          928 bytes
              path, 16 × 16 bytes                                  256 bytes
              256 nodes of level 8, 16 bytes each                4,096 bytes
                                                         total   5,300 bytes
```

The randomizer, chain values and path are the top layer's signature of the bottom
tree's root, encoded as in a `Signature`. `NewKeyFromCache` checks every tree
against `pk`, so a cache that loads gives valid signatures. The cache holds no
secret.

### `PublicKey`

Comparable with `==`.

| Function                                          | Description                                                         |
| ------------------------------------------------- | ------------------------------------------------------------------- |
| `PublicKeyFromBytes(b []byte) (PublicKey, error)` | Decodes a public key. Returns an error unless `b` is 32 bytes long. |
| `(PublicKey).Bytes() []byte`                      | Encodes a public key on 32 bytes.                                   |

### `Signature`

| Function                                           | Description                                                           |
| -------------------------------------------------- | --------------------------------------------------------------------- |
| `SignatureFromBytes(b []byte) (*Signature, error)` | Decodes a signature. Returns an error unless `b` is 2,404 bytes long. |
| `(*Signature).Bytes() []byte`                      | Encodes a signature on 2,404 bytes.                                   |
| `(*Signature).LeafIndex() uint32`                  | Returns the leaf index the signature was made at.                     |

### Verification

| Function                                                                        | Description                                                        |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `Verify(pk PublicKey, leafIndex uint32, message [32]byte, sig *Signature) bool` | Reports whether a signature of a message is valid at a leaf index. |

Leaf indices are `uint32`: a key has 2^32 of them, and a signature stores its
index on 4 bytes.

## Leaf indices are the caller's duty

leanXMSS is stateful: **never sign two different messages at the same leaf
index** with the same key, or forgeries become possible. This package does not
record used leaf indices. Signing is deterministic, so signing the same message at
the same leaf index again is safe and gives the same signature.

## Performance

On an Apple M2 Max (12 cores) and on an AMD EPYC-Rome virtual machine (10 cores,
AVX2, no AVX-512), with `go test -run '^$' -bench . -count 5 -cpu 1,12` on the M2
Max and `-count 3 -cpu 1,10` on the EPYC. "All CPUs" is 12 on the M2 Max and 10 on
the EPYC:

| Operation                              | Machine | All CPUs | 1 CPU   |
| -------------------------------------- | ------- | -------- | ------- |
| `NewKeyFromSeed` (builds the top tree) | M2 Max  | 580 ms   | 5.17 s  |
| `NewKeyFromSeed` (builds the top tree) | EPYC    | 519 ms   | 2.89 s  |
| `Prepare` (builds a bottom tree)       | M2 Max  | 626 ms   | 5.28 s  |
| `Prepare` (builds a bottom tree)       | EPYC    | 546 ms   | 3.03 s  |
| `Verify`                               | M2 Max  | 71.8 µs  | 70.3 µs |

Signing, with the permutations in assembly (SHA3 on the M2 Max, AVX2 on the EPYC)
and in pure Go (`GODEBUG=cpu.sha3=off` or `GODEBUG=cpu.avx2=off`):

| `Sign`                     | Machine | Permutation | All CPUs | 1 CPU   |
| -------------------------- | ------- | ----------- | -------- | ------- |
| Bottom tree cached         | M2 Max  | SHA3        | 8.8 ms   | 76.6 ms |
| Bottom tree cached         | M2 Max  | Pure Go     | 35.2 ms  | 310 ms  |
| Bottom tree cached         | EPYC    | AVX2        | 30.1 ms  | 179 ms  |
| Bottom tree cached         | EPYC    | Pure Go     | 144 ms   | 870 ms  |
| Bottom tree not cached yet | M2 Max  | SHA3        | 680 ms   | 5.44 s  |
| Bottom tree not cached yet | M2 Max  | Pure Go     | 760 ms   | 5.75 s  |
| Bottom tree not cached yet | EPYC    | AVX2        | 608 ms   | 3.44 s  |

The figures are the mean of the runs. The SHA3 instructions only speed up the
randomizer search: on the M2 Max, building a bottom tree costs about the same
either way. AVX2 also speeds up building trees, which hashes four leaves at a time.
Signing in a cached tree comes from `-bench SignCachedTree -benchtime 40x`, which
signs at the same 40 leaf indices in every run, as the number of randomizer trials
depends on the leaf index. With `-cpu 1`, the first run of `Prepare` and of `Sign`
in a new tree runs at the speed of all CPUs, a quirk of the benchmark harness:
those cells leave out the first run.

## Tests and benchmarks

Run the tests (about 16 s on the machine above):

```sh
go test
```

`-short` skips the slowest tests, which tamper with every byte of a signature,
fill the bottom-tree cache and check every trial below a found randomizer:

```sh
go test -short
```

Run them with the pure Go permutations only, which every architecture but arm64
and amd64 uses:

```sh
go test -tags purego
```

Run the tests, then the benchmarks:

```sh
go test -bench .
```

The figures above come from `go test -run '^$' -bench . -count 5 -cpu 1,12` (about
6 minutes). Replace `.` after `-bench` with a name, such as `Verify`, to run only
the matching benchmarks.

## Correctness

The tests check, byte for byte, every [EthLib](https://github.com/ethereum/EthLib)
test vector (key generation, signing, verification and leaf-index reading: 41
cases, vendored in `testdata/ethlib` with their checksums). EthLib is the Lean
specification of the scheme.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option, as leanVM is. See [NOTICE](NOTICE).
