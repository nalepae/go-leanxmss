package leanxmss

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"testing"
)

const (
	// devnet0BLSSecretKey is the BLS secret key of the devnet-0 mnemonic's key 0,
	// as in Lighthouse's xmss_cache tests.
	devnet0BLSSecretKey = "0dce41fa73ae9f6bdfd51df4d422d75eee174553dba5fd450c4437e4ed3fc903"
	// devnet0PublicKey is the XMSS public key of devnet-0's key 0: the first 32 bytes
	// of ethereum-package's static_files/xmss-keys/b9dec4e1daa17dfe.bin, at commit
	// d4c9a8ace9dd80ca4f9938885345f8f40a646fd0.
	devnet0PublicKey = "d7792e263b94cf0b7a9f70d8374c6d34a600b4247057d4079f810caff711c632"
	// devnet0Cache is the reference implementation's tree cache of devnet-0's key 0:
	// bytes 0 to 14,695 of the cache Lighthouse's --xmss-cache-url reads, holding the
	// top tree and bottom trees 0 and 24,576.
	devnet0Cache = "testdata/devnet0_index0.xmss"
)

// devnet0Key returns the seed, public key and tree cache of devnet-0's key 0. The
// seed is derived from the BLS secret key as the devnet's genesis tool does.
func devnet0Key(tb testing.TB) ([seedSize]byte, PublicKey, []byte) {
	tb.Helper()
	blsKey, err := hex.DecodeString(devnet0BLSSecretKey)
	if err != nil {
		tb.Fatal(err)
	}

	pkBytes, err := hex.DecodeString(devnet0PublicKey)
	if err != nil {
		tb.Fatal(err)
	}

	pk, err := PublicKeyFromBytes(pkBytes)
	if err != nil {
		tb.Fatal(err)
	}

	cache, err := os.ReadFile(devnet0Cache)
	if err != nil {
		tb.Fatal(err)
	}

	return sha256.Sum256(append([]byte("leanxmss-seed"), blsKey...)), pk, cache
}

// TestTreeCacheReference loads the reference implementation's tree cache of a
// devnet-0 key, checks that it encodes back byte for byte, and that the loaded key
// signs as a key built from the seed, in the cached bottom trees and another one.
func TestTreeCacheReference(t *testing.T) {
	seed, pk, cache := devnet0Key(t)
	if got := SeedPublicParam(seed); !bytes.Equal(got[:], pk.publicParam[:]) {
		t.Fatalf("public parameter of the seed %x, want %x", got, pk.publicParam)
	}

	loaded, err := NewKeyFromCache(seed, pk, cache)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if !bytes.Equal(loaded.TreeCache(), cache) {
		t.Fatal("tree cache of the loaded key differs from the reference one")
	}

	built := NewKeyFromSeed(seed)
	if built.PublicKey() != pk {
		t.Fatalf("public key of the seed %x, want %x", built.PublicKey().Bytes(), pk.Bytes())
	}

	message := testMessage()
	for _, leafIndex := range []uint32{1 << 15, 0x6000_8000, 3<<layerHeight + 5} {
		got := mustSign(t, loaded, leafIndex, message)
		if want := mustSign(t, built, leafIndex, message); !bytes.Equal(got.Bytes(), want.Bytes()) {
			t.Errorf("signature at %d of the loaded key differs from the built key's", leafIndex)
		}

		if !Verify(pk, leafIndex, message, got) {
			t.Errorf("signature at %d does not verify", leafIndex)
		}
	}
}

// TestTreeCacheRoundTrip checks a cache with no bottom tree, and that loading more
// bottom trees than the key caches keeps the last ones.
func TestTreeCacheRoundTrip(t *testing.T) {
	seed, pk, cache := devnet0Key(t)
	top := cache[:storedTreeSize]
	loaded, err := NewKeyFromCache(seed, pk, top)
	if err != nil {
		t.Fatalf("load the top tree only: %v", err)
	}

	if !bytes.Equal(loaded.TreeCache(), top) {
		t.Error("tree cache of a key without bottom trees differs")
	}

	// The two bottom trees, then the first again, which makes it the most recently
	// used, so it ends up last.
	again := append(append([]byte(nil), cache...), cache[storedTreeSize:storedTreeSize+cachedBottomTreeSize]...)
	loaded, err = NewKeyFromCache(seed, pk, again)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	want := append(append(append([]byte(nil), top...), cache[storedTreeSize+cachedBottomTreeSize:]...), cache[storedTreeSize:storedTreeSize+cachedBottomTreeSize]...)
	if !bytes.Equal(loaded.TreeCache(), want) {
		t.Error("a bottom tree given twice is not cached once, as the most recently used")
	}

	// More bottom trees than the cache holds: only the last ones are kept.
	many := append([]byte(nil), top...)
	for range maxCachedBottomTrees {
		many = append(many, cache[storedTreeSize:]...)
	}

	if loaded, err = NewKeyFromCache(seed, pk, many); err != nil {
		t.Fatalf("load %d bottom trees: %v", 2*maxCachedBottomTrees, err)
	}

	if len(loaded.bottoms) != 2 {
		t.Errorf("%d bottom trees cached, want 2", len(loaded.bottoms))
	}
}

// TestTreeCacheRejected checks that a cache or public key that does not match is
// rejected with the right error.
func TestTreeCacheRejected(t *testing.T) {
	seed, pk, cache := devnet0Key(t)
	const (
		bottom      = storedTreeSize                        // Where the first bottom tree starts.
		randomizer  = bottom + leafIndexSize                // Where its top layer's signature starts.
		chainValues = randomizer + randomizerLen            // Where its chain values start.
		path        = chainValues + v*n                     // Where its path starts.
		nodes       = randomizer + layerSignatureSize       // Where its stored nodes start.
		second      = storedTreeSize + cachedBottomTreeSize // Where the second bottom tree starts.
	)

	flip := func(at int) func([]byte) []byte {
		return func(c []byte) []byte {
			c[at] ^= 1
			return c
		}
	}

	setIndex := func(index uint32) func([]byte) []byte {
		return func(c []byte) []byte {
			binary.LittleEndian.PutUint32(c[bottom:], index)
			return c
		}
	}

	tests := []struct {
		name   string
		seed   func([seedSize]byte) [seedSize]byte
		pk     func(PublicKey) PublicKey
		cache  func([]byte) []byte
		target error
	}{
		{name: "another seed", seed: func(s [seedSize]byte) [seedSize]byte { s[0] ^= 1; return s }, target: errCacheMismatch},
		{name: "root of the public key", pk: func(p PublicKey) PublicKey { p.root[0] ^= 1; return p }, target: errCacheMismatch},
		{name: "public parameter", pk: func(p PublicKey) PublicKey { p.publicParam[0] ^= 1; return p }, target: errCacheMismatch},
		{name: "top tree node", cache: flip(123 * n), target: errCacheMismatch},
		{name: "bottom tree index", cache: setIndex(1), target: errCacheMismatch},
		{name: "bottom tree index outside", cache: setIndex(layerWidth), target: errCacheMismatch},
		{name: "randomizer", cache: flip(randomizer), target: errCacheMismatch},
		{name: "chain value", cache: flip(chainValues + 3*n), target: errCacheMismatch},
		{name: "path", cache: flip(path + 5*n), target: errCacheMismatch},
		{name: "bottom tree node", cache: flip(nodes + 99*n), target: errCacheMismatch},
		{name: "second bottom tree node", cache: flip(second + cachedBottomTreeSize - 1), target: errCacheMismatch},
		{name: "truncated", cache: func(c []byte) []byte { return c[:len(c)-1] }, target: errInvalidLength},
		{name: "trailing byte", cache: func(c []byte) []byte { return append(c, 0) }, target: errInvalidLength},
		{name: "shorter than the top tree", cache: func(c []byte) []byte { return c[:storedTreeSize-1] }, target: errInvalidLength},
		{name: "empty", cache: func([]byte) []byte { return nil }, target: errInvalidLength},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, p, c := seed, pk, append([]byte(nil), cache...)
			if tt.seed != nil {
				s = tt.seed(s)
			}

			if tt.pk != nil {
				p = tt.pk(p)
			}

			if tt.cache != nil {
				c = tt.cache(c)
			}

			if _, err := NewKeyFromCache(s, p, c); !errors.Is(err, tt.target) {
				t.Errorf("error %v, want %v", err, tt.target)
			}
		})
	}
}
