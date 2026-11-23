package leanxmss

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// The leaves the cached keys of testdata/treecache are prepared for: one in
// bottom tree 0, one in bottom tree 24576.
const (
	cachedLeafA = uint32(1 << 15)
	cachedLeafB = uint32(1<<15 + 1<<29 + 1<<30)
)

// cachedKey is a key whose tree cache, as the reference implementation's
// cache_to_bytes returns it at leanVM v0.15.0, is in testdata/treecache: key
// index of ethereum-package's default mnemonic, with the seed
// sha256("leanxmss-seed" | sk) of its BLS secret key sk at m/12381/3600/index/0/0.
type cachedKey struct {
	index     int
	seed      string
	publicKey string
}

var cachedKeys = []cachedKey{
	{0, "6d78e7072bfcbde1a75261f6e16772ea352de90462819cdc53e05f10d4700ad1", "d7792e263b94cf0b7a9f70d8374c6d34a600b4247057d4079f810caff711c632"},
	{1, "2c14f6af9af2d9215485b9d70d48899ecbc0284ca2fbe27bee7015ff0f532f4d", "fe121c8562eed8363ea83f94d63c982adb7114cfa36d6dd614603ceaf56edaad"},
	{9999, "a17fed608f6d5a80857ae0810c39e987127aa4a2b4d2cfdaab076722e7bee1df", "925a578bb3a8b9509d993dc2c90f4c83c700e438969af13b9695cd556ff06d73"},
}

func (c cachedKey) load(tb testing.TB) ([seedSize]byte, PublicKey, []byte) {
	tb.Helper()
	seed, err := hex.DecodeString(c.seed)
	if err != nil {
		tb.Fatal(err)
	}

	pkBytes, err := hex.DecodeString(c.publicKey)
	if err != nil {
		tb.Fatal(err)
	}

	pk, err := PublicKeyFromBytes(pkBytes)
	if err != nil {
		tb.Fatal(err)
	}

	cache, err := os.ReadFile(filepath.Join("testdata", "treecache", fmt.Sprintf("key_%d.xmss", c.index)))
	if err != nil {
		tb.Fatal(err)
	}

	return [seedSize]byte(seed), pk, cache
}

// TestNewKeyFromCache loads the reference implementation's tree caches, and
// checks the keys encode them back.
func TestNewKeyFromCache(t *testing.T) {
	for _, c := range cachedKeys {
		seed, pk, cache := c.load(t)
		if len(cache) != cachedTreeSize+2*cachedBottomSize {
			t.Fatalf("key %d: cache of %d bytes", c.index, len(cache))
		}

		if pp := PublicParamFromSeed(seed); !bytes.Equal(pp[:], pk.Bytes()[n:]) {
			t.Errorf("key %d: public parameter %x, want %x", c.index, pp, pk.Bytes()[n:])
		}

		sk, err := NewKeyFromCache(seed, pk, cache)
		if err != nil {
			t.Fatalf("key %d: %v", c.index, err)
		}

		if sk.PublicKey() != pk {
			t.Errorf("key %d: public key %x, want %x", c.index, sk.PublicKey().Bytes(), pk.Bytes())
		}

		if !bytes.Equal(sk.CacheBytes(), cache) {
			t.Errorf("key %d: the cache of the loaded key differs", c.index)
		}

		top, err := NewKeyFromCache(seed, pk, cache[:cachedTreeSize])
		if err != nil {
			t.Fatalf("key %d, top tree only: %v", c.index, err)
		}

		if !bytes.Equal(top.CacheBytes(), cache[:cachedTreeSize]) {
			t.Errorf("key %d: the cache of the key loaded from the top tree differs", c.index)
		}
	}
}

// TestCachedKeyMatchesBuiltKey checks that a key built from its seed and prepared
// for the cached trees has the reference implementation's cache, and that the key
// loaded from it signs as the built one, in the cached trees and outside them.
func TestCachedKeyMatchesBuiltKey(t *testing.T) {
	message := testMessage()
	for at, c := range cachedKeys {
		if at > 0 && testing.Short() {
			t.Skip("builds 4 trees per key")
		}

		seed, pk, cache := c.load(t)
		built := NewKeyFromSeed(seed)
		if built.PublicKey() != pk {
			t.Fatalf("key %d: public key %x, want %x", c.index, built.PublicKey().Bytes(), pk.Bytes())
		}

		mustPrepare(t, built, cachedLeafA)
		mustPrepare(t, built, cachedLeafB)
		if !bytes.Equal(built.CacheBytes(), cache) {
			t.Errorf("key %d: the cache of the built key differs", c.index)
		}

		loaded, err := NewKeyFromCache(seed, pk, cache)
		if err != nil {
			t.Fatalf("key %d: %v", c.index, err)
		}

		leaves := []uint32{cachedLeafA, cachedLeafB, cachedLeafA + 300, cachedLeafB - 1<<15, cachedLeafB + 1<<15 - 1}
		if at == 0 {
			leaves = append(leaves, 1<<layerHeight+5)
		}

		for _, leaf := range leaves {
			want := mustSign(t, built, leaf, message)
			got := mustSign(t, loaded, leaf, message)
			if !bytes.Equal(got.Bytes(), want.Bytes()) {
				t.Errorf("key %d: the signature of the loaded key at %d differs", c.index, leaf)
			}

			if !Verify(pk, leaf, message, got) {
				t.Errorf("key %d: the signature of the loaded key at %d does not verify", c.index, leaf)
			}
		}
	}
}

// TestNewKeyFromCacheRejects checks that a cache of the wrong length, a cache
// with any part tampered with, and a cache of another key are refused.
func TestNewKeyFromCacheRejects(t *testing.T) {
	seed, pk, cache := cachedKeys[0].load(t)
	otherSeed, otherPK, otherCache := cachedKeys[1].load(t)

	for _, length := range []int{0, 1, cachedTreeSize - 1, cachedTreeSize + 1, cachedTreeSize + cachedBottomSize - 1, len(cache) - 1, len(cache) + 1} {
		b := make([]byte, length)
		copy(b, cache)
		if _, err := NewKeyFromCache(seed, pk, b); !errors.Is(err, errInvalidLength) {
			t.Errorf("cache of %d bytes: %v", length, err)
		}
	}

	bottomA, bottomB := cachedTreeSize, cachedTreeSize+cachedBottomSize
	tampered := map[string]int{
		"first top node":           0,
		"last top node":            cachedTreeSize - 1,
		"first bottom index":       bottomA,
		"first bottom randomizer":  bottomA + leafIndexSize,
		"first bottom chain value": bottomA + leafIndexSize + randomizerLen + 7*n,
		"first bottom top path":    bottomA + leafIndexSize + layerSignatureSize - 1,
		"first bottom node":        bottomA + leafIndexSize + layerSignatureSize,
		"second bottom index":      bottomB + 1,
		"second bottom top path":   bottomB + leafIndexSize + randomizerLen + v*n,
		"last bottom node":         len(cache) - 1,
	}

	for name, at := range tampered {
		b := bytes.Clone(cache)
		b[at] ^= 1
		if _, err := NewKeyFromCache(seed, pk, b); !errors.Is(err, errCacheMismatch) {
			t.Errorf("tampered %s: %v", name, err)
		}
	}

	outside := bytes.Clone(cache)
	binary.LittleEndian.PutUint32(outside[bottomA:], 1<<layerHeight)
	if _, err := NewKeyFromCache(seed, pk, outside); !errors.Is(err, errCacheMismatch) {
		t.Errorf("bottom tree index outside the key: %v", err)
	}

	swapped := bytes.Clone(cache)
	copy(swapped[bottomA:bottomB], otherCache[bottomA:bottomB])
	if _, err := NewKeyFromCache(seed, pk, swapped); !errors.Is(err, errCacheMismatch) {
		t.Errorf("bottom tree of another key: %v", err)
	}

	if _, err := NewKeyFromCache(seed, otherPK, cache); !errors.Is(err, errCacheMismatch) {
		t.Errorf("another public key: %v", err)
	}

	if _, err := NewKeyFromCache(otherSeed, pk, cache); !errors.Is(err, errCacheMismatch) {
		t.Errorf("another seed: %v", err)
	}

	if _, err := NewKeyFromCache(seed, pk, otherCache); !errors.Is(err, errCacheMismatch) {
		t.Errorf("the cache of another key: %v", err)
	}

	wrongRoot := pk
	wrongRoot.root[0] ^= 1
	if _, err := NewKeyFromCache(seed, wrongRoot, cache); !errors.Is(err, errCacheMismatch) {
		t.Errorf("a public key with another root: %v", err)
	}
}

// TestCacheKeepsLastUsedTrees checks that loading more bottom trees than the
// cache holds keeps the last ones.
func TestCacheKeepsLastUsedTrees(t *testing.T) {
	seed, pk, cache := cachedKeys[0].load(t)
	bottoms := cache[cachedTreeSize:]
	long := bytes.Clone(cache)
	for len(long) < cachedTreeSize+(maxCachedBottomTrees+2)*cachedBottomSize {
		long = append(long, bottoms...)
	}

	sk, err := NewKeyFromCache(seed, pk, long)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(sk.CacheBytes(), cache) {
		t.Error("the cache of a key loaded from repeated bottom trees differs")
	}
}
