package leanxmss

import "testing"

// nextBottomTree is the next bottom tree of sharedKey no benchmark has used, so
// each iteration of the benchmarks below builds a tree.
var nextBottomTree = uint32(1 << 10)

// signedLeaves is how many leaf indices BenchmarkSignCachedTree signs at.
const signedLeaves = 40

// freshLeafIndex returns the first leaf index of a bottom tree never built before.
func freshLeafIndex() uint32 {
	nextBottomTree++
	return nextBottomTree << layerHeight
}

func BenchmarkNewKeyFromSeed(b *testing.B) {
	for i := range b.N {
		NewKeyFromSeed([seedSize]byte{byte(i)})
	}
}

// BenchmarkSignCachedTree signs in a bottom tree already built. The randomizer
// search, most of the cost, takes a number of trials that depends on the leaf
// index, so it cycles through the same signedLeaves leaf indices: run it with
// -benchtime 40x, or any multiple of signedLeaves, for figures that compare.
func BenchmarkSignCachedTree(b *testing.B) {
	sk := sharedKey()
	mustPrepare(b, sk, 0)
	message := testMessage()
	b.ResetTimer()

	for i := range b.N {
		mustSign(b, sk, uint32(i%signedLeaves), message)
	}
}

// BenchmarkPrepare builds a bottom tree not cached yet.
func BenchmarkPrepare(b *testing.B) {
	sk := sharedKey()

	for b.Loop() {
		mustPrepare(b, sk, freshLeafIndex())
	}
}

// BenchmarkSignNewTree signs in a bottom tree not cached yet, so each signature
// builds its tree.
func BenchmarkSignNewTree(b *testing.B) {
	sk := sharedKey()
	message := testMessage()

	for b.Loop() {
		mustSign(b, sk, freshLeafIndex(), message)
	}
}

func BenchmarkVerify(b *testing.B) {
	sk := sharedKey()
	message := testMessage()
	sig := mustSign(b, sk, 0, message)
	pk := sk.PublicKey()
	b.ReportAllocs()

	for b.Loop() {
		if !Verify(pk, 0, message, sig) {
			b.Fatal("does not verify")
		}
	}
}

// BenchmarkNewKeyFromCache loads a key from a tree cache of its top tree and two
// bottom trees.
func BenchmarkNewKeyFromCache(b *testing.B) {
	seed, pk, cache := devnet0Key(b)

	for b.Loop() {
		if _, err := NewKeyFromCache(seed, pk, cache); err != nil {
			b.Fatal(err)
		}
	}
}
