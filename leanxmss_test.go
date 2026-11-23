package leanxmss

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"golang.org/x/crypto/sha3"
)

func keccak256(b []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)

	return h.Sum(nil)
}

func testMessage() [messageSize]byte {
	var m [messageSize]byte
	for i := range m {
		m[i] = byte(i*3 + 7)
	}

	return m
}

// testSeed returns the seed of sharedKey.
func testSeed() [seedSize]byte {
	var seed [seedSize]byte
	for i := range seed {
		seed[i] = 1
	}

	return seed
}

// sharedKey is one full key for the tests that only need some key, generated once.
var sharedKey = sync.OnceValue(func() *PrivateKey {
	return NewKeyFromSeed(testSeed())
})

// mustSign signs message at leafIndex with sk, and fails the test on an error.
func mustSign(tb testing.TB, sk *PrivateKey, leafIndex uint32, message [messageSize]byte) *Signature {
	tb.Helper()
	sig, err := sk.Sign(leafIndex, message)
	if err != nil {
		tb.Fatalf("sign at %d: %v", leafIndex, err)
	}

	return sig
}

// mustPrepare prepares leafIndex's bottom tree in sk, and fails the test on an
// error.
func mustPrepare(tb testing.TB, sk *PrivateKey, leafIndex uint32) {
	tb.Helper()
	if err := sk.Prepare(leafIndex); err != nil {
		tb.Fatalf("prepare %d: %v", leafIndex, err)
	}
}

// TestAddressLayout checks the address layout, and Th as Keccak-256 of P | A | M
// truncated, with the reference implementation's values.
func TestAddressLayout(t *testing.T) {
	tw := newTweak(tweakNode, layerHi(1, 0x12), 0x89abcdef).withStep(5)
	var addr [addressLen]byte
	putAddress(&addr, tw)
	want := []byte{0xef, 0xcd, 0xab, 0x89, 0x12, 0x00, 0x80, 0xa3, 0, 0, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(addr[:], want) {
		t.Errorf("address %x, want %x", addr, want)
	}

	var pp publicParam
	for i := range pp {
		pp[i] = byte(i) + 1
	}

	payload := bytes.Repeat([]byte{9}, n)
	input := append(append(append([]byte{}, pp[:]...), addr[:]...), payload...)
	got := newHasher().th(&pp, tw, payload)
	if !bytes.Equal(got[:], keccak256(input)[:n]) {
		t.Errorf("Th %x, want the first %d bytes of %x", got, n, keccak256(input))
	}
}

// TestCodeword checks the codeword predicate against a direct count of the digits.
func TestCodeword(t *testing.T) {
	k := newHasher()
	hits := 0

	for i := range 1 << 16 {
		var r randomizer
		r[0], r[1] = byte(i), byte(i>>8)
		k.reset()
		k.write(r[:])
		d := k.truncated()

		var sum, high int
		for j := range digits {
			digit := int(d[j/4]>>(2*(j%4))) & 3
			if j < v {
				sum += digit
				continue
			}

			high |= digit
		}

		wantOK := high == 0 && sum == targetSum
		x, ok := codeword(&d)
		if ok != wantOK {
			t.Fatalf("digest %x: codeword %v, want %v", d, ok, wantOK)
		}

		if ok {
			hits++
			for j := range v {
				if int(x[j]) != int(d[j/4]>>(2*(j%4)))&3 {
					t.Fatalf("digest %x: digit %d is %d", d, j, x[j])
				}
			}
		}
	}

	// Random digests are codewords about once in 2^20, so hits is usually 0:
	// TestCodewordConstructed covers the positive answers.
	_ = hits
}

// TestCodewordConstructed checks codewords built digit by digit, so the predicate's
// positive answers are tested too: random digests are codewords about once in 2^20.
func TestCodewordConstructed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		digits [digits]uint8
		ok     bool
	}{
		{name: "target sum", digits: digitsSumming(targetSum), ok: true},
		{name: "one below", digits: digitsSumming(targetSum - 1), ok: false},
		{name: "one above", digits: digitsSumming(targetSum + 1), ok: false},
		{name: "high digit set", digits: withDigit(digitsSumming(targetSum), digits-1, 1), ok: false},
		{name: "first zero digit set", digits: withDigit(digitsSumming(targetSum), v, 2), ok: false},
	} {
		var d digest
		for j, digit := range tc.digits {
			d[j/4] |= digit << (2 * (j % 4))
		}

		x, ok := codeword(&d)
		if ok != tc.ok {
			t.Errorf("%s: codeword %v, want %v", tc.name, ok, tc.ok)
		}

		if !ok {
			continue
		}

		for j := range v {
			if x[j] != tc.digits[j] {
				t.Errorf("%s: digit %d is %d, want %d", tc.name, j, x[j], tc.digits[j])
			}
		}
	}
}

// digitsSumming returns v digits summing to sum, spread over every digit value,
// followed by zeroDigits zeros.
func digitsSumming(sum int) [digits]uint8 {
	var d [digits]uint8
	for j := range v {
		d[j] = uint8(j % chainLen)
	}

	current := 0
	for j := range v {
		current += int(d[j])
	}

	for j := 0; current != sum; j = (j + 1) % v {
		switch {
		case current < sum && d[j] < chainLen-1:
			d[j]++
			current++
		case current > sum && d[j] > 0:
			d[j]--
			current--
		}
	}

	return d
}

func withDigit(d [digits]uint8, j int, digit uint8) [digits]uint8 {
	d[j] = digit
	return d
}

func TestAddTrialCarries(t *testing.T) {
	r := addTrial(u128{lo: ^uint64(0), hi: 7}, 1)
	want := randomizer{8: 8}
	if r != want {
		t.Errorf("carry: %x, want %x", r, want)
	}

	r = addTrial(u128{lo: ^uint64(0), hi: ^uint64(0)}, 2)
	want = randomizer{0: 1}
	if r != want {
		t.Errorf("wrap: %x, want %x", r, want)
	}
}

// TestSignVerify signs in two bottom trees, prepared at once on two goroutines, and
// checks that the signatures verify, that signing is deterministic, and that a
// signature moved to another leaf index or put on another message does not verify.
func TestSignVerify(t *testing.T) {
	sk := sharedKey()
	pk := sk.PublicKey()
	message := testMessage()
	other := uint32(7<<layerHeight + 3)

	var (
		wg       sync.WaitGroup
		otherErr error
	)

	wg.Go(func() { otherErr = sk.Prepare(other) })
	mustPrepare(t, sk, 5)
	wg.Wait()
	if otherErr != nil {
		t.Fatalf("prepare %d: %v", other, otherErr)
	}

	first := mustSign(t, sk, 5, message)
	if !Verify(pk, 5, message, first) {
		t.Fatal("signature at 5 does not verify")
	}

	otherTree := mustSign(t, sk, other, message)
	if !Verify(pk, other, message, otherTree) {
		t.Fatal("signature in another bottom tree does not verify")
	}

	if first.top == otherTree.top {
		t.Error("two bottom trees share a top-layer signature")
	}

	if again := mustSign(t, sk, 5, message); !bytes.Equal(again.Bytes(), first.Bytes()) {
		t.Error("signing is not deterministic")
	}

	if first.LeafIndex() != 5 {
		t.Errorf("signature at leaf index %d, want 5", first.LeafIndex())
	}

	if Verify(pk, 4, message, first) {
		t.Error("a signature verifies at another leaf index")
	}

	moved := first.Bytes()
	moved[0] = 4
	movedSig, err := SignatureFromBytes(moved)
	if err != nil {
		t.Fatal(err)
	}

	if Verify(pk, 4, message, movedSig) {
		t.Error("a signature moved to leaf index 4 verifies")
	}

	otherMessage := message
	otherMessage[0] ^= 1
	if Verify(pk, 5, otherMessage, first) {
		t.Error("a signature verifies on another message")
	}

	otherKey := NewKeyFromSeed([seedSize]byte{2})
	if Verify(otherKey.PublicKey(), 5, message, first) {
		t.Error("a signature verifies under another key")
	}

	if Verify(pk, 5, message, nil) {
		t.Error("a nil signature verifies")
	}
}

// TestTamperedSignature flips each byte of a signature in turn and checks that none
// verifies. Every byte is covered: the leaf index, both randomizers, every chain
// value and every path node.
func TestTamperedSignature(t *testing.T) {
	if testing.Short() {
		t.Skip("signs and verifies 2,404 signatures")
	}

	sk := sharedKey()
	pk := sk.PublicKey()
	message := testMessage()
	encoded := mustSign(t, sk, 5, message).Bytes()
	for i := range encoded {
		tampered := bytes.Clone(encoded)
		tampered[i] ^= 0x01
		sig, err := SignatureFromBytes(tampered)
		if err != nil {
			t.Fatal(err)
		}

		// At the leaf index it carries, so a flipped leaf index byte is caught by
		// the hashes, not by the leaf index check.
		if Verify(pk, sig.LeafIndex(), message, sig) {
			t.Fatalf("a signature with byte %d flipped verifies", i)
		}
	}
}

func TestLastLeafIndex(t *testing.T) {
	sk := sharedKey()
	message := testMessage()
	sig := mustSign(t, sk, 0xFFFFFFFF, message)
	if !Verify(sk.PublicKey(), 0xFFFFFFFF, message, sig) {
		t.Error("the signature at the last leaf index does not verify")
	}
}

func TestEncodingRoundTrip(t *testing.T) {
	sk := sharedKey()
	pk := sk.PublicKey()
	pkBytes := pk.Bytes()
	if len(pkBytes) != publicKeySize {
		t.Fatalf("public key of %d bytes", len(pkBytes))
	}

	decodedPK, err := PublicKeyFromBytes(pkBytes)
	if err != nil || decodedPK != pk {
		t.Fatalf("public key round trip: %v", err)
	}

	sig := mustSign(t, sk, 1, testMessage())
	sigBytes := sig.Bytes()
	if len(sigBytes) != signatureSize {
		t.Fatalf("signature of %d bytes", len(sigBytes))
	}

	decoded, err := SignatureFromBytes(sigBytes)
	if err != nil || *decoded != *sig {
		t.Fatalf("signature round trip: %v", err)
	}

	if decoded.LeafIndex() != 1 {
		t.Errorf("leaf index %d, want 1", decoded.LeafIndex())
	}
}

func TestInvalidLengths(t *testing.T) {
	for _, size := range []int{0, publicKeySize - 1, publicKeySize + 1} {
		if _, err := PublicKeyFromBytes(make([]byte, size)); !errors.Is(err, errInvalidLength) {
			t.Errorf("public key of %d bytes: %v", size, err)
		}
	}

	for _, size := range []int{0, signatureSize - 1, signatureSize + 1} {
		if _, err := SignatureFromBytes(make([]byte, size)); !errors.Is(err, errInvalidLength) {
			t.Errorf("signature of %d bytes: %v", size, err)
		}
	}
}

// TestBottomTreeCache checks that the cache keeps the maxCachedBottomTrees trees
// used last, and that a signature from a rebuilt tree is the same.
func TestBottomTreeCache(t *testing.T) {
	if testing.Short() {
		t.Skip("builds 10 bottom trees")
	}

	sk := sharedKey()
	message := testMessage()
	first := mustSign(t, sk, 0, message).Bytes()
	for tree := uint32(1); tree <= maxCachedBottomTrees; tree++ {
		mustPrepare(t, sk, tree<<layerHeight)
	}

	func() {
		sk.mu.Lock()
		defer sk.mu.Unlock()

		if len(sk.bottoms) != maxCachedBottomTrees {
			t.Errorf("%d cached trees, want %d", len(sk.bottoms), maxCachedBottomTrees)
		}

		for _, b := range sk.bottoms {
			if b.index == 0 {
				t.Error("the least recently used tree is still cached")
			}
		}
	}()

	// Using tree 1 makes it the most recently used, so tree 2 is evicted next.
	mustPrepare(t, sk, 1<<layerHeight)
	if again := mustSign(t, sk, 0, message).Bytes(); !bytes.Equal(again, first) {
		t.Error("a signature from a rebuilt bottom tree differs")
	}

	sk.mu.Lock()
	defer sk.mu.Unlock()

	cached := map[uint32]bool{}
	for _, b := range sk.bottoms {
		cached[b.index] = true
	}

	if !cached[0] || !cached[1] || cached[2] {
		t.Errorf("cached trees %v, want 0 and 1 cached and 2 evicted", cached)
	}

	if last := sk.bottoms[len(sk.bottoms)-1].index; last != 0 {
		t.Errorf("most recently used tree %d, want 0", last)
	}
}

// TestConcurrentSigning signs from several goroutines at once, in shared and
// separate bottom trees. Run with -race.
func TestConcurrentSigning(t *testing.T) {
	sk := sharedKey()
	pk := sk.PublicKey()
	message := testMessage()
	leaves := []uint32{10, 11, 3<<layerHeight + 1, 3<<layerHeight + 2}
	sigs := make([]*Signature, len(leaves))
	errs := make([]error, len(leaves))
	var wg sync.WaitGroup
	for i, leaf := range leaves {
		wg.Go(func() {
			sigs[i], errs[i] = sk.Sign(leaf, message)
		})
	}

	wg.Wait()

	for i, sig := range sigs {
		if errs[i] != nil {
			t.Errorf("sign at %d: %v", leaves[i], errs[i])
			continue
		}

		if !Verify(pk, leaves[i], message, sig) {
			t.Errorf("signature at %d does not verify", leaves[i])
		}
	}
}

// TestPathOutsideTree checks that asking a tree for the path of a leaf it does not
// hold returns an error instead of panicking.
func TestPathOutsideTree(t *testing.T) {
	tree := &layerTree{index: 1}
	for _, leaf := range []uint32{0, 1<<layerHeight - 1, 2 << layerHeight} {
		if _, err := tree.path(&publicParam{}, &schemeSeed{}, leaf); !errors.Is(err, errLeafOutside) {
			t.Errorf("path of leaf %d: %v", leaf, err)
		}
	}
}
