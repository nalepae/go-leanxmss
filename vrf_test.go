package leanxmss

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"golang.org/x/crypto/sha3"
)

func referenceKeccak256(input []byte) [vrfHashSize]byte {
	var out [vrfHashSize]byte

	h := sha3.NewLegacyKeccak256()
	h.Write(input)
	h.Sum(out[:0])

	return out
}

func TestVRFHash(t *testing.T) {
	for _, size := range []int{0, 1, 40, 64, keccakRate - 1} {
		input := make([]byte, size)
		for i := range input {
			input[i] = byte(i*7 + size)
		}

		if vrfHash(input) != referenceKeccak256(input) {
			t.Fatalf("hash of %d bytes differs from Keccak-256", size)
		}
	}
}

// vrfReference is a VRF tree built in full up to a power of two of leaves, to
// check states against.
type vrfReference struct {
	layers [][][sha256.Size]byte
	top    [VRFTreeDepth + 1][sha256.Size]byte
	zeros  [VRFTreeDepth][sha256.Size]byte
}

func newVRFReference(seed [sha256.Size]byte, leaves uint64, depth int) *vrfReference {
	r := &vrfReference{layers: make([][][sha256.Size]byte, depth+1)}
	for level := 1; level < VRFTreeDepth; level++ {
		r.zeros[level] = vrfNode(&r.zeros[level-1], &r.zeros[level-1])
	}

	r.layers[0] = make([][sha256.Size]byte, 1<<depth)
	for i := range leaves {
		var input [sha256.Size + 8]byte

		copy(input[:], seed[:])
		for b := range 8 {
			input[sha256.Size+b] = byte(i >> (8 * b))
		}

		r.layers[0][i] = referenceKeccak256(input[:])
	}

	for level := 1; level <= depth; level++ {
		r.layers[level] = make([][sha256.Size]byte, len(r.layers[level-1])/2)
		for i := range r.layers[level] {
			r.layers[level][i] = referenceKeccak256(append(r.layers[level-1][2*i][:], r.layers[level-1][2*i+1][:]...))
		}
	}

	r.top[depth] = r.layers[depth][0]
	for level := depth; level < VRFTreeDepth; level++ {
		r.top[level+1] = vrfNode(&r.top[level], &r.zeros[level])
	}

	return r
}

func (r *vrfReference) node(level int, index uint64) [sha256.Size]byte {
	switch {
	case level < len(r.layers) && index < uint64(len(r.layers[level])):
		return r.layers[level][index]
	case level >= len(r.layers)-1 && index == 0:
		return r.top[level]
	default:
		return r.zeros[level]
	}
}

func (r *vrfReference) root() [sha256.Size]byte {
	return r.top[VRFTreeDepth]
}

func (r *vrfReference) proof(slot uint32) [VRFProofLen][sha256.Size]byte {
	var proof [VRFProofLen][sha256.Size]byte

	proof[0] = r.node(0, uint64(slot))
	for level := range VRFTreeDepth {
		proof[level+1] = r.node(level, uint64(slot>>level)^1)
	}

	return proof
}

func checkVRFState(t *testing.T, k *VRFKey, r *vrfReference, s *VRFState) {
	t.Helper()

	proof := k.Proof(s)
	if proof != r.proof(s.slot) {
		t.Fatalf("slot %d: proof differs from the full tree's", s.slot)
	}

	if k.Root(s) != r.root() {
		t.Fatalf("slot %d: root differs from the full tree's", s.slot)
	}

	if !VerifyVRFProof(r.root(), uint64(s.slot), &proof) {
		t.Fatalf("slot %d: proof does not verify", s.slot)
	}
}

func vrfTestSeed() [sha256.Size]byte {
	return sha256.Sum256([]byte("leanxmss vrf test"))
}

func mustVRFKey(t *testing.T, seed [sha256.Size]byte, leaves uint64) *VRFKey {
	t.Helper()

	k, err := NewVRFKey(seed, leaves)
	if err != nil {
		t.Fatal(err)
	}

	return k
}

func mustVRFAdvance(t *testing.T, k *VRFKey, s *VRFState, slot uint32) *VRFState {
	t.Helper()

	next, err := k.Advance(s, slot)
	if err != nil {
		t.Fatal(err)
	}

	return next
}

// The vector of the Lighthouse and ethPandaOps genesis tooling: the seed is
// SHA-256("vrf-seed" | BLS secret key) and the first 2^20 leaves are filled.
func TestVRFDevnetVector(t *testing.T) {
	secret, _ := hex.DecodeString("2892f3ba475c3640a67fe730798ad9c4eed3a6d934db85f91c41cfc837ce8834")
	want, _ := hex.DecodeString("46f6772a35c14c7f8467e9d8791450ed3c6853191129876fc50e769ec9bac18d")
	k := mustVRFKey(t, sha256.Sum256(append([]byte("vrf-seed"), secret...)), DefaultVRFLeaves)

	s, err := k.State(0)
	if err != nil {
		t.Fatal(err)
	}

	if root := k.Root(s); !bytes.Equal(root[:], want) {
		t.Fatalf("root %x, want %x", root, want)
	}
}

func TestVRFDefaultFill(t *testing.T) {
	seed := vrfTestSeed()
	k := mustVRFKey(t, seed, DefaultVRFLeaves)
	r := newVRFReference(seed, DefaultVRFLeaves, 20)

	for _, slot := range []uint32{0, 5, 1<<20 - 1, 1 << 20, 1<<31 - 1} {
		s, err := k.State(slot)
		if err != nil {
			t.Fatal(err)
		}

		checkVRFState(t, k, r, s)
	}

	s, err := k.State(1<<19 - 100)
	if err != nil {
		t.Fatal(err)
	}

	for range 200 {
		s = mustVRFAdvance(t, k, s, s.slot+1)
		checkVRFState(t, k, r, s)
	}

	for range 40 {
		s = mustVRFAdvance(t, k, s, s.slot+997)
		checkVRFState(t, k, r, s)
	}

	for shift := 1; shift < VRFTreeDepth; shift++ {
		s = mustVRFAdvance(t, k, s, 1<<shift-1)
		checkVRFState(t, k, r, s)
		s = mustVRFAdvance(t, k, s, 1<<shift)
		checkVRFState(t, k, r, s)
	}

	for _, slot := range []uint32{1<<20 + 7, 1<<20 - 3, 12345, 0, 1<<31 - 1, 1} {
		s = mustVRFAdvance(t, k, s, slot)
		checkVRFState(t, k, r, s)
	}
}

func TestVRFSmallFills(t *testing.T) {
	seed := vrfTestSeed()
	for _, leaves := range []uint64{0, 1, 2, 3, 1000, 1024} {
		k := mustVRFKey(t, seed, leaves)
		r := newVRFReference(seed, leaves, 10)

		walk, err := k.State(0)
		if err != nil {
			t.Fatal(err)
		}

		for slot := range uint32(2200) {
			s, err := k.State(slot)
			if err != nil {
				t.Fatal(err)
			}

			checkVRFState(t, k, r, s)

			walk = mustVRFAdvance(t, k, walk, slot)
			if *walk != *s {
				t.Fatalf("%d leaves, slot %d: advanced state differs from a fresh one", leaves, slot)
			}
		}

		jump := walk
		for i := range uint32(3000) {
			jump = mustVRFAdvance(t, k, jump, (i*i*7919+i*104729)%2200)
			checkVRFState(t, k, r, jump)
		}
	}
}

func TestVRFStateEncoding(t *testing.T) {
	seed := vrfTestSeed()
	k := mustVRFKey(t, seed, 1024)
	r := newVRFReference(seed, 1024, 10)

	s, err := k.State(777)
	if err != nil {
		t.Fatal(err)
	}

	encoded := s.Bytes()
	if len(encoded) != VRFStateSize || VRFStateSize != 996 {
		t.Fatalf("encoded %d bytes, VRFStateSize %d, want 996", len(encoded), VRFStateSize)
	}

	decoded, err := VRFStateFromBytes(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if *decoded != *s {
		t.Fatal("decoded state differs")
	}

	checkVRFState(t, k, r, mustVRFAdvance(t, k, decoded, 900))

	encoded[100] ^= 1

	corrupted, err := VRFStateFromBytes(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if k.Root(corrupted) == r.root() {
		t.Fatal("a corrupted state leads to the root")
	}

	if _, err := VRFStateFromBytes(encoded[1:]); !errors.Is(err, errInvalidLength) {
		t.Fatalf("short encoding: got %v, want errInvalidLength", err)
	}

	encoded[3] = 0x80
	if _, err := VRFStateFromBytes(encoded); !errors.Is(err, errLeafOutside) {
		t.Fatalf("slot past the tree: got %v, want errLeafOutside", err)
	}
}

func TestVRFBounds(t *testing.T) {
	seed := vrfTestSeed()
	if _, err := NewVRFKey(seed, 1<<31+1); !errors.Is(err, errLeafOutside) {
		t.Fatalf("too many leaves: got %v, want errLeafOutside", err)
	}

	if _, err := NewVRFKey(seed, 1<<31); err != nil {
		t.Fatal(err)
	}

	k := mustVRFKey(t, seed, 16)
	if _, err := k.State(1 << 31); !errors.Is(err, errLeafOutside) {
		t.Fatalf("slot past the tree: got %v, want errLeafOutside", err)
	}

	s, err := k.State(9)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := k.Advance(s, 1<<31); !errors.Is(err, errLeafOutside) {
		t.Fatalf("advance past the tree: got %v, want errLeafOutside", err)
	}

	proof := k.Proof(s)
	root := k.Root(s)
	if !VerifyVRFProof(root, 9+1<<31, &proof) {
		t.Fatal("only the 31 low bits of the slot count")
	}

	if VerifyVRFProof(root, 10, &proof) {
		t.Fatal("proof verifies at another slot")
	}

	proof[0][0] ^= 1
	if VerifyVRFProof(root, 9, &proof) {
		t.Fatal("proof of another leaf verifies")
	}
}

// The same state and root as the Rust lean_xmss crate gives for this seed.
func TestVRFSharedVector(t *testing.T) {
	k := mustVRFKey(t, vrfTestSeed(), DefaultVRFLeaves)

	s, err := k.State(777777)
	if err != nil {
		t.Fatal(err)
	}

	encoding := referenceKeccak256(s.Bytes())
	if got := hex.EncodeToString(encoding[:]); got != "63b553b8e581093f7c4631b22aba29bd0ce06d015872f910844ee09c6ca76546" {
		t.Fatalf("Keccak-256 of the encoded state is %s", got)
	}

	root := k.Root(s)
	if got := hex.EncodeToString(root[:]); got != "c2ea7ef9c148cbef3fae2b336c6772d7e815f3dba924abc25e1451ce196b9a37" {
		t.Fatalf("root is %s", got)
	}
}
