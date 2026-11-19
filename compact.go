package leanxmss

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"runtime"
	"sync"
)

// CompactStateSize is the length of an encoded [CompactState], in bytes.
const CompactStateSize = leafIndexSize + layerHeight*n + n + layerSignatureSize

// CompactKey signs from a seed and a [CompactState], without holding any tree.
type CompactKey struct {
	seed        schemeSeed
	publicParam publicParam
}

// CompactState is what signing at one leaf needs besides the seed: the leaf's
// authentication path in its bottom tree, that tree's root, and the top layer's
// signature of the root. It holds nothing secret: every signature made from it
// publishes the same values.
type CompactState struct {
	leaf uint32
	path [layerHeight]digest
	root digest
	top  layerSignature
}

// NewCompactKey returns the compact key of a seed. It builds no tree.
func NewCompactKey(seed [32]byte) *CompactKey {
	k := newHasher()
	s := k.deriveSchemeSeed(&seed)

	return &CompactKey{seed: s, publicParam: k.derivePublicParam(&s)}
}

// CompactState returns the compact state of sk at leafIndex, building the bottom
// tree leafIndex is in if it is not cached.
func (sk *PrivateKey) CompactState(leafIndex uint32) (*CompactState, error) {
	bottom, err := sk.bottomTree(leafIndex)
	if err != nil {
		return nil, err
	}

	path, err := bottom.tree.path(leafIndex)
	if err != nil {
		return nil, err
	}

	return &CompactState{leaf: leafIndex, path: path, root: bottom.tree.root(), top: bottom.topSignature}, nil
}

// LeafIndex returns the leaf the state signs at.
func (s *CompactState) LeafIndex() uint32 {
	return s.leaf
}

// Bytes returns the encoding of s, [CompactStateSize] bytes long.
func (s *CompactState) Bytes() []byte {
	out := make([]byte, 0, CompactStateSize)
	out = binary.LittleEndian.AppendUint32(out, s.leaf)
	for i := range s.path {
		out = append(out, s.path[i][:]...)
	}

	out = append(out, s.root[:]...)
	out = append(out, s.top.randomizer[:]...)
	for i := range s.top.chainValues {
		out = append(out, s.top.chainValues[i][:]...)
	}

	for i := range s.top.path {
		out = append(out, s.top.path[i][:]...)
	}

	return out
}

// CompactStateFromBytes decodes a state encoded by [CompactState.Bytes]. Check it
// against the expected public key with [CompactKey.PublicKey] before signing.
func CompactStateFromBytes(b []byte) (*CompactState, error) {
	if len(b) != CompactStateSize {
		return nil, fmt.Errorf("%w: compact state of %d bytes, want %d", errInvalidLength, len(b), CompactStateSize)
	}

	s := &CompactState{leaf: binary.LittleEndian.Uint32(b[:leafIndexSize])}
	at := leafIndexSize
	take := func(dst []byte) {
		at += copy(dst, b[at:at+len(dst)])
	}

	for i := range s.path {
		take(s.path[i][:])
	}

	take(s.root[:])
	take(s.top.randomizer[:])
	for i := range s.top.chainValues {
		take(s.top.chainValues[i][:])
	}

	for i := range s.top.path {
		take(s.top.path[i][:])
	}

	return s, nil
}

// PublicKey returns the public key s leads to under ck's seed. It is false if the
// top layer's signature in s does not decode.
func (ck *CompactKey) PublicKey(s *CompactState) (PublicKey, bool) {
	k := newHasher()
	root, ok := k.layerRoot(&ck.publicParam, 1, layerIndex(s.leaf, 1), s.root[:], &s.top)

	return PublicKey{root: root, publicParam: ck.publicParam}, ok
}

// Advance returns the state at leafIndex, a later leaf of the bottom tree s is
// in. It recomputes the leaves of the subtree below the level where the two
// leaves' paths part, at most half the tree. Moving to an earlier leaf is
// refused: a state must never sign two messages at one leaf.
func (ck *CompactKey) Advance(s *CompactState, leafIndex uint32) (*CompactState, error) {
	if layerIndex(leafIndex, 1) != layerIndex(s.leaf, 1) {
		return nil, fmt.Errorf("%w: leaf %d is not in the bottom tree of leaf %d", errLeafOutside, leafIndex, s.leaf)
	}

	if leafIndex < s.leaf {
		return nil, fmt.Errorf("%w: leaf %d is before leaf %d", errLeafBehind, leafIndex, s.leaf)
	}

	next := *s
	next.leaf = leafIndex
	if leafIndex == s.leaf {
		return &next, nil
	}

	pp, seed := &ck.publicParam, &ck.seed
	split := bits.Len32(leafIndex^s.leaf) - 1

	k := newHasher()
	current := k.wotsPublicLeaf(pp, seed, 0, s.leaf)
	for z := range split {
		sibling := s.path[z]
		if (s.leaf>>z)&1 == 0 {
			current = k.node(pp, 0, z+1, s.leaf>>(z+1), &current, &sibling)
			continue
		}

		current = k.node(pp, 0, z+1, s.leaf>>(z+1), &sibling, &current)
	}

	next.path[split] = current

	width := 1 << split
	first := (leafIndex >> split) << split
	level := make([]digest, width)
	workers := min(runtime.GOMAXPROCS(0), width)

	var wg sync.WaitGroup
	for i := range workers {
		from, to := i*width/workers, (i+1)*width/workers
		wg.Go(func() {
			h := newHasher()
			for j := from; j < to; j++ {
				level[j] = h.wotsPublicLeaf(pp, seed, 0, first+uint32(j))
			}
		})
	}

	wg.Wait()

	for z := range split {
		next.path[z] = level[((leafIndex-first)>>z)^1]
		up := make([]digest, len(level)/2)
		base := first >> (z + 1)
		for j := range up {
			up[j] = k.node(pp, 0, z+1, base+uint32(j), &level[2*j], &level[2*j+1])
		}

		level = up
	}

	return &next, nil
}

// Sign returns the signature of message at the leaf of s, identical to the one
// [PrivateKey.Sign] returns at that leaf.
//
// Never sign two different messages with the same state: it allows forgeries.
func (ck *CompactKey) Sign(s *CompactState, message [32]byte) (*Signature, error) {
	r, values, err := wotsSign(&ck.publicParam, &ck.seed, 0, s.leaf, message[:])
	if err != nil {
		return nil, fmt.Errorf("one-time signature at leaf %d: %w", s.leaf, err)
	}

	return &Signature{
		leafIndex: s.leaf,
		bottom: layerSignature{
			randomizer:  r,
			chainValues: values,
			path:        s.path,
		},
		top: s.top,
	}, nil
}
