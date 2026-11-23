package leanxmss

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	storedTreeSize       = storedNodes * n                                     // Size of a tree's stored nodes in a tree cache, in bytes.
	cachedBottomTreeSize = leafIndexSize + layerSignatureSize + storedTreeSize // Size of one bottom tree in a tree cache, in bytes.
)

var errCacheMismatch = errors.New("leanxmss: tree cache does not match the key") // A tree cache's trees are not those of the key.

// Compile-time checks of the tree cache sizes, those of the reference implementation.
var (
	_ = [1]int{}[storedTreeSize-4096]
	_ = [1]int{}[cachedBottomTreeSize-5300]
)

// SeedPublicParam returns the public parameter of the key of seed: the last 16
// bytes of its public key. It costs two hashes, where the whole public key needs
// the top tree. It tells which public key a seed may have, out of known ones.
func SeedPublicParam(seed [32]byte) [16]byte {
	k := newHasher()
	s := k.deriveSchemeSeed(&seed)

	return k.derivePublicParam(&s)
}

// TreeCache returns the trees of sk, for [NewKeyFromCache] to load them without
// building them, in the format of the reference implementation's
// cache_to_bytes: the 2^8 nodes the top tree stores, then for each cached bottom
// tree, least recently used first, its index on 4 bytes little endian, the top
// layer's signature of its root as in a [Signature], and the 2^8 nodes it stores.
// That is 4,096 bytes, plus 5,300 per cached bottom tree.
//
// It holds no secret: the nodes are public, and the top layer's signatures are in
// every signature made in their bottom trees.
func (sk *PrivateKey) TreeCache() []byte {
	bottoms := func() []*bottomTree {
		sk.mu.Lock()
		defer sk.mu.Unlock()

		return append([]*bottomTree(nil), sk.bottoms...)
	}()

	out := make([]byte, 0, storedTreeSize+len(bottoms)*cachedBottomTreeSize)
	out = appendNodes(out, sk.top.stored())
	for _, b := range bottoms {
		out = binary.LittleEndian.AppendUint32(out, b.index)
		out = b.topSignature.append(out)
		out = appendNodes(out, b.tree.stored())
	}

	return out
}

// append appends the encoding of s to out: the randomizer, the chain values and
// the path.
func (s *layerSignature) append(out []byte) []byte {
	out = append(out, s.randomizer[:]...)
	for i := range s.chainValues {
		out = append(out, s.chainValues[i][:]...)
	}

	for i := range s.path {
		out = append(out, s.path[i][:]...)
	}

	return out
}

// appendNodes appends nodes to out.
func appendNodes(out []byte, nodes []digest) []byte {
	for i := range nodes {
		out = append(out, nodes[i][:]...)
	}

	return out
}

// NewKeyFromCache returns the private key of a seed, as [NewKeyFromSeed], with
// its trees loaded from cache, made by [PrivateKey.TreeCache] or the reference
// implementation's cache_to_bytes, instead of built. Loading hashes about 2^8
// nodes per tree: well under a millisecond.
//
// pk must be trusted: it is what the trees are checked against. The top tree must
// reach pk's root, and each bottom tree a root its top layer's signature signs
// under pk, so a cache that loads gives valid signatures. Of more bottom trees
// than the key caches, it keeps the last ones.
//
// It returns an error if seed's public parameter is not pk's, the cache's length
// is not 4,096 plus a multiple of 5,300, or the trees do not match pk. The caller
// can then fall back to [NewKeyFromSeed].
func NewKeyFromCache(seed [32]byte, pk PublicKey, cache []byte) (*PrivateKey, error) {
	if len(cache) < storedTreeSize || (len(cache)-storedTreeSize)%cachedBottomTreeSize != 0 {
		return nil, fmt.Errorf("%w: tree cache of %d bytes, want %d plus a multiple of %d", errInvalidLength, len(cache), storedTreeSize, cachedBottomTreeSize)
	}

	k := newHasher()
	s := k.deriveSchemeSeed(&seed)
	pp := k.derivePublicParam(&s)
	if pp != pk.publicParam {
		return nil, fmt.Errorf("%w: the seed's public parameter is not the public key's", errCacheMismatch)
	}

	top := newLayerTree(&pp, 1, 0, decodeNodes(cache[:storedTreeSize]))
	if top.root() != pk.root {
		return nil, fmt.Errorf("%w: the top tree's root is not the public key's", errCacheMismatch)
	}

	sk := newPrivateKey(s, pp, top)
	for at := storedTreeSize; at < len(cache); at += cachedBottomTreeSize {
		bottom, err := decodeBottomTree(k, &pk, cache[at:at+cachedBottomTreeSize])
		if err != nil {
			return nil, fmt.Errorf("bottom tree at byte %d of the cache: %w", at, err)
		}

		sk.cache(bottom)
	}

	return sk, nil
}

// decodeBottomTree decodes one bottom tree of a tree cache, and checks that the
// top layer's signature of its root verifies under pk.
func decodeBottomTree(k *hasher, pk *PublicKey, b []byte) (*bottomTree, error) {
	index := binary.LittleEndian.Uint32(b)
	if index >= layerWidth {
		return nil, fmt.Errorf("%w: bottom tree index %d, want below %d", errCacheMismatch, index, layerWidth)
	}

	at := leafIndexSize
	take := func(dst []byte) {
		at += copy(dst, b[at:at+len(dst)])
	}

	var sig layerSignature
	take(sig.randomizer[:])
	for i := range sig.chainValues {
		take(sig.chainValues[i][:])
	}

	for i := range sig.path {
		take(sig.path[i][:])
	}

	tree := newLayerTree(&pk.publicParam, 0, index, decodeNodes(b[at:]))
	bottomRoot := tree.root()
	root, ok := k.layerRoot(&pk.publicParam, 1, index, bottomRoot[:], &sig)
	if !ok || root != pk.root {
		return nil, fmt.Errorf("%w: the top layer's signature of bottom tree %d does not verify", errCacheMismatch, index)
	}

	return &bottomTree{index: index, tree: tree, topSignature: sig}, nil
}

// decodeNodes decodes the 2^8 stored nodes b holds.
func decodeNodes(b []byte) []digest {
	nodes := make([]digest, storedNodes)
	for i := range nodes {
		copy(nodes[i][:], b[i*n:])
	}

	return nodes
}
