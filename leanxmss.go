package leanxmss

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

var (
	errInvalidLength = errors.New("leanxmss: invalid length")         // An encoded public key or signature has the wrong length.
	errNoCodeword    = errors.New("leanxmss: no admissible encoding") // None of a layer's randomizer trials gives a codeword.
	errLeafOutside   = errors.New("leanxmss: leaf outside the tree")  // A leaf is not in the tree asked for its path.
	errLeafBehind    = errors.New("leanxmss: leaf behind the state")  // A compact state is asked to move to an earlier leaf.
)

// PublicKey is a leanXMSS public key: the root of the top tree and the public
// parameter. It is comparable with ==.
type PublicKey struct {
	root        digest
	publicParam publicParam
}

// Bytes returns the 32-byte encoding of pk: the root, then the public
// parameter.
func (pk PublicKey) Bytes() []byte {
	out := make([]byte, 0, publicKeySize)
	out = append(out, pk.root[:]...)

	return append(out, pk.publicParam[:]...)
}

// PublicKeyFromBytes decodes a public key encoded by [PublicKey.Bytes]. It returns
// an error if b is not 32 bytes long.
func PublicKeyFromBytes(b []byte) (PublicKey, error) {
	if len(b) != publicKeySize {
		return PublicKey{}, fmt.Errorf("%w: public key of %d bytes, want %d", errInvalidLength, len(b), publicKeySize)
	}

	var pk PublicKey
	copy(pk.root[:], b[:n])
	copy(pk.publicParam[:], b[n:])

	return pk, nil
}

// layerSignature is one layer's signature: the randomizer, the chain values and the
// authentication path.
type layerSignature struct {
	randomizer  randomizer
	chainValues [v]digest
	path        [layerHeight]digest
}

// Signature is a leanXMSS signature, at one leaf index.
type Signature struct {
	leafIndex uint32
	bottom    layerSignature
	top       layerSignature
}

// LeafIndex returns the leaf index the signature was made at.
func (s *Signature) LeafIndex() uint32 {
	return s.leafIndex
}

// Bytes returns the 2,404-byte encoding of s: the leaf index, little
// endian, then for the bottom layer and then the top layer, the randomizer, the
// chain values and the path.
func (s *Signature) Bytes() []byte {
	out := make([]byte, 0, signatureSize)
	out = binary.LittleEndian.AppendUint32(out, s.leafIndex)
	for _, layer := range []*layerSignature{&s.bottom, &s.top} {
		out = append(out, layer.randomizer[:]...)

		for i := range layer.chainValues {
			out = append(out, layer.chainValues[i][:]...)
		}

		for i := range layer.path {
			out = append(out, layer.path[i][:]...)
		}
	}

	return out
}

// SignatureFromBytes decodes a signature encoded by [Signature.Bytes]. It returns
// an error if b is not 2,404 bytes long. Any bytes of the right
// length decode: whether they form a valid signature is for [Verify] to say.
func SignatureFromBytes(b []byte) (*Signature, error) {
	if len(b) != signatureSize {
		return nil, fmt.Errorf("%w: signature of %d bytes, want %d", errInvalidLength, len(b), signatureSize)
	}

	s := &Signature{leafIndex: binary.LittleEndian.Uint32(b[:leafIndexSize])}
	at := leafIndexSize
	take := func(dst []byte) {
		at += copy(dst, b[at:at+len(dst)])
	}

	for _, layer := range []*layerSignature{&s.bottom, &s.top} {
		take(layer.randomizer[:])
		for i := range layer.chainValues {
			take(layer.chainValues[i][:])
		}

		for i := range layer.path {
			take(layer.path[i][:])
		}
	}

	return s, nil
}

// PrivateKey is a leanXMSS private key: its seed, with the top tree and the bottom
// trees it used last cached to make signing faster. It is safe for concurrent use.
type PrivateKey struct {
	seed        schemeSeed
	publicParam publicParam
	top         *layerTree

	mu      sync.Mutex
	bottoms []*bottomTree // holds the bottom trees the key used last, least recently used first.
}

// bottomTree is a bottom tree, with the top layer's signature of its root.
type bottomTree struct {
	index        uint32
	tree         *layerTree
	topSignature layerSignature
}

// NewKeyFromSeed returns the private key of a seed. The seed is the whole secret:
// keep it private, and derive the key from it again when needed. It builds the
// top tree, about 14 million Keccak-256 permutations spread over all CPUs.
func NewKeyFromSeed(seed [32]byte) *PrivateKey {
	k := newHasher()
	s := k.deriveSchemeSeed(&seed)
	pp := k.derivePublicParam(&s)

	return &PrivateKey{
		seed:        s,
		publicParam: pp,
		top:         buildLayerTree(&pp, &s, 1, 0),
		bottoms:     make([]*bottomTree, 0, maxCachedBottomTrees+1),
	}
}

// PublicKey returns the public key of sk.
func (sk *PrivateKey) PublicKey() PublicKey {
	return PublicKey{root: sk.top.root(), publicParam: sk.publicParam}
}

// Sign returns the signature of message at leafIndex.
//
// Never sign two different messages at the same leaf index with the same key: it
// allows forgeries. Signing is deterministic, so signing the same message at the
// same leaf index again gives the same signature. The first signature in a bottom
// tree builds that tree, see [PrivateKey.Prepare].
//
// Sign returns an error if none of a layer's 2^32 randomizer trials gives a
// codeword, which happens with probability below 2^-2954: never in practice.
func (sk *PrivateKey) Sign(leafIndex uint32, message [32]byte) (*Signature, error) {
	bottom, err := sk.bottomTree(leafIndex)
	if err != nil {
		return nil, fmt.Errorf("bottom tree of leaf %d: %w", leafIndex, err)
	}

	r, values, err := wotsSign(&sk.publicParam, &sk.seed, 0, leafIndex, message[:])
	if err != nil {
		return nil, fmt.Errorf("one-time signature at leaf %d: %w", leafIndex, err)
	}

	path, err := bottom.tree.path(leafIndex)
	if err != nil {
		return nil, fmt.Errorf("authentication path of leaf %d: %w", leafIndex, err)
	}

	return &Signature{
		leafIndex: leafIndex,
		bottom: layerSignature{
			randomizer:  r,
			chainValues: values,
			path:        path,
		},
		top: bottom.topSignature,
	}, nil
}

// Prepare makes later signing at leafIndex faster, by building and caching the
// bottom tree leafIndex is in. The cache holds 8 trees. It returns an error in the
// same never expected case as [PrivateKey.Sign].
func (sk *PrivateKey) Prepare(leafIndex uint32) error {
	if _, err := sk.bottomTree(leafIndex); err != nil {
		return fmt.Errorf("bottom tree of leaf %d: %w", leafIndex, err)
	}

	return nil
}

// bottomTree returns the bottom tree leafIndex is in, with the top layer's
// signature of its root: the cached one, or built and cached. It is built outside
// the lock, which is only held to read or update the cache.
func (sk *PrivateKey) bottomTree(leafIndex uint32) (*bottomTree, error) {
	index := layerIndex(leafIndex, 1)
	cached := func() *bottomTree {
		sk.mu.Lock()
		defer sk.mu.Unlock()

		return sk.useCached(index)
	}()

	if cached != nil {
		return cached, nil
	}

	tree := buildLayerTree(&sk.publicParam, &sk.seed, 0, index)
	root := tree.root()
	r, values, err := wotsSign(&sk.publicParam, &sk.seed, 1, index, root[:])
	if err != nil {
		return nil, fmt.Errorf("top one-time signature of bottom tree %d: %w", index, err)
	}

	topPath, err := sk.top.path(index)
	if err != nil {
		return nil, fmt.Errorf("authentication path of bottom tree %d: %w", index, err)
	}

	bottom := &bottomTree{
		index: index,
		tree:  tree,
		topSignature: layerSignature{
			randomizer:  r,
			chainValues: values,
			path:        topPath,
		},
	}

	sk.mu.Lock()
	defer sk.mu.Unlock()

	// Another goroutine may have built it meanwhile.
	if cached := sk.useCached(index); cached != nil {
		return cached, nil
	}

	sk.bottoms = append(sk.bottoms, bottom)
	if len(sk.bottoms) > maxCachedBottomTrees {
		sk.bottoms = append(sk.bottoms[:0], sk.bottoms[1:]...)
	}

	return bottom, nil
}

// useCached returns bottom tree index if cached, moved to the most recently used
// end, or nil. The caller holds sk.mu.
func (sk *PrivateKey) useCached(index uint32) *bottomTree {
	for at, b := range sk.bottoms {
		if b.index == index {
			copy(sk.bottoms[at:], sk.bottoms[at+1:])
			sk.bottoms[len(sk.bottoms)-1] = b
			return b
		}
	}

	return nil
}

// Verify reports whether sig is a valid signature of message under pk made at
// leafIndex, as the consensus specification's Verify: a valid signature made at
// another leaf index does not verify.
func Verify(pk PublicKey, leafIndex uint32, message [32]byte, sig *Signature) bool {
	if sig == nil || sig.leafIndex != leafIndex {
		return false
	}

	k := newHasher()
	pp := &pk.publicParam
	bottomRoot, ok := k.layerRoot(pp, 0, layerIndex(sig.leafIndex, 0), message[:], &sig.bottom)
	if !ok {
		return false
	}

	root, ok := k.layerRoot(pp, 1, layerIndex(sig.leafIndex, 1), bottomRoot[:], &sig.top)
	return ok && root == pk.root
}

// layerRoot returns the root a layer's signature by key e reaches, or false if its
// digest is not a codeword.
func (k *hasher) layerRoot(pp *publicParam, layer int, e uint32, message []byte, sig *layerSignature) (digest, bool) {
	leaf, ok := k.wotsLeaf(pp, layer, e, message, &sig.randomizer, &sig.chainValues)
	if !ok {
		return digest{}, false
	}
	return k.pathRoot(pp, layer, e, leaf, &sig.path), true
}
