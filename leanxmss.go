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
	errCacheMismatch = errors.New("leanxmss: cache does not match")   // A tree cache does not match the key it is loaded for.
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

// PublicParamFromSeed returns the public parameter of the key of a seed, the last
// 16 bytes of its public key, without building the key: it costs two hashes. It
// tells which public key is a seed's among known ones, as [NewKeyFromCache] needs.
func PublicParamFromSeed(seed [32]byte) [16]byte {
	k := newHasher()
	s := k.deriveSchemeSeed(&seed)

	return k.derivePublicParam(&s)
}

// layerSignature is one layer's signature: the randomizer, the chain values and the
// authentication path.
type layerSignature struct {
	randomizer  randomizer
	chainValues [v]digest
	path        [layerHeight]digest
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

// read decodes s from the front of b, at least layerSignatureSize bytes long, and
// returns the number of bytes read.
func (s *layerSignature) read(b []byte) int {
	at := copy(s.randomizer[:], b)
	for i := range s.chainValues {
		at += copy(s.chainValues[i][:], b[at:])
	}

	for i := range s.path {
		at += copy(s.path[i][:], b[at:])
	}

	return at
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
	out = s.bottom.append(out)

	return s.top.append(out)
}

// SignatureFromBytes decodes a signature encoded by [Signature.Bytes]. It returns
// an error if b is not 2,404 bytes long. Any bytes of the right
// length decode: whether they form a valid signature is for [Verify] to say.
func SignatureFromBytes(b []byte) (*Signature, error) {
	if len(b) != signatureSize {
		return nil, fmt.Errorf("%w: signature of %d bytes, want %d", errInvalidLength, len(b), signatureSize)
	}

	s := &Signature{leafIndex: binary.LittleEndian.Uint32(b[:leafIndexSize])}
	at := leafIndexSize + s.bottom.read(b[leafIndexSize:])
	s.top.read(b[at:])

	return s, nil
}

// PrivateKey is a leanXMSS private key: its seed, with the top tree and the bottom
// trees it used last cached to make signing faster. It stores one level of each
// tree and recomputes the rest per path. It is safe for concurrent use.
type PrivateKey struct {
	seed      schemeSeed
	publicKey PublicKey
	top       *layerTree

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

	return newPrivateKey(s, pp, buildLayerTree(&pp, &s, 1, 0))
}

func newPrivateKey(seed schemeSeed, pp publicParam, top *layerTree) *PrivateKey {
	return &PrivateKey{
		seed:      seed,
		publicKey: PublicKey{root: top.root(&pp), publicParam: pp},
		top:       top,
		bottoms:   make([]*bottomTree, 0, maxCachedBottomTrees+1),
	}
}

// NewKeyFromCache returns the private key of a seed, from its public key and the
// tree cache [PrivateKey.CacheBytes] returns, without building the top tree or
// the cached bottom trees. It returns an error if the length of cache is wrong
// or if cache does not match the key.
//
// Each tree's stored level is checked: the top tree's must hash to the public
// key's root, and each bottom tree's to a root its top-layer signature signs under
// the public key. The levels below are recomputed from the seed, so a loaded key
// signs as a built one.
func NewKeyFromCache(seed [32]byte, publicKey PublicKey, cache []byte) (*PrivateKey, error) {
	if len(cache) < cachedTreeSize || (len(cache)-cachedTreeSize)%cachedBottomSize != 0 {
		return nil, fmt.Errorf("%w: tree cache of %d bytes, want %d and a multiple of %d", errInvalidLength, len(cache), cachedTreeSize, cachedBottomSize)
	}

	k := newHasher()
	s := k.deriveSchemeSeed(&seed)
	pp := k.derivePublicParam(&s)
	sk := newPrivateKey(s, pp, layerTreeFromBytes(1, 0, cache[:cachedTreeSize]))
	if sk.publicKey != publicKey {
		return nil, fmt.Errorf("%w: the top tree is not the public key's", errCacheMismatch)
	}

	for rest := cache[cachedTreeSize:]; len(rest) > 0; rest = rest[cachedBottomSize:] {
		index := binary.LittleEndian.Uint32(rest[:leafIndexSize])
		if index>>layerHeight != 0 {
			return nil, fmt.Errorf("%w: bottom tree %d outside the key", errCacheMismatch, index)
		}

		bottom := &bottomTree{index: index}
		at := leafIndexSize + bottom.topSignature.read(rest[leafIndexSize:])
		bottom.tree = layerTreeFromBytes(0, index, rest[at:cachedBottomSize])
		bottomRoot := bottom.tree.root(&pp)
		root, ok := k.layerRoot(&pp, 1, index, bottomRoot[:], &bottom.topSignature)
		if !ok || root != publicKey.root {
			return nil, fmt.Errorf("%w: bottom tree %d is not signed under the public key", errCacheMismatch, index)
		}

		sk.cache(bottom)
	}

	return sk, nil
}

// CacheBytes returns the tree cache of sk, which holds no secret: the stored
// level of the top tree, 4,096 bytes, then for each cached bottom tree, least
// recently used first, 5,300 bytes: its index, little endian, the top layer's
// signature of its root and its stored level. [NewKeyFromCache] loads it.
func (sk *PrivateKey) CacheBytes() []byte {
	sk.mu.Lock()
	defer sk.mu.Unlock()

	out := make([]byte, 0, cachedTreeSize+len(sk.bottoms)*cachedBottomSize)
	out = sk.top.appendNodes(out)
	for _, b := range sk.bottoms {
		out = binary.LittleEndian.AppendUint32(out, b.index)
		out = b.topSignature.append(out)
		out = b.tree.appendNodes(out)
	}

	return out
}

// PublicKey returns the public key of sk.
func (sk *PrivateKey) PublicKey() PublicKey {
	return sk.publicKey
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

	pp := &sk.publicKey.publicParam
	r, values, err := wotsSign(pp, &sk.seed, 0, leafIndex, message[:])
	if err != nil {
		return nil, fmt.Errorf("one-time signature at leaf %d: %w", leafIndex, err)
	}

	path, err := bottom.tree.path(pp, &sk.seed, leafIndex)
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
// bottom tree leafIndex is in. The cache holds 4 trees. It returns an error in the
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

	pp := &sk.publicKey.publicParam
	tree := buildLayerTree(pp, &sk.seed, 0, index)
	root := tree.root(pp)
	r, values, err := wotsSign(pp, &sk.seed, 1, index, root[:])
	if err != nil {
		return nil, fmt.Errorf("top one-time signature of bottom tree %d: %w", index, err)
	}

	topPath, err := sk.top.path(pp, &sk.seed, index)
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

	return sk.cache(bottom), nil
}

// cache caches bottom, or returns the one another goroutine cached first.
func (sk *PrivateKey) cache(bottom *bottomTree) *bottomTree {
	sk.mu.Lock()
	defer sk.mu.Unlock()

	if cached := sk.useCached(bottom.index); cached != nil {
		return cached
	}

	sk.bottoms = append(sk.bottoms, bottom)
	if len(sk.bottoms) > maxCachedBottomTrees {
		sk.bottoms = append(sk.bottoms[:0], sk.bottoms[1:]...)
	}

	return bottom
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
