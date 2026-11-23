package leanxmss

const (
	n              = 16 // Length of a hash value and of a Merkle node, in bytes.
	publicParamLen = 16 // Length of the public parameter, in bytes.
	addressLen     = 16 // Length of a hash call's address, in bytes.
	randomizerLen  = 16 // Length of the randomizer a layer's message digest is computed under, in bytes.
	leafIndexSize  = 4  // Length of an encoded leaf index, in bytes.

	w          = 2                   // Size of a digit, in bits.
	chainLen   = 1 << w              // 2^w: one more than the steps of a hash chain.
	digits     = 8 * n / w           // Number of base-2^w digits of a 128-bit digest.
	zeroDigits = 6                   // Number of last digits the signer grinds to zero, so they have no chain.
	v          = digits - zeroDigits // Number of chains of a one-time key.
	targetSum  = 106                 // Sum of the v digits of every codeword.

	layerHeight        = 16                                  // Height of each layer's tree.
	layerSignatureSize = randomizerLen + v*n + layerHeight*n // Size of one layer's signature: the randomizer, the chain values and the path.

	maxRandomizerTrials = 1 << 32 // Number of randomizers tried per layer signature.

	seedSize             = 32                                   // Size of a private key's seed, in bytes.
	messageSize          = 32                                   // Size of a signed message, in bytes.
	publicKeySize        = n + publicParamLen                   // Size of an encoded public key, in bytes: the root of the top tree, then the public parameter.
	signatureSize        = leafIndexSize + 2*layerSignatureSize // Size of an encoded signature, in bytes: the leaf index, then the bottom layer's signature, then the top layer's.
	logLifetime          = 2 * layerHeight                      // Base-2 logarithm of the number of leaf indices of a key.
	maxCachedBottomTrees = 4                                    // How many recently used bottom trees a [PrivateKey] caches.

	cachedTreeSize   = cachedNodes * n                                     // Size of a tree's stored level, in bytes.
	cachedBottomSize = leafIndexSize + layerSignatureSize + cachedTreeSize // Size of a cached bottom tree, in bytes: its index, the top layer's signature of its root, then its stored level.
)

// Hash types, the low five bits of an address's byte 7.
const (
	tweakPRF        uint8 = 0
	tweakChain      uint8 = 1
	tweakLeaf       uint8 = 2
	tweakNode       uint8 = 3
	tweakParameter  uint8 = 5
	tweakRandomizer uint8 = 7
	tweakMsg        uint8 = 12
)

const topFlag uint32 = 1 << 23 // Set in an address's hi field on the top layer.

// Compile-time checks of the derived sizes, as in the reference implementation:
// indexing a one-element array with a constant other than 0 does not compile.
var (
	_ = [1]int{}[v-58]
	_ = [1]int{}[publicKeySize-32]
	_ = [1]int{}[layerSignatureSize-1200]
	_ = [1]int{}[signatureSize-2404]
	_ = [1]int{}[cachedTreeSize-4096]
	_ = [1]int{}[cachedBottomSize-5300]
	_ = [1]int{}[logLifetime-8*leafIndexSize]
	_ = [1]int{}[v%2] // the chain starts come in pairs
)
