package leanxmss

import (
	"bytes"
	"errors"
	"testing"
)

func compactSeed() [seedSize]byte {
	var seed [seedSize]byte
	for i := range seed {
		seed[i] = 1
	}

	return seed
}

func checkSame(t *testing.T, sk *PrivateKey, ck *CompactKey, state *CompactState, message [messageSize]byte) {
	t.Helper()

	got, err := ck.Sign(state, message)
	if err != nil {
		t.Fatalf("compact sign at %d: %v", state.leaf, err)
	}

	want := mustSign(t, sk, state.leaf, message)
	if !bytes.Equal(got.Bytes(), want.Bytes()) {
		t.Fatalf("leaf %d: compact signature differs from the library's", state.leaf)
	}

	if !Verify(sk.PublicKey(), state.leaf, message, got) {
		t.Fatalf("leaf %d: compact signature does not verify", state.leaf)
	}
}

func TestCompactMatchesLibrary(t *testing.T) {
	sk := sharedKey()
	ck := NewCompactKey(compactSeed())
	message := testMessage()

	t.Run("attestation pattern, +1 from 2^15", func(t *testing.T) {
		state, err := sk.CompactState(1 << 15)
		if err != nil {
			t.Fatal(err)
		}

		pk, ok := ck.PublicKey(state)
		if !ok || pk != sk.PublicKey() {
			t.Fatal("public key recovered from the compact state differs")
		}

		checkSame(t, sk, ck, state, message)
		for range 70 {
			if state, err = ck.Advance(state, state.leaf+1); err != nil {
				t.Fatal(err)
			}

			checkSame(t, sk, ck, state, message)
		}
	})

	t.Run("serialization round trip", func(t *testing.T) {
		state, err := sk.CompactState(1<<15 + 5)
		if err != nil {
			t.Fatal(err)
		}

		encoded := state.Bytes()
		if len(encoded) != CompactStateSize {
			t.Fatalf("encoded %d bytes, want %d", len(encoded), CompactStateSize)
		}

		decoded, err := CompactStateFromBytes(encoded)
		if err != nil {
			t.Fatal(err)
		}

		if decoded, err = ck.Advance(decoded, 1<<15+900); err != nil {
			t.Fatal(err)
		}

		checkSame(t, sk, ck, decoded, message)
	})

	t.Run("half-tree boundary, and no going back", func(t *testing.T) {
		state, err := sk.CompactState(1<<15 - 1)
		if err != nil {
			t.Fatal(err)
		}

		if state, err = ck.Advance(state, 1<<15); err != nil {
			t.Fatal(err)
		}

		checkSame(t, sk, ck, state, message)

		if _, err = ck.Advance(state, 12345); !errors.Is(err, errLeafBehind) {
			t.Fatalf("advancing backwards: got %v, want errLeafBehind", err)
		}
	})

	t.Run("proposer pattern, jumps of about 8000 leaves", func(t *testing.T) {
		base := uint32(1<<15 + 1<<29 + 1<<30)
		state, err := sk.CompactState(base)
		if err != nil {
			t.Fatal(err)
		}

		checkSame(t, sk, ck, state, message)
		for _, slot := range []uint32{997, 2003, 2999, 4001, 4095} {
			if state, err = ck.Advance(state, base+slot*8); err != nil {
				t.Fatal(err)
			}

			checkSame(t, sk, ck, state, message)
		}

		if _, err = ck.Advance(state, base+4096*8); err == nil {
			t.Fatal("advancing into the next bottom tree must fail")
		}
	})
}
