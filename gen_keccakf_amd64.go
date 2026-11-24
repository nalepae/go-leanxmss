//go:build ignore

// gen_keccakf_amd64 writes keccakf_amd64.s, the AVX2 Keccak-f[1600] of four states at
// once. Run it with go generate. It writes two functions:
//   - keccakF1600x4AVX2 permutes the four states in place.
//   - keccakF1600x4HeadAVX2 permutes four states without changing them, and writes
//     only lanes 0 and 1 of the result, the first 16 bytes of a Keccak-256 digest: its
//     last round computes only those two lanes. The randomizer search uses it.
//
// Lane i of the four states is the 256-bit vector at byte 32i of the state. AVX2 has 16
// vector registers, too few for 25 lanes: the state lives in memory, and each round
// reads it from one buffer and writes it to another. keccakF1600x4AVX2 alternates
// between the argument and an 800-byte buffer on the stack: 24 rounds end in the
// argument. keccakF1600x4HeadAVX2 reads the argument once, then alternates between two
// buffers on the stack.
//
// A round keeps in registers the five θ column parities C of its input, the five θ
// terms D, the five lanes of one output row B, and one temporary T. It computes D from
// C, then each output row: it loads the five lanes π sends there, XORs D into them and
// rotates them by ρ, then applies χ, and ι on the first lane. It stores the row and
// XORs it into C, which ends the round as the parities of its output.
package main

import (
	"fmt"
	"log"
	"os"
	"strings"
)

const (
	laneBytes  = 32  // Bytes of a lane of the four states, a 256-bit vector.
	stateBytes = 800 // Bytes of the four states.
	headLanes  = 2   // Lanes keccakF1600x4HeadAVX2 writes: 0 and 1.
	rounds     = 24  // Rounds of Keccak-f[1600].
	output     = "keccakf_amd64.s"
)

var (
	// roundConstants are the round constants of Keccak-f[1600].
	roundConstants = [rounds]uint64{
		0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
		0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
		0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
		0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
		0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
		0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
	}

	// rows lists, for each output row y and column x, the input lane π moves to lane
	// 5y + x and its ρ rotation, as in keccakF1600.
	rows = [5][5]struct{ lane, rho int }{
		{{0, 0}, {6, 44}, {12, 43}, {18, 21}, {24, 14}},
		{{3, 28}, {9, 20}, {10, 3}, {16, 45}, {22, 61}},
		{{1, 1}, {7, 6}, {13, 25}, {19, 8}, {20, 18}},
		{{4, 27}, {5, 36}, {11, 10}, {17, 15}, {23, 56}},
		{{2, 62}, {8, 55}, {14, 39}, {15, 41}, {21, 2}},
	}
)

// generator accumulates the assembly text.
type generator struct {
	strings.Builder
}

// d, c and b name the registers of the θ terms, the column parities and the output row.
func d(x int) string { return fmt.Sprintf("Y%d", x) }
func c(x int) string { return fmt.Sprintf("Y%d", 5+x) }
func b(x int) string { return fmt.Sprintf("Y%d", 10+x) }

// t is the temporary register.
const t = "Y15"

// emit writes one instruction line.
func (g *generator) emit(format string, args ...any) {
	fmt.Fprintf(g, "\t"+format+"\n", args...)
}

// comment writes a comment line.
func (g *generator) comment(text string) {
	fmt.Fprintf(g, "\n\t// %s\n", text)
}

// rotate writes to register dst the four lanes of register src rotated left by n bits,
// with t as scratch. n is not 0.
func (g *generator) rotate(src, dst string, n int) {
	g.emit("VPSLLQ $%d, %s, %s", n, src, t)
	g.emit("VPSRLQ $%d, %s, %s", 64-n, src, dst)
	g.emit("VPOR %s, %s, %s", t, dst, dst)
}

// round writes one round from the state at src to the state at dst, with the round
// constant at rc.
func (g *generator) round(src, dst, rc string) {
	g.comment("θ: D[x] = C[x-1] ^ rot(C[x+1], 1). The B registers are free.")
	for x := range 5 {
		g.rotate(c((x+1)%5), b(x), 1)
		g.emit("VPXOR %s, %s, %s", c((x+4)%5), b(x), d(x))
	}

	for y := range 5 {
		g.comment(fmt.Sprintf("Row %d: θ, ρ and π into B.", y))
		for x, in := range rows[y] {
			g.emit("VPXOR %d(%s), %s, %s", laneBytes*in.lane, src, d(in.lane%5), b(x))
			if in.rho != 0 {
				g.rotate(b(x), b(x), in.rho)
			}
		}

		g.comment(fmt.Sprintf("Row %d: χ, then ι on lane 0, stored and folded into C.", y))
		for x := range 5 {
			// The first row's output starts the parities of the next round's input.
			out := t
			if y == 0 {
				out = c(x)
			}

			// VPANDN y, x, z computes z = ^x & y.
			g.emit("VPANDN %s, %s, %s", b((x+2)%5), b((x+1)%5), out)
			g.emit("VPXOR %s, %s, %s", b(x), out, out)
			if y == 0 && x == 0 {
				g.emit("VPXOR %s, %s, %s", rc, out, out)
			}

			g.emit("VMOVDQU %s, %d(%s)", out, laneBytes*(5*y+x), dst)
			if y > 0 {
				g.emit("VPXOR %s, %s, %s", t, c(x), c(x))
			}
		}
	}
}

// parities writes the five column parities C of the state at src.
func (g *generator) parities(src string) {
	g.comment("C[x]: the column parities of the input.")
	for x := range 5 {
		g.emit("VMOVDQU %d(%s), %s", laneBytes*x, src, c(x))
		for y := 1; y < 5; y++ {
			g.emit("VPXOR %d(%s), %s, %s", laneBytes*(5*y+x), src, c(x), c(x))
		}
	}
}

// headRound writes the last round from the state at src, computing only the lanes 0
// and 1 of its output, which it stores at out. They need the first four lanes of row
// 0 after θ, ρ and π, so only D[0] to D[3].
func (g *generator) headRound(src, out, rc string) {
	g.comment("θ: D[0] to D[3].")
	for x := range 4 {
		g.rotate(c((x+1)%5), b(x), 1)
		g.emit("VPXOR %s, %s, %s", c((x+4)%5), b(x), d(x))
	}

	g.comment("Row 0, lanes 0 to 3: θ, ρ and π into B.")
	for x, in := range rows[0][:4] {
		g.emit("VPXOR %d(%s), %s, %s", laneBytes*in.lane, src, d(in.lane%5), b(x))
		if in.rho != 0 {
			g.rotate(b(x), b(x), in.rho)
		}
	}

	g.comment("Lanes 0 and 1: χ, then ι on lane 0.")
	for x := range headLanes {
		g.emit("VPANDN %s, %s, %s", b(x+2), b(x+1), t)
		g.emit("VPXOR %s, %s, %s", b(x), t, t)
		if x == 0 {
			g.emit("VPXOR %s, %s, %s", rc, t, t)
		}

		g.emit("VMOVDQU %s, %d(%s)", t, laneBytes*x, out)
	}
}

// permute writes keccakF1600x4AVX2.
func (g *generator) permute() {
	fmt.Fprintf(g, `
// func keccakF1600x4AVX2(s *[100]uint64)
TEXT ·keccakF1600x4AVX2(SB), 0, $%d-8
	MOVQ s+0(FP), SI
	MOVQ SP, DI
	LEAQ round_consts_x4<>(SB), R8
	MOVQ $%d, CX
`, stateBytes, rounds/2)

	g.parities("SI")
	g.WriteString("\nloop:")
	g.comment("Even round: from the argument to the stack.")
	g.round("SI", "DI", "0(R8)")
	g.comment("Odd round: from the stack back to the argument.")
	g.round("DI", "SI", fmt.Sprintf("%d(R8)", laneBytes))
	g.WriteString("\n")
	g.emit("ADDQ $%d, R8", 2*laneBytes)
	g.emit("DECQ CX")
	g.emit("JNZ loop")
	g.emit("VZEROUPPER")
	g.emit("RET")
}

// permuteHead writes keccakF1600x4HeadAVX2: round 0 from the argument to buffer A on
// the stack, rounds 1 to 22 between A and buffer B, ending in A, and the last round
// from A to out.
func (g *generator) permuteHead() {
	fmt.Fprintf(g, `
// func keccakF1600x4HeadAVX2(s *[100]uint64, out *[%d]uint64)
TEXT ·keccakF1600x4HeadAVX2(SB), 0, $%d-16
	MOVQ s+0(FP), SI
	MOVQ out+8(FP), DX
	MOVQ SP, DI
	LEAQ %d(SP), BX
	LEAQ round_consts_x4<>(SB), R8
	MOVQ $%d, CX
`, 4*headLanes, 2*stateBytes, stateBytes, (rounds-2)/2)

	g.parities("SI")
	g.comment("Round 0: from the argument, left unchanged, to A.")
	g.round("SI", "DI", "0(R8)")
	g.emit("ADDQ $%d, R8", laneBytes)
	g.WriteString("\nloopHead:")
	g.comment("Odd round: from A to B.")
	g.round("DI", "BX", "0(R8)")
	g.comment("Even round: from B back to A.")
	g.round("BX", "DI", fmt.Sprintf("%d(R8)", laneBytes))
	g.WriteString("\n")
	g.emit("ADDQ $%d, R8", 2*laneBytes)
	g.emit("DECQ CX")
	g.emit("JNZ loopHead")
	g.headRound("DI", "DX", "0(R8)")
	g.WriteString("\n")
	g.emit("VZEROUPPER")
	g.emit("RET")
}

// generate returns the whole assembly file.
func generate() string {
	var g generator
	g.WriteString(`// Code generated by gen_keccakf_amd64.go. DO NOT EDIT.

//go:build amd64 && !purego

#include "textflag.h"
`)

	g.permute()
	g.permuteHead()

	g.WriteString("\n// Each round constant, once per state.\n")
	for i, rc := range roundConstants {
		for j := range 4 {
			fmt.Fprintf(&g, "DATA round_consts_x4<>+0x%03x(SB)/8, $0x%016x\n", laneBytes*i+8*j, rc)
		}
	}

	fmt.Fprintf(&g, "GLOBL round_consts_x4<>(SB), NOPTR|RODATA, $%d\n", laneBytes*rounds)
	return g.String()
}

func main() {
	if err := os.WriteFile(output, []byte(generate()), 0o644); err != nil {
		log.Fatal(fmt.Errorf("write %s: %w", output, err))
	}
}
