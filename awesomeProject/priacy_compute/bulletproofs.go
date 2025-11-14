package priacy_compute

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/coinbase/kryptology/pkg/bulletproof"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/gtank/merlin"
)

type RangeProof struct {
	Commit []byte
	Proof  []byte
	Upper  uint64
}

func (rp *RangeProof) MarshalBinary() ([]byte, error) {

	var result []byte
	result = append(result, rp.Commit...)
	result = append(result, rp.Proof...)
	return result, nil
}

func GenerateRangeProof(sum *big.Int, upper uint64, com *PedersenCommitment) (*RangeProof, error) {
	if sum == nil || sum.Sign() < 0 {
		return nil, errors.New("sum cannot be negative")
	}
	if com == nil || com.Value == nil || com.Value.Cmp(sum) != 0 {
		return nil, errors.New("commitment mismatch with sum")
	}

	curve := curves.K256()

	g := curve.NewGeneratorPoint().Generator()
	h := curve.NewGeneratorPoint().Hash([]byte("bp:h"))
	u := curve.NewGeneratorPoint().Hash([]byte("bp:u"))

	// Prepare the transcript for Fiat-Shamir heuristic
	transcript := merlin.NewTranscript("range-proof")

	// RangeProver
	prover, err := bulletproof.NewRangeProver(64, []byte("range-domain"), []byte("ipp-domain"), *curve)
	if err != nil {
		return nil, fmt.Errorf("failed to create range prover: %w", err)
	}

	sumScalar, err := curve.NewScalar().SetBigInt(sum)
	if err != nil {
		return nil, fmt.Errorf("failed to set BigInt to Scalar: %w", err)
	}

	// Prove that the sum is less than or equal to the upper bound (2^n)
	rp, err := prover.Prove(sumScalar, curve.Scalar.Random(rand.Reader), 64, g, h, u, transcript)
	if err != nil {
		return nil, fmt.Errorf("failed to generate range proof: %w", err)
	}

	// Return the generated proof
	return &RangeProof{
		Commit: com.Commit,
		Proof:  rp.MarshalBinary(),
		Upper:  upper,
	}, nil
}
func VerifyRangeProof(com *PedersenCommitment, proof *RangeProof, upper uint64) bool {

	if !PedersenVerify(com) {
		return false
	}

	var rp bulletproof.RangeProof
	err := rp.UnmarshalBinary(proof.Proof)
	if err != nil {
		fmt.Printf("failed to unmarshal range proof: %v\n", err)
		return false
	}

	curve := curves.K256()

	g := curve.NewGeneratorPoint().Generator()
	h := curve.NewGeneratorPoint().Hash([]byte("bp:h"))
	u := curve.NewGeneratorPoint().Hash([]byte("bp:u"))

	transcript := merlin.NewTranscript("range-proof-verify")

	v := curve.Scalar.Random(rand.Reader)
	gamma := curve.Scalar.Random(rand.Reader)

	capV := g.Mul(gamma).Add(h.Mul(v))

	verifier, err := bulletproof.NewRangeVerifier(64, []byte("range-domain"), []byte("ipp-domain"), *curve)
	if err != nil {
		fmt.Printf("failed to create range verifier: %v\n", err)
		return false
	}

	valid, err := verifier.Verify(&rp, capV, g, h, u, 64, transcript)
	if err != nil || !valid {
		fmt.Printf("failed to verify range proof: %v\n", err)
		return false
	}

	return true
}
