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

// RangeProof结构体用于保存范围证明
type RangeProof struct {
	Commit []byte
	Proof  []byte
	Upper  uint64
}

// MarshalBinary 将 RangeProof 转换为字节数组
func (rp *RangeProof) MarshalBinary() ([]byte, error) {
	// 这里假设 Proof 和 Commit 是字节数组
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

	// 使用 K256 曲线
	curve := curves.K256()

	// 生成生成点
	g := curve.NewGeneratorPoint().Generator()          // 生成点 g
	h := curve.NewGeneratorPoint().Hash([]byte("bp:h")) // 哈希生成点 h
	u := curve.NewGeneratorPoint().Hash([]byte("bp:u")) // 哈希生成点 u

	// Prepare the transcript for Fiat-Shamir heuristic
	transcript := merlin.NewTranscript("range-proof")

	// 创建 RangeProver
	prover, err := bulletproof.NewRangeProver(64, []byte("range-domain"), []byte("ipp-domain"), *curve)
	if err != nil {
		return nil, fmt.Errorf("failed to create range prover: %w", err)
	}

	// 将 sum 转换为 curves.Scalar 类型，并处理错误
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
	// 检查 Pedersen 承诺是否有效
	if !PedersenVerify(com) {
		return false
	}

	// 校验范围证明
	// 将 proof 转换为 bulletproof.RangeProof 对象
	var rp bulletproof.RangeProof
	err := rp.UnmarshalBinary(proof.Proof)
	if err != nil {
		fmt.Printf("failed to unmarshal range proof: %v\n", err)
		return false
	}

	// 使用提供的curve、proof 和合适的transcript来验证范围证明
	curve := curves.K256()

	// 生成证明所需的生成点
	g := curve.NewGeneratorPoint().Generator()
	h := curve.NewGeneratorPoint().Hash([]byte("bp:h"))
	u := curve.NewGeneratorPoint().Hash([]byte("bp:u"))
	// 创建用于 Fiat-Shamir 启发式的 transcript
	transcript := merlin.NewTranscript("range-proof-verify")

	// 生成 capV 承诺
	v := curve.Scalar.Random(rand.Reader)
	gamma := curve.Scalar.Random(rand.Reader)

	// 生成 capV
	capV := g.Mul(gamma).Add(h.Mul(v))

	// 创建范围验证器
	verifier, err := bulletproof.NewRangeVerifier(64, []byte("range-domain"), []byte("ipp-domain"), *curve)
	if err != nil {
		fmt.Printf("failed to create range verifier: %v\n", err)
		return false
	}

	// 验证范围证明
	valid, err := verifier.Verify(&rp, capV, g, h, u, 64, transcript)
	if err != nil || !valid {
		fmt.Printf("failed to verify range proof: %v\n", err)
		return false
	}

	// 返回验证结果
	return true
}
