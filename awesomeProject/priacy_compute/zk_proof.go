package priacy_compute

import (
	"fmt"
	plonkbn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/backend/witness"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	r1cs "github.com/consensys/gnark/frontend/cs/r1cs"

	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254kzg "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

// 与电路公开输入一致（若电路里有 gnark:",public" 的字段，这里都要有）
type CountPublic struct {
	T    [MaxM]frontend.Variable `gnark:",public"`
	M    frontend.Variable       `gnark:",public"`
	D    frontend.Variable       `gnark:",public"`
	Tmax frontend.Variable       `gnark:",public"`
	K    frontend.Variable       `gnark:",public"`
}

func (n *Node) buildAndProveCount(
	T []uint64, d, t, k uint64,
	srs *bn254kzg.SRS, srsLag bn254kzg.SRS,
) (proof *plonkbn254.Proof, vk *plonkbn254.VerifyingKey, pub bn254fr.Vector, err error) {

	// Log the entry to the function
	fmt.Println("[buildAndProveCount] Called")

	// 先确保已加载/构建一次
	if err := n.ensureSetupCount(); err != nil {
		return nil, nil, nil, err
	}
	// 1) 用 R1CS builder 编译（域传模数 *big.Int）
	var circuit CountCircuit
	fmt.Println("[buildAndProveCount] Compiling circuit with R1CS builder")
	ccs, err := frontend.Compile(bn254fr.Modulus(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compile failed: %w", err)
	}
	fmt.Println("[buildAndProveCount] Circuit compiled successfully")

	// 2) 将接口断言为 *cs.SparseR1CS（注意是顶层 cs 包，不是 r1cs 子包）
	spr, ok := ccs.(*cs.SparseR1CS)
	if !ok {
		return nil, nil, nil, fmt.Errorf("expected *cs.SparseR1CS, got %T", ccs)
	}

	// 3) 准备公开 assignment（必须与电路公开字段一一对应）
	fmt.Println("[buildAndProveCount] Preparing public assignment")
	if len(T) > MaxM {
		return nil, nil, nil, fmt.Errorf("T len=%d > MaxM=%d", len(T), MaxM)
	}
	var assign CountCircuit
	for i := 0; i < MaxM; i++ {
		if i < len(T) {
			assign.T[i] = T[i]
		} else {
			assign.T[i] = 0
		}
	}
	assign.M = uint64(len(T))
	assign.D = d
	assign.Tmax = t
	assign.K = k
	fmt.Println("[buildAndProveCount] Public assignment prepared")

	// 4) 构造 full witness（同样传模数）
	fmt.Println("[buildAndProveCount] Constructing full witness")
	var w witness.Witness
	w, err = frontend.NewWitness(&assign, bn254fr.Modulus())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new witness: %w", err)
	}
	fmt.Println("[buildAndProveCount] Full witness constructed successfully")

	// 4.1) 取公开部分：w.Public()（不是包级函数）
	wPub, err := w.Public()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("public(): %w", err)
	}

	// 4.2) 从公开 witness 里取底层向量，并断言为 bn254fr.Vector（Verify 需要）
	vecAny := wPub.Vector()
	var ok2 bool
	pub, ok2 = vecAny.(bn254fr.Vector)
	if !ok2 {
		return nil, nil, nil, fmt.Errorf("unexpected public vector type %T", vecAny)
	}
	fmt.Println("[buildAndProveCount] Public vector extracted successfully")

	// 5) Setup：传 *SparseR1CS + bn254/kzg.SRS（值类型）
	fmt.Println("[buildAndProveCount] Running setup with SparseR1CS and SRS")
	pk, vk2, err := plonkbn254.Setup(spr, *srs, srsLag)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("setup: %w", err)
	}
	fmt.Println("[buildAndProveCount] Setup completed successfully")

	// 6) Prove：同样传 *SparseR1CS + full witness
	fmt.Println("[buildAndProveCount] Generating proof")
	proof, err = plonkbn254.Prove(spr, pk, w)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("prove: %w", err)
	}
	fmt.Println("[buildAndProveCount] Proof generated successfully")

	// Return the proof, verification key, and public vector
	return proof, vk2, pub, nil
}

func (n *Node) verifyCount(
	proof *plonkbn254.Proof, vk *plonkbn254.VerifyingKey, pub bn254fr.Vector,
) error {
	if err := plonkbn254.Verify(proof, vk, pub); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	return nil
}
