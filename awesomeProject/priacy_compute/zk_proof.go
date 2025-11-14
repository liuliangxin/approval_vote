package priacy_compute

import (
	"crypto/rand"
	"fmt"
	"math/bits"
	"os"

	plonkbn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/backend/witness"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	scs "github.com/consensys/gnark/frontend/cs/scs"

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

// 上取 2 次幂
func nextPow2(n int) int {
	if n <= 1 {
		return 1
	}
	return 1 << (bits.Len(uint(n - 1)))
}

func (n *Node) buildAndProveCount(
	T []uint64, d, t, k uint64,
	srs *bn254kzg.SRS, srsLag bn254kzg.SRS,
) (proof *plonkbn254.Proof, vk *plonkbn254.VerifyingKey, pub bn254fr.Vector, err error) {

	// Log the entry to the function
	fmt.Println("[buildAndProveCount] Called")

	// 1) 用 R1CS builder 编译（域传模数 *big.Int）
	var circuit CountCircuit
	fmt.Println("[buildAndProveCount] Compiling circuit with R1CS builder")
	ccs, err := frontend.Compile(bn254fr.Modulus(), scs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compile failed: %w", err)
	}
	fmt.Println("[buildAndProveCount] Circuit compiled successfully")

	// 2) 将接口断言为 *cs.SparseR1CS（注意是顶层 cs 包，不是 r1cs 子包）
	spr, ok := ccs.(*cs.SparseR1CS)
	if !ok {
		return nil, nil, nil, fmt.Errorf("expected *cs.SparseR1CS, got %T", ccs)
	}

	// ========= 2.5) 就地确保 SRS 尺寸足够 =========
	// 估算 FFT 域基数：约束数 + 公共输入，上取 2 次幂
	nbConstraints := spr.GetNbConstraints()
	nbPublic := len(spr.Public)
	cardinality := nextPow2(nbConstraints + nbPublic)
	needPk := cardinality + 3 // gnark plonk 里对 canonical SRS 的要求
	needLag := cardinality    // lagrange 版刚好 = cardinality

	// canonical SRS: 不足则重建
	if srs == nil || len(srs.Pk.G1) < needPk {
		fmt.Printf("[buildAndProveCount] (re)build canonical SRS: needPk=%d (was %d)\n",
			needPk, func() int {
				if srs == nil {
					return 0
				}
				return len(srs.Pk.G1)
			}())

		tau, err2 := rand.Int(rand.Reader, bn254fr.Modulus())
		if err2 != nil {
			return nil, nil, nil, fmt.Errorf("rand.Int: %w", err2)
		}
		tmp, _ := bn254kzg.NewSRS(uint64(needPk), tau)
		srs = tmp
	}

	// lagrange SRS: 不等于 needLag 就重建
	if srsLag.Pk.G1 == nil || len(srsLag.Pk.G1) != needLag {
		fmt.Printf("[buildAndProveCount] (re)build lagrange SRS: needLag=%d (was %d)\n",
			needLag, len(srsLag.Pk.G1))

		tau, err2 := rand.Int(rand.Reader, bn254fr.Modulus())
		if err2 != nil {
			return nil, nil, nil, fmt.Errorf("rand.Int lagrange: %w", err2)
		}

		tmpLag, _ := bn254kzg.NewSRS(uint64(needLag), tau)
		srsLag = *tmpLag
	}
	// ========= /SRS 就地保证 =========

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
	//ht := Poseidon2MD_HT_BN254(T, int(assign.M))
	//assign.HT = ht
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

	// 生成 Solidity 验证合约
	fmt.Println("[ProveAndBroadcastCount] Exporting Solidity verifier contract...")
	if err := exportVerifier(vk2, "Verifier.sol"); err != nil {
		return nil, nil, nil, fmt.Errorf("export solidity verifier failed: %w", err)
	}
	fmt.Println("[ProveAndBroadcastCount] Solidity verifier contract saved as Verifier.sol")

	// Return the proof, verification key, and public vector
	return proof, vk2, pub, nil
}

func exportVerifier(vk *plonkbn254.VerifyingKey, outPath string) error {
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// 默认导出 Solidity 0.8.x 兼容合约
	// 可选参数：solidity.WithSolidityVersion("0.8.20")
	return vk.ExportSolidity(f)
}

func (n *Node) verifyCount(
	proof *plonkbn254.Proof, vk *plonkbn254.VerifyingKey, pub bn254fr.Vector,
) error {
	if err := plonkbn254.Verify(proof, vk, pub); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	return nil
}

//func Poseidon2MD_HT_BN254(T []uint64, M int) *big.Int {
//	// 创建 poseidon2 宽度=2 的参数
//	params := p2.NewParameters(2, p2.DefaultNbFullRounds(), p2.DefaultNbPartialRounds())
//
//	// state = [left, right]，初始 [0, 0]；我们用 left 作为“状态”
//	var left, right fr.Element
//	left.SetZero()
//	right.SetZero()
//
//	for i := 0; i < len(T); i++ {
//		// 只在 i < M 时“喂入” T[i]，否则相当于喂 0
//		if i < M {
//			right.SetUint64(T[i])
//		} else {
//			right.SetZero()
//		}
//
//		// 执行 2-lane 置换
//		// p2.Permutation 接受一个长度为2的切片并就地置换
//		lanes := [2]fr.Element{left, right}
//		p2.Permutation(params, lanes[:]) // 置换后在 lanes 里
//
//		// Merkle–Damgård 的压缩输出为 (right_lane_after + right_input)
//		// 注意：gnark/std 的 poseidon2.Compress 返回的是 api.Add(vars[1], right)
//		lanes[1].Add(&lanes[1], &right)
//
//		// 新状态 = 压缩输出；下一轮继续
//		left = lanes[1]
//		// right 在下一轮会被覆盖
//	}
//
//	// 返回最终状态（left）
//	out := new(big.Int)
//	left.BigInt(out)
//	return out
//}
