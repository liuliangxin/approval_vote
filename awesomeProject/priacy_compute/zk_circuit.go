// package priacy_compute

// import (
// 	"github.com/consensys/gnark/frontend"
// 	"github.com/consensys/gnark/std/hash"
// 	poseidon2hash "github.com/consensys/gnark/std/hash/poseidon2"
// )

// // 最大候选上限（编译期常量）
// const MaxM = 64
// const Kmax = 8 //

// // CountCircuit: 计票电路（公开输入即可；后续可把某些量改为私密+哈希绑定）
// type CountCircuit struct {
// 	// 公开输入
// 	T  [MaxM]frontend.Variable `gnark:",public"` // 票数向量（多余槽位填 0）
// 	HT frontend.Variable       `gnark:",public"`
// 	//A    [MaxM]frontend.Variable `gnark:",public"`
// 	M      frontend.Variable       `gnark:",public"` // 实际候选人数 (<= MaxM)
// 	D      frontend.Variable       `gnark:",public"` // d: 哈希个数
// 	Tmax   frontend.Variable       `gnark:",public"` // t: 每人最多批准数
// 	K      frontend.Variable       `gnark:",public"` // Top-K
// 	TopIdx [Kmax]frontend.Variable `gnark:",public"`
// 	// （可选）把 Poseidon(T) 做成公开承诺，这里先不加，跑通再加
// }

// // Define 里用 frontend.API 写约束
// func (c *CountCircuit) Define(api frontend.API) error {

// 	// --- 1) 对 T 做承诺并与公开 HT 绑定 ---
// 	var h hash.FieldHasher
// 	var err error
// 	h, err = poseidon2hash.NewMerkleDamgardHasher(api)
// 	if err != nil {
// 		return err // 这里不要忽略 err
// 	}

// 	// --- 1) 对 T 做承诺并与公开 HT 绑定 ---
// 	for i := 0; i < MaxM; i++ {
// 		// active = 1{ i < M }
// 		cmp := api.Cmp(c.M, i) // 1 if M>i, 0 if M=i, -1 if M<i
// 		active := api.Select(api.IsZero(api.Sub(cmp, 1)), 0, 1)
// 		ti := api.Mul(c.T[i], active)
// 		h.Write(ti)
// 	}
// 	api.AssertIsEqual(h.Sum(), c.HT)

// 	// maxVotes = d * k
// 	maxVotes := api.Mul(c.D, c.K)

// 	// 1) 边界约束：0 ≤ T[i] ≤ d*k
// 	for i := 0; i < MaxM; i++ {
// 		// 如果 i >= M，mask=0，表示无效槽位
// 		cmp := api.Cmp(c.M, i)                                  // 1 if M>i, 0 if M=i, -1 if M<i
// 		active := api.Select(api.IsZero(api.Sub(cmp, 1)), 0, 1) // (M>i) ? 1 : 0

// 		ti := api.Mul(c.T[i], active)
// 		api.AssertIsLessOrEqual(ti, maxVotes)
// 		api.AssertIsLessOrEqual(0, ti) // 确保非负
// 	}

// 	// 2) 总和约束： sum(T[0..M-1]) ≤ d * k * M
// 	sum := frontend.Variable(0)
// 	for i := 0; i < MaxM; i++ {
// 		cmp := api.Cmp(c.M, i)
// 		active := api.Select(api.IsZero(api.Sub(cmp, 1)), 0, 1)
// 		ti := api.Mul(c.T[i], active)
// 		sum = api.Add(sum, ti)
// 	}
// 	api.AssertIsLessOrEqual(sum, api.Mul(maxVotes, c.M))

// 	// 3) Top-K 简化：要求至少 K 个候选得票 ≥ 1
// 	cntGE := frontend.Variable(0)
// 	one := frontend.Variable(1)
// 	for i := 0; i < MaxM; i++ {
// 		cmp := api.Cmp(c.M, i)
// 		active := api.Select(api.IsZero(api.Sub(cmp, 1)), 0, 1)
// 		ti := api.Mul(c.T[i], active)
// 		ge := api.Select(api.IsZero(api.Cmp(ti, one)), 1, 0) // (ti≥1)?1:0
// 		cntGE = api.Add(cntGE, ge)
// 	}
// 	api.AssertIsLessOrEqual(c.K, cntGE)

// 	return nil
// }
//package priacy_compute
//
//import (
//	"github.com/consensys/gnark/frontend"
//	"github.com/consensys/gnark/std/hash"
//	poseidon2hash "github.com/consensys/gnark/std/hash/poseidon2"
//)
//
//// 最大候选上限（编译期常量）
//const MaxM = 64
//const Kmax = 8 //
//
//// CountCircuit: 计票电路（公开输入即可；后续可把某些量改为私密+哈希绑定）
//type CountCircuit struct {
//	// 公开输入
//	T  [MaxM]frontend.Variable `gnark:",public"` // 票数向量（多余槽位填 0）
//	HT frontend.Variable       `gnark:",public"`
//	//A    [MaxM]frontend.Variable `gnark:",public"`
//	M      frontend.Variable       `gnark:",public"` // 实际候选人数 (<= MaxM)
//	D      frontend.Variable       `gnark:",public"` // d: 哈希个数
//	Tmax   frontend.Variable       `gnark:",public"` // t: 每人最多批准数
//	K      frontend.Variable       `gnark:",public"` // Top-K
//	TopIdx [Kmax]frontend.Variable `gnark:",public"`
//	// （可选）把 Poseidon(T) 做成公开承诺，这里先不加，跑通再加
//}
//
//// Define 里用 frontend.API 写约束
//func (c *CountCircuit) Define(api frontend.API) error {
//
//	// --- 1) 对 T 做承诺并与公开 HT 绑定 ---
//	var h hash.FieldHasher
//	var err error
//	h, err = poseidon2hash.NewMerkleDamgardHasher(api)
//	if err != nil {
//		return err // 这里不要忽略 err
//	}
//
//	// --- 1) 对 T 做承诺并与公开 HT 绑定 ---
//	for i := 0; i < MaxM; i++ {
//		// active = 1{ i < M }
//		cmp := api.Cmp(c.M, i) // 1 if M>i, 0 if M==i, -1 if M<i
//		// active = (cmp == 1) ? 1 : 0
//		active := api.Select(api.IsZero(api.Sub(cmp, 1)), 1, 0)
//		ti := api.Mul(c.T[i], active)
//
//		h.Write(ti)
//
//	}
//	api.AssertIsEqual(h.Sum(), c.HT)
//
//	// maxVotes = d * k
//	maxVotes := api.Mul(c.D, c.K)
//
//	// 1) 边界约束：0 ≤ T[i] ≤ d*k
//	for i := 0; i < MaxM; i++ {
//		// 如果 i >= M，mask=0，表示无效槽位
//		cmp := api.Cmp(c.M, i)                                  // 1 if M>i, 0 if M=i, -1 if M<i
//		active := api.Select(api.IsZero(api.Sub(cmp, 1)), 1, 0) // (M>i) ? 1 : 0
//
//		ti := api.Mul(c.T[i], active)
//		api.AssertIsLessOrEqual(ti, maxVotes)
//		api.AssertIsLessOrEqual(0, ti) // 确保非负
//	}
//
//	// 2) 总和约束： sum(T[0..M-1]) ≤ d * k * M
//	sum := frontend.Variable(0)
//	for i := 0; i < MaxM; i++ {
//		cmp := api.Cmp(c.M, i)
//		active := api.Select(api.IsZero(api.Sub(cmp, 1)), 1, 0)
//		ti := api.Mul(c.T[i], active)
//		sum = api.Add(sum, ti)
//	}
//	api.AssertIsLessOrEqual(sum, api.Mul(maxVotes, c.M))
//
//	// 3) Top-K 简化：要求至少 K 个候选得票 ≥ 1
//	cntGE := frontend.Variable(0)
//	one := frontend.Variable(1)
//	for i := 0; i < MaxM; i++ {
//		cmp := api.Cmp(c.M, i)
//		active := api.Select(api.IsZero(api.Sub(cmp, 1)), 1, 0)
//		ti := api.Mul(c.T[i], active)
//		ge := api.Select(api.IsZero(api.Cmp(ti, one)), 1, 0) // (ti≥1)?1:0
//		cntGE = api.Add(cntGE, ge)
//	}
//	api.AssertIsLessOrEqual(c.K, cntGE)
//
//	return nil
//}

package priacy_compute

import (
	"github.com/consensys/gnark/frontend"
)

const MaxM = 256

// CountCircuit:
type CountCircuit struct {
	// 公开输入
	T    [MaxM]frontend.Variable `gnark:",public"` //
	A    [MaxM]frontend.Variable `gnark:",public"`
	M    frontend.Variable       `gnark:",public"` //
	D    frontend.Variable       `gnark:",public"` //
	Tmax frontend.Variable       `gnark:",public"` //
	K    frontend.Variable       `gnark:",public"` //

}

func (c *CountCircuit) Define(api frontend.API) error {
	// maxVotes = d * k
	maxVotes := api.Mul(c.D, c.K)

	for i := 0; i < MaxM; i++ {

		cmp := api.Cmp(c.M, i)                                  // 1 if M>i, 0 if M=i, -1 if M<i
		active := api.Select(api.IsZero(api.Sub(cmp, 1)), 0, 1) // (M>i) ? 1 : 0

		ti := api.Mul(c.T[i], active)
		api.AssertIsLessOrEqual(ti, maxVotes)
		api.AssertIsLessOrEqual(0, ti) //
	}

	// 2) 总和约束： sum(T[0..M-1]) ≤ d * k * M
	sum := frontend.Variable(0)
	for i := 0; i < MaxM; i++ {
		cmp := api.Cmp(c.M, i)
		active := api.Select(api.IsZero(api.Sub(cmp, 1)), 0, 1)
		ti := api.Mul(c.T[i], active)
		sum = api.Add(sum, ti)
	}
	api.AssertIsLessOrEqual(sum, api.Mul(maxVotes, c.M))

	// 3) Top-K
	cntGE := frontend.Variable(0)
	one := frontend.Variable(1)
	for i := 0; i < MaxM; i++ {
		cmp := api.Cmp(c.M, i)
		active := api.Select(api.IsZero(api.Sub(cmp, 1)), 0, 1)
		ti := api.Mul(c.T[i], active)
		ge := api.Select(api.IsZero(api.Cmp(ti, one)), 1, 0) // (ti≥1)?1:0
		cntGE = api.Add(cntGE, ge)
	}
	api.AssertIsLessOrEqual(c.K, cntGE)

	return nil
}
