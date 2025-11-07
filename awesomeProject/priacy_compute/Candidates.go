package priacy_compute

import (
	"math"
	"math/big"
)

// 组合数 C(n, k)
func comb(n, k int64) *big.Int {
	if k < 0 || k > n {
		return big.NewInt(0)
	}
	num := new(big.Int).Binomial(n, k)
	return num
}

// 计算超几何尾部概率
func hypergeometricTail(N, m, fN int64, theta float64) float64 {
	total := comb(N, m)
	var sum big.Float
	sum.SetPrec(512)
	for x := int64(theta * float64(m)); x <= m; x++ {
		good := comb(fN, x)
		bad := comb(N-fN, m-x)
		numerator := new(big.Int).Mul(good, bad)
		ratio := new(big.Float).Quo(new(big.Float).SetInt(numerator), new(big.Float).SetInt(total))
		sum.Add(&sum, ratio)
	}
	result, _ := sum.Float64()
	return result
}

// 根据 N、f、θ、p_target 计算最小候选集规模 m 和 τ
func findMinimumCandidateSize(N int64, f float64, theta float64, pTarget float64) (int64, float64) {
	fN := int64(math.Ceil(f * float64(N)))
	for m := int64(1); m <= N; m++ {
		pFail := hypergeometricTail(N, m, fN, theta)
		if pFail <= pTarget {
			tau := float64(m) / float64(N)
			return m, tau
		}
	}
	return N, 1.0 // fallback
}
