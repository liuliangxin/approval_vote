package bloom

import (
	"math"
	"testing"
)

func TestCalcBloomParams(t *testing.T) {
	l, d := CalcBloomParams(100, 20, 0.01) // m=100, t=20, eps=1%
	if l <= 0 || d <= 0 {
		t.Fatalf("CalcBloomParams returned non-positive: l=%d d=%d", l, d)
	}
	if l < 20 {
		t.Fatalf("l should be >= t (20), got %d", l)
	}

	// t > m 时应被钳制为 t=m
	l2, d2 := CalcBloomParams(10, 20, 0.01) // t>m
	if l2 <= 0 || d2 <= 0 {
		t.Fatalf("CalcBloomParams (clamped) returned non-positive: l=%d d=%d", l2, d2)
	}
}

func TestNewBloomAndExport(t *testing.T) {
	b := NewBloom(128, 3)
	if b.L != 128 || b.D != 3 {
		t.Fatalf("NewBloom set wrong params: L=%d D=%d", b.L, b.D)
	}
	if len(b.Bits) != 128 {
		t.Fatalf("Bits len mismatch: got %d", len(b.Bits))
	}
	clone := b.ExportBits()
	if len(clone) != len(b.Bits) {
		t.Fatalf("ExportBits length mismatch")
	}
	// 修改导出切片不应影响内部
	if len(clone) > 0 {
		clone[0] = 1
	}
	if b.Bits[0] != 0 {
		t.Fatalf("ExportBits should return a copy")
	}
}

func TestAddAndCheck_NoFalseNegative(t *testing.T) {
	const (
		L = 4096
		D = 3
		N = 500
	)

	b := NewBloom(L, D)

	// 插入 N 个唯一索引
	for i := 0; i < N; i++ {
		b.AddIndex(uint64(i + 1))
	}

	// 已插入的元素不应出现假阴性
	for i := 0; i < N; i++ {
		if !b.CheckIndex(uint64(i + 1)) {
			t.Fatalf("False negative on inserted index %d", i+1)
		}
	}
}

func TestFalsePositiveRateApprox(t *testing.T) {
	const (
		L        = 4096
		D        = 3
		Inserted = 400
		Trials   = 5000
	)

	b := NewBloom(L, D)

	// 插入若干元素
	for i := 0; i < Inserted; i++ {
		b.AddIndex(uint64(i + 1))
	}

	// 观测假阳性率（用不相交的索引空间避免碰撞为真阳性）
	fp := 0
	for i := 0; i < Trials; i++ {
		x := uint64(1_000_000 + i) // 确保与已插入的不重叠
		if b.CheckIndex(x) {
			fp++
		}
	}
	observed := float64(fp) / float64(Trials)

	expected := b.FalsePositiveRate()

	diff := math.Abs(observed - expected)
	// 允许的容差：max(0.01, 5 * sigma)
	sigma := math.Sqrt(expected * (1 - expected) / Trials)
	allow := math.Max(0.01, 5*sigma)

	if diff > allow {
		t.Fatalf("FPR mismatch: observed=%.4f expected=%.4f diff=%.4f allow=%.4f", observed, expected, diff, allow)
	}
}

func TestOnesCountMonotonic(t *testing.T) {
	const (
		L = 2048
		D = 3
	)
	b := NewBloom(L, D)

	before := b.OnesCount()
	if before != 0 {
		t.Fatalf("initial OnesCount should be 0, got %d", before)
	}

	// 逐步加入，位数应非减（考虑到可能命中同一位，不做严格增长断言）
	for i := 0; i < 200; i++ {
		b.AddIndex(uint64(i + 1))
		after := b.OnesCount()
		if after < before {
			t.Fatalf("OnesCount decreased: before=%d after=%d at i=%d", before, after, i)
		}
		before = after
	}
}
