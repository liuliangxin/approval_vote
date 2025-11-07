package priacy_compute

import (
	"encoding/binary"
	"hash/fnv"
	"math"
	"math/big"
)

// Bloom 参数：l 位长，d 哈希个数
type Bloom struct {
	L    int     // 位长
	D    int     // 哈希函数个数
	Bits []uint8 // 0/1 向量（长度 L）
	N    int     // 已插入元素数（用于计算 FPR）
}

// 由系统参数 (m, t, epsBF) 计算 l, d
// l = - t ln eps / (ln 2)^2, d = (l/t) ln 2
func CalcBloomParams(m, t int, epsBF float64) (l int, d int) {
	// ==== 输入校验====
	if m <= 0 { // 总人数至少为 1
		m = 1
	}
	if t < 0 {
		t = 0
	}
	if t > m { // 约束：t ≤ m
		t = m
	}
	// eps 约束到 (0,1)
	const epsMin = 1e-12
	const epsMax = 1 - 1e-12
	if epsBF <= 0 {
		epsBF = epsMin
	} else if epsBF >= 1 {
		epsBF = epsMax
	}

	// ==== 计算 ====
	if t == 0 { // 没有要存的元素，退化情形
		return 0, 1
	}

	ln2 := math.Ln2
	lFloat := -float64(t) * math.Log(epsBF) / (ln2 * ln2)
	l = int(math.Ceil(lFloat))
	if l < t { // 至少能放下 t 个独立位
		l = t
	}

	dFloat := (float64(l) / float64(t)) * ln2
	d = int(math.Round(dFloat))
	if d < 1 {
		d = 1
	}
	return
}

func NewBloom(l, d int) *Bloom {
	return &Bloom{
		L:    l,
		D:    d,
		Bits: make([]uint8, l),
		N:    0,
	}
}

// 计算两个基础哈希 h1, h2
func (b *Bloom) getH1H2(x uint64) (uint64, uint64) {
	h := fnv.New64a()
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], x)
	_, _ = h.Write(buf[:])
	h1 := h.Sum64()

	// 简单扰动得到 h2，可以换成另一种 hash 函数
	h2 := (h1 >> 33) ^ (h1 << 13)
	if h2 == 0 {
		h2 = 0x9e3779b97f4a7c15 // 避免退化为 0
	}
	return h1, h2
}

// AddIndex 将索引加入 Bloom
func (b *Bloom) AddIndex(idx uint64) {
	if b.L == 0 || b.D == 0 {
		return
	}
	h1, h2 := b.getH1H2(idx)
	mod := uint64(b.L)
	for j := 0; j < b.D; j++ {
		pos := (h1 + uint64(j)*h2) % mod
		b.Bits[pos] = 1
	}
	b.N++
}

// CheckIndex 检查是否可能存在
func (b *Bloom) CheckIndex(idx uint64) bool {
	if b.L == 0 || b.D == 0 {
		return false
	}
	h1, h2 := b.getH1H2(idx)
	mod := uint64(b.L)
	for j := 0; j < b.D; j++ {
		pos := (h1 + uint64(j)*h2) % mod
		if b.Bits[pos] == 0 {
			return false
		}
	}
	return true
}

// FalsePositiveRate 当前假阳性率 FPR = (1 - e^(-d*n/l))^d
func (b *Bloom) FalsePositiveRate() float64 {
	if b.L == 0 || b.D == 0 || b.N == 0 {
		return 0
	}
	return math.Pow(1-math.Exp(-float64(b.D)*float64(b.N)/float64(b.L)), float64(b.D))
}

func (b *Bloom) OnesCount() int {
	cnt := 0
	for _, v := range b.Bits {
		if v == 1 {
			cnt++
		}
	}
	return cnt
}

// 导出/导入
func (b *Bloom) ExportBits() []uint8 {
	out := make([]uint8, len(b.Bits))
	copy(out, b.Bits)
	return out
}

func GenerateBloomFilter(voteList []int) (*Bloom, *big.Int) {
	// 假设 S 是候选集
	S := len(voteList) // 设定候选集大小

	// 计算 l, d 等参数，取布隆过滤器容错率为0.01
	l, d := CalcBloomParams(S, 10, 0.01)

	// 创建布隆过滤器
	bloomFilter := NewBloom(l, d)

	// 填充布隆过滤器
	sum := big.NewInt(0) // 投票的总和
	for _, idx := range voteList {
		bloomFilter.AddIndex(uint64(idx))
		// 统计投票总和
		sum.Add(sum, big.NewInt(int64(idx)))
	}

	return bloomFilter, sum
}
