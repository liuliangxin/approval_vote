package priacy_compute

import (
	"encoding/binary"
	"hash/fnv"
	"math"
	"math/big"
)

type Bloom struct {
	L    int
	D    int
	Bits []uint8
	N    int
}

// l = - t ln eps / (ln 2)^2, d = (l/t) ln 2
func CalcBloomParams(m, t int, epsBF float64) (l int, d int) {

	if m <= 0 {
		m = 1
	}
	if t < 0 {
		t = 0
	}
	if t > m { //
		t = m
	}

	const epsMin = 1e-12
	const epsMax = 1 - 1e-12
	if epsBF <= 0 {
		epsBF = epsMin
	} else if epsBF >= 1 {
		epsBF = epsMax
	}

	if t == 0 { //
		return 0, 1
	}

	ln2 := math.Ln2
	lFloat := -float64(t) * math.Log(epsBF) / (ln2 * ln2)
	l = int(math.Ceil(lFloat))
	if l < t { //
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

func (b *Bloom) getH1H2(x uint64) (uint64, uint64) {
	h := fnv.New64a()
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], x)
	_, _ = h.Write(buf[:])
	h1 := h.Sum64()

	h2 := (h1 >> 33) ^ (h1 << 13)
	if h2 == 0 {
		h2 = 0x9e3779b97f4a7c15 //
	}
	return h1, h2
}

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

func (b *Bloom) ExportBits() []uint8 {
	out := make([]uint8, len(b.Bits))
	copy(out, b.Bits)
	return out
}

func GenerateBloomFilter(voteList []int) (*Bloom, *big.Int) {

	S := len(voteList)

	l, d := CalcBloomParams(S, 10, 0.01)

	bloomFilter := NewBloom(l, d)

	sum := big.NewInt(0)
	for _, idx := range voteList {
		bloomFilter.AddIndex(uint64(idx))

		sum.Add(sum, big.NewInt(int64(idx)))
	}

	return bloomFilter, sum
}
