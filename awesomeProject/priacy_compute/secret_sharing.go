package priacy_compute

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"
)

// 选一个大素数 q（演示用；生产请统一链上参数）
var Q = big.NewInt(0).SetUint64(2305843009213693951) // 2^61-1

// 将 bit 向量做 2-份加法分享：s1=r, s2=(bit - r) mod q
// 返回 s1,s2（uint64表示，实际是 mod Q）
func SplitBitsAdditive(bits []uint8) (s1 []uint64, s2 []uint64, err error) {
	n := len(bits)
	s1 = make([]uint64, n)
	s2 = make([]uint64, n)
	for i := 0; i < n; i++ {
		if bits[i] != 0 && bits[i] != 1 {
			return nil, nil, errors.New("bit not in {0,1}")
		}
		r := randUint64ModQ()
		var bi uint64 = uint64(bits[i]) % Q.Uint64()
		var t2 uint64
		if r <= bi {
			t2 = bi - r
		} else {
			t2 = (Q.Uint64() - (r - bi)) % Q.Uint64()
		}
		s1[i] = r
		s2[i] = t2
	}
	return
}

func randUint64ModQ() uint64 {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	x := binary.LittleEndian.Uint64(buf[:])
	return x % Q.Uint64()
}
