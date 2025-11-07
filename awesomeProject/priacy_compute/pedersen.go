package priacy_compute

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

// PedersenCommitment: Pedersen 承诺结构
type PedersenCommitment struct {
	Commit []byte   // g^value * h^rand 的曲线点序列化
	Rand   *big.Int // 盲因子整数（便于调试）
	Value  *big.Int // 明文值
	Blind  []byte   // 盲因子曲线标量的序列化（常用于后续 ZK/子协议）
}

// MarshalBinary 将 Scalar 对象转换为字节数组

// NewPedersenCommitment: 创建 Pedersen 承诺，自动生成盲因子
func NewPedersenCommitment(v *big.Int) (*PedersenCommitment, error) {
	if v == nil || v.Sign() < 0 {
		return nil, errors.New("value must be non-negative")
	}

	curve := curves.K256()
	g := curve.NewGeneratorPoint().Generator()
	h := curve.NewGeneratorPoint().Hash([]byte("bp:h"))

	// 标量化 value
	scV := curve.NewScalar()
	scV, err := scV.SetBigInt(v)
	if err != nil {
		return nil, err
	}

	// 随机盲因子 r
	r := curve.NewScalar().Random(rand.Reader)

	// Com = g^v * h^r
	com := curve.NewIdentityPoint()
	com.SumOfProducts([]curves.Point{g, h}, []curves.Scalar{scV, r})

	// === v1.8.0 正确的序列化方式 ===
	commitBytes := com.ToAffineCompressed() // []byte
	blindBytes := r.Bytes()                 // []byte
	return &PedersenCommitment{
		Commit: commitBytes,
		Rand:   r.BigInt(),
		Value:  new(big.Int).Set(v),
		Blind:  blindBytes,
	}, nil
}

// PedersenCommit: 按给定 value 与 rand 生成承诺
func PedersenCommit(value *big.Int, rand *big.Int) (*PedersenCommitment, error) {
	if value == nil || value.Sign() < 0 {
		return nil, errors.New("value must be non-negative")
	}
	if rand == nil {
		// 若未传入盲因子，自动随机生成
		return NewPedersenCommitment(value)
	}

	curve := curves.K256()
	g := curve.NewGeneratorPoint().Generator()
	h := curve.NewGeneratorPoint().Hash([]byte("bp:h"))

	// 标量化 value 与 rand
	scV := curve.NewScalar()
	scV, err := scV.SetBigInt(value)
	if err != nil {
		return nil, err
	}
	scR := curve.NewScalar()
	scR, err = scR.SetBigInt(rand)
	if err != nil {
		return nil, err
	}

	// Com = g^v * h^r
	com := curve.NewIdentityPoint()
	com.SumOfProducts([]curves.Point{g, h}, []curves.Scalar{scV, scR})

	// === v1.8.0 正确的序列化方式 ===
	commitBytes := com.ToAffineCompressed() // []byte
	blindBytes := scR.Bytes()               // []byte
	return &PedersenCommitment{
		Commit: commitBytes,
		Rand:   new(big.Int).Set(rand),
		Value:  new(big.Int).Set(value),
		Blind:  blindBytes,
	}, nil
}

// PedersenVerify: 重计算 g^value * h^rand 并与 Commit 比较
func PedersenVerify(c *PedersenCommitment) bool {
	if c == nil || c.Value == nil || c.Rand == nil || len(c.Commit) == 0 {
		return false
	}

	curve := curves.K256()
	g := curve.NewGeneratorPoint().Generator()
	h := curve.NewGeneratorPoint().Hash([]byte("bp:h"))

	// 反序列化承诺点（压缩形式）
	got, err := curve.NewIdentityPoint().FromAffineCompressed(c.Commit)
	if err != nil {
		return false
	}
	// 重算 Com'
	scV := curve.NewScalar()
	if err, _ := scV.SetBigInt(c.Value); err != nil {
		return false
	}
	scR := curve.NewScalar()
	if err, _ := scR.SetBigInt(c.Rand); err != nil {
		return false
	}
	expect := curve.NewIdentityPoint()
	expect.SumOfProducts([]curves.Point{g, h}, []curves.Scalar{scV, scR})

	// 比较点是否相等
	return expect.Equal(got)
}

func (pc *PedersenCommitment) String() string {
	return fmt.Sprintf("PedersenCommitment{Com=%x, Value=%s}", pc.Commit, pc.Value.String())
}
