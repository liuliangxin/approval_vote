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

	scV := curve.NewScalar()
	scV, err := scV.SetBigInt(v)
	if err != nil {
		return nil, err
	}

	//
	r := curve.NewScalar().Random(rand.Reader)

	//
	com := curve.NewIdentityPoint()
	com.SumOfProducts([]curves.Point{g, h}, []curves.Scalar{scV, r})

	//
	commitBytes := com.ToAffineCompressed() // []byte
	blindBytes := r.Bytes()                 // []byte
	return &PedersenCommitment{
		Commit: commitBytes,
		Rand:   r.BigInt(),
		Value:  new(big.Int).Set(v),
		Blind:  blindBytes,
	}, nil
}

func PedersenCommit(value *big.Int, rand *big.Int) (*PedersenCommitment, error) {
	if value == nil || value.Sign() < 0 {
		return nil, errors.New("value must be non-negative")
	}
	if rand == nil {
		//
		return NewPedersenCommitment(value)
	}

	curve := curves.K256()
	g := curve.NewGeneratorPoint().Generator()
	h := curve.NewGeneratorPoint().Hash([]byte("bp:h"))

	//
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

	//
	com := curve.NewIdentityPoint()
	com.SumOfProducts([]curves.Point{g, h}, []curves.Scalar{scV, scR})

	//
	commitBytes := com.ToAffineCompressed() // []byte
	blindBytes := scR.Bytes()               // []byte
	return &PedersenCommitment{
		Commit: commitBytes,
		Rand:   new(big.Int).Set(rand),
		Value:  new(big.Int).Set(value),
		Blind:  blindBytes,
	}, nil
}

func PedersenVerify(c *PedersenCommitment) bool {
	if c == nil || c.Value == nil || c.Rand == nil || len(c.Commit) == 0 {
		return false
	}

	curve := curves.K256()
	g := curve.NewGeneratorPoint().Generator()
	h := curve.NewGeneratorPoint().Hash([]byte("bp:h"))

	got, err := curve.NewIdentityPoint().FromAffineCompressed(c.Commit)
	if err != nil {
		return false
	}

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

	return expect.Equal(got)
}

func (pc *PedersenCommitment) String() string {
	return fmt.Sprintf("PedersenCommitment{Com=%x, Value=%s}", pc.Commit, pc.Value.String())
}
