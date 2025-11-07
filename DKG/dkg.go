package DKG

import "C"
import "fmt"

type Dkg struct {
	t_   int
	n_   int
	flag []int
	id   []Fr
}

func Generator_h() (h G2) {
	sk := new(SecretKey)
	sk.SetByCSPRNG()
	pk := sk.GetPublicKey()
	h = pk.v
	//bls.G2Mul(pk, C.getQ(), sk)
	return h
}

func Generator_g() (g G2) {
	var sk SecretKey
	sk.v.SetInt64(1)
	pk := sk.GetPublicKey()
	g = pk.v
	return g
}

// 初始化一个dkg过程，设定节点数和阈值，初始化id
func (dkg_instance *Dkg) dkg_init(t int, n int, id []int) {
	dkg_instance.t_ = t
	dkg_instance.n_ = n
	dkg_instance.flag = make([]int, n)
	dkg_instance.id = make([]Fr, n)
	for i := range dkg_instance.flag {
		dkg_instance.flag[i] = 0
	}
	for i := range dkg_instance.id {
		dkg_instance.id[i].SetInt64(int64(id[i]))
	}
}

// 随机产生多项式
func (dkg_instance *Dkg) GeneratePolynomial() ([]Fr, []Fr) {
	Pola := make([]Fr, dkg_instance.t_)
	Polb := make([]Fr, dkg_instance.t_)
	for i := range Pola {
		Pola[i].SetByCSPRNG()
		Polb[i].SetByCSPRNG()
	}
	for {
		if Pola[len(Pola)-1].IsZero() {
			Pola[len(Pola)-1].SetByCSPRNG()
		} else {
			break
		}
	}
	for {
		if Polb[len(Polb)-1].IsZero() {
			Polb[len(Polb)-1].SetByCSPRNG()
		} else {
			break
		}
	}
	return Pola, Polb
}

// 生成第一阶段的验证向量
func (dkg_instance *Dkg) VerificationVector_C(Pola []Fr, Polb []Fr, g G2, h G2) []G2 {
	verification_vector := make([]G2, dkg_instance.t_)
	var tempa, tempb G2
	for i := 0; i < dkg_instance.t_; i++ {
		G2Mul(&tempa, &g, &Pola[i])
		G2Mul(&tempb, &h, &Polb[i])
		G2Add(&verification_vector[i], &tempa, &tempb)
	}
	return verification_vector
}

// 生成第二阶段的验证向量
func (dkg_instance *Dkg) VerificationVector_A(Pola []Fr, g G2) []G2 {
	verification_vector := make([]G2, dkg_instance.t_)
	for i := 0; i < dkg_instance.t_; i++ {
		G2Mul(&verification_vector[i], &g, &Pola[i])
	}
	return verification_vector
}

// 节点根据自己生成的多项式，生成带分发的share
func (dkg_instance *Dkg) SecretKeyContribution(pola []Fr, polb []Fr) ([]Fr, []Fr) {
	SecretKeyContribution_veca := make([]Fr, dkg_instance.n_)
	SecretKeyContribution_vecb := make([]Fr, dkg_instance.n_)
	for i := 0; i < dkg_instance.n_; i++ {
		err := FrEvaluatePolynomial(&SecretKeyContribution_veca[i], pola, &(dkg_instance.id[i]))
		if err != nil {
			fmt.Printf("EvaluatePolynomial is error")
		}
		err = FrEvaluatePolynomial(&SecretKeyContribution_vecb[i], polb, &(dkg_instance.id[i]))
		if err != nil {
			fmt.Printf("EvaluatePolynomial is error")
		}
	}
	return SecretKeyContribution_veca, SecretKeyContribution_vecb
}

// 节点根据自己收到的share，生成最终的share
func SecretKeyShareCreate(secret_key_receive []Fr) Fr {
	var SecretKeyShare, temp Fr
	SecretKeyShare.SetInt64(0)
	temp.SetInt64(0)
	for i := 0; i < len(secret_key_receive); i++ {
		FrAdd(&SecretKeyShare, &temp, &secret_key_receive[i])
		temp = SecretKeyShare
	}
	return SecretKeyShare
}

// 第一阶段的VSS验证
func (dkg_instance *Dkg) Verification_C(id Fr, share_a Fr, share_b Fr, verification_vector []G2, g G2, h G2) bool {
	var value, value_temp G2
	var temp_fr Fr
	var temp_g2 G2
	value = verification_vector[0]
	G2Mul(&temp_g2, &verification_vector[0], &temp_fr)
	for i := 1; i < dkg_instance.t_; i++ {
		FrPow(&temp_fr, &id, int64(i))
		G2Mul(&temp_g2, &verification_vector[i], &temp_fr)
		G2Add(&value_temp, &value, &temp_g2)
		value = value_temp
	}
	var temp1, temp2, temp3 G2
	G2Mul(&temp1, &g, &share_a)
	G2Mul(&temp2, &h, &share_b)
	G2Add(&temp3, &temp2, &temp1)
	return value.IsEqual(&temp3)
}

// 第二阶段的VSS验证
func (dkg_instance *Dkg) Verification_A(id Fr, share Fr, verification_vector []G2, g G2) bool {
	var value, value_temp G2
	var temp_fr Fr
	var temp_g2 G2
	value = verification_vector[0]
	G2Mul(&temp_g2, &verification_vector[0], &temp_fr)
	for i := 1; i < dkg_instance.t_; i++ {
		FrPow(&temp_fr, &id, int64(i))
		G2Mul(&temp_g2, &verification_vector[i], &temp_fr)
		G2Add(&value_temp, &value, &temp_g2)
		value = value_temp
	}
	G2Mul(&temp_g2, &g, &share)
	return value.IsEqual(&temp_g2)
}

// 节点根据自己收到的share，生成最终的share
func (dkg_instance *Dkg) GenerateShare(secret_key_receive []Fr) SecretKey {
	var value, value_temp Fr
	value_temp.SetInt64(0)
	for i := range secret_key_receive {
		FrAdd(&value, &value_temp, &secret_key_receive[i])
		value_temp = value
	}
	var sec SecretKey
	sec.v = value
	return sec
}

func GenerateMPK(vec_a [][]G2) PublicKey {

	var pub, pub_temp PublicKey
	pub_temp.v = vec_a[0][0]
	for i := 0; i < (len(vec_a) - 1); i++ {
		G2Add(&pub.v, &pub_temp.v, &vec_a[i+1][0])
		pub_temp.v = pub.v
	}
	return pub

}
