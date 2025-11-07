package DKG

import "C"
import (
	"fmt"
)

// 初始化BLS门限签名，输入是门限值t、总节点数n和节点id   输出各个节点对应的BLS签名私钥以及主公钥mpk
func DKG(t int, n int, id []int) (sec_vec []SecretKey, mpk PublicKey) {
	Init(CurveFp382_1)
	g := Generator_g()
	h := Generator_h()

	pol_a := make([][]Fr, n)
	pol_b := make([][]Fr, n)
	sec_contribution_a := make([][]Fr, n)
	sec_contribution_b := make([][]Fr, n)
	vec := make([][]G2, n, n)
	dkg_instance := make([]Dkg, n)
	sec_rec_a := make([][]Fr, n)
	sec_rec_b := make([][]Fr, n)
	for i := range dkg_instance {
		sec_contribution_a[i] = make([]Fr, n)
		sec_contribution_b[i] = make([]Fr, n)
	}
	for i := range dkg_instance {
		dkg_instance[i].dkg_init(t, n, id)
		pol_a[i], pol_b[i] = dkg_instance[i].GeneratePolynomial()
		sec_contribution_a[i], sec_contribution_b[i] = dkg_instance[i].SecretKeyContribution(pol_a[i], pol_b[i])
		vec[i] = dkg_instance[i].VerificationVector_C(pol_a[i], pol_b[i], g, h)
	}

	for i := range dkg_instance {
		sec_rec_a[i] = make([]Fr, n)
		sec_rec_b[i] = make([]Fr, n)
		//	sec_rec_a[i]=sec_contribution_a[i]
		for j := range dkg_instance {
			sec_rec_a[i][j] = sec_contribution_a[j][i]
			sec_rec_b[i][j] = sec_contribution_b[j][i]
		}

	}

	tag := make([]bool, n)
	for i := range tag {
		tag[i] = true
	}

	for i := range dkg_instance {
		for j := 0; j < n; j++ {
			if dkg_instance[i].Verification_C(dkg_instance[i].id[i], sec_rec_a[i][j], sec_rec_b[i][j], vec[j], g, h) == false {
				tag[j] = false
				fmt.Printf("In process one, i is %v, j is %v, tag is %v\n", i+1, j+1, tag[j])

			}
		}
	}
	for i := range tag {
		fmt.Printf("In process one, party %v is %v\n", id[i], tag[i])
	}

	vec_a := make([][]G2, n)
	for i := range dkg_instance {
		vec_a[i] = dkg_instance[i].VerificationVector_A(pol_a[i], g)
	}
	for i := range dkg_instance {
		for j := 0; j < n; j++ {
			if dkg_instance[i].Verification_A(dkg_instance[i].id[i], sec_rec_a[i][j], vec_a[j], g) == false {
				tag[j] = false
			}
		}
	}

	for i := range tag {
		fmt.Printf("In process two, party %v is %v\n", id[i], tag[i])
	}

	share := make([]SecretKey, n)
	pub := make([]PublicKey, n)
	for i := 0; i < n; i++ {
		share[i] = dkg_instance[i].GenerateShare(sec_rec_a[i])
		pub[i] = *share[i].GetPublicKey()
	}
	PUB := GenerateMPK(vec_a)
	return share, PUB
}

/*
func main() {
	bls_sk,pk:=DKG(2, 3)
	fmt.Printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

	//对消息m进行签名
	m:="Hddddddddddddello"
	sign1:= bls_sk[0].Sign(m)
	sign2:= bls_sk[1].Sign(m)
	sign3:= bls_sk[2].Sign(m)

	fmt.Printf("sign 1 is %v\n",sign1.Verify(bls_sk[0].GetPublicKey(),m))
	fmt.Printf("sign 1 is %v\n",sign2.Verify(bls_sk[1].GetPublicKey(),m))
	fmt.Printf("sign 1 is %v\n",sign3.Verify(bls_sk[2].GetPublicKey(),m))

	//生成签名向量和对应的身份向量
	var sign Sign
	sign_vec:=make([]Sign,2)
	sign_vec[0]=*sign1
	sign_vec[1]=*sign2
	id_vec:=make([]ID,2)
	id_vec[0].SetDecString("1")
	id_vec[1].SetDecString("2")

	//恢复主签名
	sign.Recover(sign_vec,id_vec)


	fmt.Printf("sign  is %v\n",sign.Verify(&pk,m))
}*/

func DKGGen(t int, n int, id []int) (sec_vec []string, pub_vec []string, mpk string) {
	Init(CurveFp382_1)
	var dkg_instance Dkg
	dkg_instance.dkg_init(t, n, id)
	pola := make([]Fr, t)
	for i := range pola {
		pola[i].SetByCSPRNG()
	}
	for {
		if pola[len(pola)-1].IsZero() {
			pola[len(pola)-1].SetByCSPRNG()
		} else {
			break
		}
	}
	SecretKeyContribution := make([]Fr, n)
	for i := 0; i < dkg_instance.n_; i++ {
		err := FrEvaluatePolynomial(&SecretKeyContribution[i], pola, &(dkg_instance.id[i]))
		if err != nil {
			fmt.Printf("EvaluatePolynomial is error")
		}
	}
	SecretKeys := make([]SecretKey, n)
	for i := range SecretKeyContribution {
		SecretKeys[i].v = SecretKeyContribution[i]
	}
	var sk SecretKey
	sk.v = pola[0]
	pk := sk.GetPublicKey()
	sec_vec = make([]string, n)
	for i := range SecretKeys {
		sec_vec[i] = SecretKeys[i].GetHexString()
	}
	pub_vec = make([]string, n)
	for i := range SecretKeys {
		pub_vec[i] = SecretKeys[i].GetPublicKey().GetHexString()
	}
	mpk = pk.GetHexString()
	return sec_vec, pub_vec, mpk
}
