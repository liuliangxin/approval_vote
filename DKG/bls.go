package DKG

/*
#cgo CFLAGS:-DMCLBN_FP_UNIT_SIZE=6
#cgo LDFLAGS:-lbls384 -lgmpxx -lstdc++ -lgmp -lcrypto
#include <bls/bls.h>
*/
import "C"
import (
	"fmt"
	"strconv"
)
import "unsafe"

// Init --
// call this function before calling all the other operations
// this function is not thread safe
func Init(curve int) error {
	err := C.blsInit(C.int(curve), C.MCLBN_FP_UNIT_SIZE)
	if err != 0 {
		return fmt.Errorf("ERR Init curve=%d", curve)
	}
	return nil
}

// ID --
type ID struct {
	v Fr
}

// getPointer --
func (id *ID) getPointer() (p *C.blsId) {
	// #nosec
	return (*C.blsId)(unsafe.Pointer(id))
}

// GetLittleEndian --
func (id *ID) GetLittleEndian() []byte {
	return id.v.Serialize()
}

// SetLittleEndian --
func (id *ID) SetLittleEndian(buf []byte) error {
	return id.v.SetLittleEndian(buf)
}

// GetHexString --
func (id *ID) GetHexString() string {
	return id.v.GetString(16)
}

// GetDecString --
func (id *ID) GetDecString() string {
	return id.v.GetString(10)
}

// SetHexString --
func (id *ID) SetHexString(s string) error {
	return id.v.SetString(s, 16)
}

// SetDecString --
func (id *ID) SetDecString(s string) error {
	return id.v.SetString(s, 10)
}

// SetDecString --
func (id *ID) SetInt64(v int64) {
	id.v.SetInt64(v)
}

// IsEqual --
func (id *ID) IsEqual(rhs *ID) bool {
	return id.v.IsEqual(&rhs.v)
}

// SecretKey --
type SecretKey struct {
	v Fr
}

// getPointer --
func (sec *SecretKey) getPointer() (p *C.blsSecretKey) {
	// #nosec
	return (*C.blsSecretKey)(unsafe.Pointer(sec))
}

// GetLittleEndian --
func (sec *SecretKey) GetLittleEndian() []byte {
	return sec.v.Serialize()
}

// SetLittleEndian --
func (sec *SecretKey) SetLittleEndian(buf []byte) error {
	return sec.v.SetLittleEndian(buf)
}

// GetHexString --
func (sec *SecretKey) GetHexString() string {
	return sec.v.GetString(16)
}

// GetDecString --
func (sec *SecretKey) GetDecString() string {
	return sec.v.GetString(10)
}

// SetHexString --
func (sec *SecretKey) SetHexString(s string) error {
	return sec.v.SetString(s, 16)
}

// SetDecString --
func (sec *SecretKey) SetDecString(s string) error {
	return sec.v.SetString(s, 10)
}

// IsEqual --
func (sec *SecretKey) IsEqual(rhs *SecretKey) bool {
	return sec.v.IsEqual(&rhs.v)
}

// SetByCSPRNG --
func (sec *SecretKey) SetByCSPRNG() {
	sec.v.SetByCSPRNG()
}

// Add --
func (sec *SecretKey) Add(rhs *SecretKey) {
	FrAdd(&sec.v, &sec.v, &rhs.v)
}

// GetMasterSecretKey --
func (sec *SecretKey) GetMasterSecretKey(k int) (msk []SecretKey) {
	msk = make([]SecretKey, k)
	msk[0] = *sec
	for i := 1; i < k; i++ {
		msk[i].SetByCSPRNG()
	}
	return msk
}

// GetMasterPublicKey --
func GetMasterPublicKey(msk []SecretKey) (mpk []PublicKey) {
	n := len(msk)
	mpk = make([]PublicKey, n)
	for i := 0; i < n; i++ {
		mpk[i] = *msk[i].GetPublicKey()
	}
	return mpk
}

// Set --
func (sec *SecretKey) Set(msk []SecretKey, id *ID) error {
	// #nosec
	return FrEvaluatePolynomial(&sec.v, *(*[]Fr)(unsafe.Pointer(&msk)), &id.v)
}

// Recover --
func (sec *SecretKey) Recover(secVec []SecretKey, idVec []ID) error {
	// #nosec
	return FrLagrangeInterpolation(&sec.v, *(*[]Fr)(unsafe.Pointer(&idVec)), *(*[]Fr)(unsafe.Pointer(&secVec)))
}

// GetPop --
func (sec *SecretKey) GetPop() (sign *Sign) {
	sign = new(Sign)
	C.blsGetPop(sign.getPointer(), sec.getPointer())
	return sign
}

// PublicKey --
type PublicKey struct {
	v G2
}

// getPointer --
func (pub *PublicKey) getPointer() (p *C.blsPublicKey) {
	// #nosec
	return (*C.blsPublicKey)(unsafe.Pointer(pub))
}

// Serialize --
func (pub *PublicKey) Serialize() []byte {
	return pub.v.Serialize()
}

// Deserialize --
func (pub *PublicKey) Deserialize(buf []byte) error {
	return pub.v.Deserialize(buf)
}

// GetHexString --
func (pub *PublicKey) GetHexString() string {
	return pub.v.GetString(16)
}

// SetHexString --
func (pub *PublicKey) SetHexString(s string) error {
	return pub.v.SetString(s, 16)
}

// IsEqual --
func (pub *PublicKey) IsEqual(rhs *PublicKey) bool {
	return pub.v.IsEqual(&rhs.v)
}

// Add --
func (pub *PublicKey) Add(rhs *PublicKey) {
	G2Add(&pub.v, &pub.v, &rhs.v)
}

// Set --
func (pub *PublicKey) Set(mpk []PublicKey, id *ID) error {
	// #nosec
	return G2EvaluatePolynomial(&pub.v, *(*[]G2)(unsafe.Pointer(&mpk)), &id.v)
}

// Recover --
func (pub *PublicKey) Recover(pubVec []PublicKey, idVec []ID) error {
	// #nosec
	return G2LagrangeInterpolation(&pub.v, *(*[]Fr)(unsafe.Pointer(&idVec)), *(*[]G2)(unsafe.Pointer(&pubVec)))
}

// Sign  --
type Sign struct {
	v G1
}

// getPointer --
func (sign *Sign) getPointer() (p *C.blsSignature) {
	// #nosec
	return (*C.blsSignature)(unsafe.Pointer(sign))
}

// Serialize --
func (sign *Sign) Serialize() []byte {
	return sign.v.Serialize()
}

// Deserialize --
func (sign *Sign) Deserialize(buf []byte) error {
	return sign.v.Deserialize(buf)
}

// GetHexString --
func (sign *Sign) GetHexString() string {
	return sign.v.GetString(16)
}

// SetHexString --
func (sign *Sign) SetHexString(s string) error {
	return sign.v.SetString(s, 16)
}

// IsEqual --
func (sign *Sign) IsEqual(rhs *Sign) bool {
	return sign.v.IsEqual(&rhs.v)
}

// GetPublicKey --
func (sec *SecretKey) GetPublicKey() (pub *PublicKey) {
	pub = new(PublicKey)
	C.blsGetPublicKey(pub.getPointer(), sec.getPointer())
	return pub
}

// Sign -- Constant Time version
func (sec *SecretKey) Sign(m string) (sign *Sign) {
	sign = new(Sign)
	buf := []byte(m)
	// #nosec
	C.blsSign(sign.getPointer(), sec.getPointer(), unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	return sign
}

// Add --
func (sign *Sign) Add(rhs *Sign) {
	C.blsSignatureAdd(sign.getPointer(), rhs.getPointer())
}

// Recover --
func (sign *Sign) Recover(signVec []Sign, idVec []ID) error {
	// #nosec
	return G1LagrangeInterpolation(&sign.v, *(*[]Fr)(unsafe.Pointer(&idVec)), *(*[]G1)(unsafe.Pointer(&signVec)))
}

// Verify --
func (sign *Sign) Verify(pub *PublicKey, m string) bool {
	buf := []byte(m)
	// #nosec
	return C.blsVerify(sign.getPointer(), pub.getPointer(), unsafe.Pointer(&buf[0]), C.size_t(len(buf))) == 1
}

// VerifyPop --
func (sign *Sign) VerifyPop(pub *PublicKey) bool {
	return C.blsVerifyPop(sign.getPointer(), pub.getPointer()) == 1
}

// DHKeyExchange --
func DHKeyExchange(sec *SecretKey, pub *PublicKey) (out PublicKey) {
	C.blsDHKeyExchange(out.getPointer(), sec.getPointer(), pub.getPointer())
	return out
}

func BLSsign(sk string, m string) string {
	var sec SecretKey
	sec.SetHexString(sk)
	return sec.Sign(m).GetHexString()
}

func BLSverify(pk string, sig string, digest string) bool {
	var pub PublicKey
	var sign Sign
	sign.SetHexString(sig)
	pub.SetHexString(pk)
	return sign.Verify(&pub, digest)
}

func BLSrevocer(signatures []string, id []string) (string, error) {
	var err error
	votes_num := len(signatures)
	sign_vec := make([]Sign, votes_num)
	id_vec := make([]ID, votes_num)
	votes_num = 0
	for i := range signatures {
		sign_vec[i].SetHexString(signatures[i])
		num, err := strconv.ParseInt(id[i], 10, 64)
		if err != nil {
			fmt.Printf("BLSrecover is failed")
			return "", err
		}
		id_vec[votes_num].SetInt64(num)
		votes_num = votes_num + 1
	}
	var sign Sign
	sign.Recover(sign_vec, id_vec)
	return sign.GetHexString(), err
}

///for bls multi agg///

func BLSsign1(sk string, digest []byte) string {
	var sec SecretKey
	var hash0 G1
	var out G1
	sec.SetHexString(sk)
	hash0.HashAndMapTo(digest)
	G1Mul(&out, &hash0, &sec.v)
	return out.GetString(16)
}

func BLSverify1(pk string, sig string, digest []byte) bool {
	var pub PublicKey
	var sign Sign
	sign.SetHexString(sig)
	pub.SetHexString(pk)

	var e1, e2 GT
	var hash G1

	hash.HashAndMapTo(digest)

	var sk SecretKey
	sk.v.SetInt64(1)
	gtemp := *sk.GetPublicKey()
	g := gtemp.v

	Pairing(&e1, &sign.v, &g)
	Pairing(&e2, &hash, &pub.v)

	return (&e1).IsEqual(&e2)
}

func BLSMulti(signatures []string, pks []string) (string, string) {
	var sign Sign
	sign.SetHexString(signatures[0])
	sigMul := sign
	for i := 1; i < len(signatures); i++ {
		sign.SetHexString(signatures[i])
		sigMul.Add(&sign)
	}
	var pk PublicKey
	pk.SetHexString(pks[0])
	pkMul := pk
	for i := 1; i < len(pks); i++ {
		pk.SetHexString(pks[i])
		pkMul.Add(&pk)
	}
	return sigMul.GetHexString(), pkMul.GetHexString()
}

func BLSMultiVerify(signature string, gpkString string, digest []byte) bool {

	var sign Sign
	var e1, e2 GT
	var hash G1
	var gpk PublicKey

	sign.SetHexString(signature)
	gpk.SetHexString(gpkString)
	hash.HashAndMapTo(digest)

	var sk SecretKey
	sk.v.SetInt64(1)
	pk := sk.GetPublicKey()
	g := pk.v

	Pairing(&e1, &sign.v, &g)
	Pairing(&e2, &hash, &gpk.v)

	return (&e1).IsEqual(&e2)
}

func BLSSignAgg(signatures []string) string {
	var sign, signMul Sign
	signMul.SetHexString(signatures[0])
	for i := 1; i < len(signatures); i++ {
		sign.SetHexString(signatures[i])
		signMul.Add(&sign)
		//println("sign: ", sign.GetHexString())
		//println("signMul: ", signMul.GetHexString())
	}
	return signMul.GetHexString()
}

func BLSSignAggVerify(signature string, gpks []string, digests [][]byte) bool {
	var sign Sign
	var e1, e2, etmp, eadd GT
	var hash0 G1
	var gpk PublicKey

	sign.SetHexString(signature)
	gpk.SetHexString(gpks[0])
	hash0.HashAndMapTo(digests[0])

	var sk SecretKey
	sk.v.SetInt64(1)
	pk := sk.GetPublicKey()
	g := pk.v

	Pairing(&e1, &sign.v, &g)
	Pairing(&e2, &hash0, &gpk.v)
	for i := 1; i < len(digests); i++ {
		gpk.SetHexString(gpks[i])
		hash0.HashAndMapTo(digests[i])
		Pairing(&etmp, &hash0, &gpk.v)
		//GTAdd(&eadd, &e2, &etmp)
		GTMul(&eadd, &e2, &etmp)
		e2.v = eadd.v
	}

	//println("e1", e1.GetString(16))
	//println("e2", e2.GetString(16))

	return (&e1).IsEqual(&e2)
}
