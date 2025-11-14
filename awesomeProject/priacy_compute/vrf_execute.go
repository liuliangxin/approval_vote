package priacy_compute

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/r2ishiguro/vrf/go/vrf_ed25519"
)

type AggVRFMsg struct {
	NodeID  string `json:"node_id"`
	PKHex   string `json:"pk_hex"`
	Proof   []byte `json:"proof"`
	Context string `json:"context"` // 例如 "agg-select|epoch1:block100"
}

// (F) 内部：收集到的 y 值
type aggY struct {
	NodeID string
	YTail2 uint8 // y 的最低 8bit（或最低两位十六进制）
}

type RoundKey struct {
	T uint64
	C string
}
type SeenKey struct {
	Round  RoundKey
	NodeID string
}

var seen = map[SeenKey]struct{}{}

// ======= 工具：拼消息、归一化、从 proof 解出 γ =======

func makeMessage(t uint64, context []byte) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], t)
	msg := append(buf[:], context...)
	return msg
}

// 把 γ（字节）映射到 [0,1)
func bytesToUnitFloat(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	num := new(big.Int).SetBytes(b)
	den := new(big.Int).Lsh(big.NewInt(1), uint(8*len(b))) // 2^(8*len)
	r := new(big.Rat).SetFrac(num, den)
	f, _ := r.Float64()
	return f
}

// ======= 本地计算一轮 vrf（Eval + Verify） =======
func (n *Node) evalVRFOnce(t uint64, context []byte) (value float64, pi []byte, hash []byte, err error) {
	msg := makeMessage(t, context)

	// 产生 proof π，并返回 vrf 输出（hash）和错误信息
	pi, err = vrf_ed25519.ECVRF_prove(n.SelfPK, n.SelfSK, msg)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("ECVRF_prove: %w", err)
	}

	hash = vrf_ed25519.ECVRF_proof2hash(pi) // 注意：这个函数通常只返回 []byte

	// 自验
	ok, err := vrf_ed25519.ECVRF_verify(n.SelfPK, pi, msg)
	if err != nil || !ok {
		return 0, pi, nil, fmt.Errorf("ECVRF_verify: ok=%v err=%v", ok, err)
	}

	// 将 hash 映射到 [0, 1) 并返回
	val := bytesToUnitFloat(hash) // 用 hash 作为参数传入 bytesToUnitFloat
	return val, pi, hash, nil
}

// ======= 触发一轮随机选举并广播 =======
func (n *Node) RunRandomElectAndBroadcast() error {
	funcStart := time.Now()
	defer func() {
		fmt.Printf("[timing] RunRandomElectAndBroadcast total=%s\n", time.Since(funcStart))
	}()

	// --- 1) evalVRFOnce ---
	t0 := time.Now()
	val, pi, _, err := n.evalVRFOnce(n.VRF_T, []byte(n.VRF_Context))
	d0 := time.Since(t0)
	if err != nil {
		fmt.Printf("[timing] evalVRFOnce failed after %s: %v\n", d0, err)
		return err
	}
	fmt.Printf("[timing] evalVRFOnce ok in %s\n", d0)

	n.VRFValue = val
	n.VRFProof = pi
	n.VRFChosen = val < n.Tau

	force := (n.NodeID == "1" || n.NodeID == "2")
	if force {
		fmt.Printf("[VRF] \n", n.NodeID)
	}
	if !n.VRFChosen && !force {
		fmt.Println("VRFChosen is false, skipping the rest of the logic.")
		return nil
	}

	// --- 2) handleBloomParams ---
	t1 := time.Now()
	bloomParams := BloomParamsMsg{M: 150, T: 30, EpsBF: 0.000001}
	err = n.handleBloomParams(&bloomParams)
	d1 := time.Since(t1)
	if err != nil {
		fmt.Printf("[timing] handleBloomParams failed after %s: %v\n", d1, err)
		return err
	}
	fmt.Printf("[timing] handleBloomParams ok in %s\n", d1)

	// --- 3) randomApprovedIndices ---
	t2 := time.Now()
	approvedIndices := randomApprovedIndices(bloomParams.M, bloomParams.T)
	d2 := time.Since(t2)
	fmt.Printf("[timing] randomApprovedIndices took %s\n", d2)

	localVoteMsg := LocalApproveVoteMsg{ApprovedIndices: approvedIndices}
	msgBody, _ := json.Marshal(localVoteMsg)

	t3 := time.Now()
	resp, err := http.Post(fmt.Sprintf("http://%s/vote/approve", n.NodeTable[n.NodeID]),
		"application/json", bytes.NewBuffer(msgBody))
	d3 := time.Since(t3)
	if err != nil {
		return fmt.Errorf("error triggering /vote/approve after %s: %v", d3, err)
	}
	defer resp.Body.Close()

	fmt.Printf("[timing] http.Post /vote/approve took %s\n", d3)
	if resp.StatusCode == http.StatusOK {
		fmt.Println("Successfully triggered local approve vote.")
	} else {
		fmt.Printf("Failed to trigger /vote/approve, status code: %d\n", resp.StatusCode)
	}

	totalExceptVRF := d1 + d2 + d3
	fmt.Printf("[timing] total(except evalVRFOnce)=%s\n", totalExceptVRF)

	return nil
}

func randomApprovedIndices(M, T int) []uint64 {
	if M <= 0 || T <= 0 {
		return nil
	}
	if T > M {
		T = M
	}
	rand.Seed(time.Now().UnixNano())
	perm := rand.Perm(M)[:T]
	out := make([]uint64, 0, T)
	for _, p := range perm {
		out = append(out, uint64(p))
	}
	return out
}

func (n *Node) VerifyAndSaveVRF(v *VRFResult) error {

	if v.T != n.VRF_T || v.Context != n.VRF_Context {
		return fmt.Errorf("round mismatch: expected (T=%d, context=%s), got (T=%d, context=%s)", n.VRF_T, n.VRF_Context, v.T, v.Context)
	}

	expectedPK := hex.EncodeToString(n.SelfPK)
	if !strings.EqualFold(expectedPK, v.PKHex) {
		return fmt.Errorf("public key mismatch for NodeID %s: expected %s, got %s", v.NodeID, expectedPK, v.PKHex)
	}

	key := SeenKey{Round: RoundKey{T: v.T, C: v.Context}, NodeID: v.NodeID}
	if _, ok := seen[key]; ok {
		return fmt.Errorf("duplicate VRF result received from node %s for round %d", v.NodeID, v.T)
	}

	msg := makeMessage(v.T, []byte(v.Context))
	ok, err := vrf_ed25519.ECVRF_verify(ed25519.PublicKey(v.PKHex), v.Proof, msg)
	if err != nil || !ok {
		return fmt.Errorf("VRF proof verification failed for node %s: %v", v.NodeID, err)
	}

	out := vrf_ed25519.ECVRF_proof2hash(v.Proof)
	value := bytesToUnitFloat(out)

	chosen := value < n.Tau

	rec := &VRFRecord{
		NodeID:   v.NodeID,
		PK:       ed25519.PublicKey(v.PKHex),
		T:        v.T,
		Context:  v.Context,
		Proof:    v.Proof,
		Value:    value,
		Verified: true,
		Chosen:   chosen,
		RecvTime: time.Now(),
	}

	n.CandidateSet[v.NodeID] = rec

	seen[key] = struct{}{}

	if chosen {
		fmt.Printf("Node %s is chosen for the candidate set, value: %.8f\n", v.NodeID, value)
	}

	return nil
}

func jsonMarshal(v interface{}) ([]byte, error) {
	type alias = interface{}
	return json.Marshal(alias(v))
}

func (n *Node) RunAggVRFBroadcast(context string) error {

	val, _, hash, err := n.evalVRFOnce(n.VRF_T, []byte(context))
	if err != nil {
		return err
	}
	_ = val

	var tail uint8
	if len(hash) > 0 {
		tail = hash[len(hash)-1]
	}
	_ = tail //

	n.Aggregators[0] = "1" //
	n.Aggregators[1] = "2" //

	n.IsAggregator = false
	n.AggregatorPart = 0
	switch n.NodeID {
	case n.Aggregators[0]:
		n.IsAggregator = true
		n.AggregatorPart = 1
	case n.Aggregators[1]:
		n.IsAggregator = true
		n.AggregatorPart = 2
	default:
		n.IsAggregator = false
		n.AggregatorPart = 0
	}

	fmt.Printf("[AggSelect] self=%s IsAgg=%v part=%d A=%s B=%s\n",
		n.NodeID, n.IsAggregator, n.AggregatorPart, n.Aggregators[0], n.Aggregators[1])
	if n.IsAggregator {
		if n.AggregatorPart == 1 {
			n.PeerAggregator = n.Aggregators[1] //
		} else if n.AggregatorPart == 2 {
			n.PeerAggregator = n.Aggregators[0] //
		}
		fmt.Printf("[AggSelect] self=%s part=%d peer=%s\n", n.NodeID, n.AggregatorPart, n.PeerAggregator)
	}

	return nil
}

func (n *Node) handleAggVRFMsg(m *AggVRFMsg) error {

	fmt.Printf("[handleAggVRFMsg] called by node=%s (AggContext=%s, MsgContext=%s, VRF_T=%d)\n",
		n.NodeID, n.AggContext, m.Context, n.VRF_T)

	if m.Context != n.AggContext {
		fmt.Printf("[handleAggVRFMsg] skip: context mismatch (got=%s, expect=%s)\n", m.Context, n.AggContext)
		return fmt.Errorf("agg vrf ctx mismatch")
	}

	pk, _ := hex.DecodeString(m.PKHex)
	ok, err := vrf_ed25519.ECVRF_verify(ed25519.PublicKey(pk), m.Proof, makeMessage(n.VRF_T, []byte(m.Context)))
	if err != nil {
		fmt.Printf("[handleAggVRFMsg] verify error from %s: %v\n", m.NodeID, err)
		return fmt.Errorf("agg vrf verify error: %v", err)
	}
	if !ok {
		fmt.Printf("[handleAggVRFMsg] verify failed from %s (proof invalid)\n", m.NodeID)
		return fmt.Errorf("agg vrf verify fail from %s", m.NodeID)
	}

	fmt.Printf("[handleAggVRFMsg] VRF proof verified successfully from node=%s\n", m.NodeID)

	out := vrf_ed25519.ECVRF_proof2hash(m.Proof)
	var tail uint8
	if len(out) > 0 {
		tail = out[len(out)-1]
	}
	fmt.Printf("[handleAggVRFMsg] proof2hash tail byte=%d (0x%x)\n", tail, tail)

	if _, exists := n.aggBox[m.NodeID]; exists {
		fmt.Printf("[handleAggVRFMsg] duplicate msg from node=%s, ignore.\n", m.NodeID)
		return nil
	}

	n.aggBox[m.NodeID] = tail
	fmt.Printf("[handleAggVRFMsg] stored tail for node=%s (currentBoxSize=%d)\n", m.NodeID, len(n.aggBox))

	threshold := int(float64(len(n.CandidateSet)) * 2.0 / 3.0)
	if len(n.aggBox) >= threshold {
		fmt.Printf("[handleAggVRFMsg] threshold reached (%d/%d), triggering finalization.\n",
			len(n.aggBox), threshold)
		n.tryFinalizeAggregators()
	} else {
		fmt.Printf("[handleAggVRFMsg] waiting for more VRF messages (%d/%d)\n",
			len(n.aggBox), threshold)
	}

	return nil
}

func (n *Node) tryFinalizeAggregators() {

	if n.Aggregators[0] != "" && n.Aggregators[1] != "" {
		return
	}
	if time.Now().Before(n.aggDeadline) && len(n.aggBox) < 2 {
		return //
	}
	n.finalizeAggregators()

	//
	winners := struct {
		Epoch, Round uint64
		Context      string
		MA, MB       string
		//
	}{n.AggEpoch, n.AggRound, n.AggContext, n.Aggregators[0], n.Aggregators[1]}
	body, _ := json.Marshal(winners)
	for _, url := range n.NodeTable {
		n.VoteSend_go <- SendMsg_go{url: url + "/vrf/agg_winners", msg: body}
	}
}

func (n *Node) finalizeAggregators() {
	items := make([]aggY, 0, len(n.aggBox))
	for id, t := range n.aggBox {
		items = append(items, aggY{NodeID: id, YTail2: t})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].YTail2 != items[j].YTail2 {
			return items[i].YTail2 < items[j].YTail2
		}
		return items[i].NodeID < items[j].NodeID
	})

	if len(items) >= 1 {
		n.Aggregators[0] = items[0].NodeID
	}
	if len(items) >= 2 {
		n.Aggregators[1] = items[1].NodeID
	}
}
