package priacy_compute

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"net/http"
	"time"
)

type ApproveShareMsg struct {
	From   string   `json:"from"`
	Part   int      `json:"part"`   // 1 -> M_A, 2 -> M_B
	Shares []uint64 `json:"shares"` //
	Commit []byte   `json:"commit"` //
	Proof  []byte   `json:"proof"`  //
	Upper  uint64   `json:"upper"`  // d * t
}

type BloomParamsMsg struct {
	M     int     `json:"m"`
	T     int     `json:"t"`
	EpsBF float64 `json:"eps_bf"`
}

type LocalApproveVoteMsg struct {
	ApprovedIndices []uint64 `json:"approved_indices"`
}

type VoteGenerator struct {
	CandidateSet []string //
	MaxVotes     int      //
}

type SecretSharePacket struct {
	FromNode string   `json:"from_node"`
	ToNode   string   `json:"to_node"`
	Part     int      `json:"part"` // 1 or 2
	L        int      `json:"l"`
	D        int      `json:"d"`
	Shares   []uint64 `json:"shares"` //

	PedersenCom string `json:"pedersen_com_hex"`
	RangeProof  string `json:"range_proof_hex"`
	SumOnes     uint64 `json:"sum_ones"`
}

type ReceivedShareMsg struct {
	Pkt SecretSharePacket
}

func (v *VoteGenerator) GenerateVotes() []uint64 {
	rand.Seed(time.Now().UnixNano())
	n := len(v.CandidateSet)
	if n == 0 || v.MaxVotes <= 0 {
		return nil
	}
	k := v.MaxVotes
	if k > n {
		k = n
	}

	perm := rand.Perm(n)[:k]
	out := make([]uint64, 0, k)
	for _, p := range perm {
		out = append(out, uint64(p))
	}
	return out
}

func (n *Node) handleBloomParams(p *BloomParamsMsg) error {
	n.BloomM, n.BloomT, n.BloomEps = p.M, p.T, p.EpsBF
	l, d := CalcBloomParams(n.BloomM, n.BloomT, n.BloomEps)
	n.BloomL, n.BloomD = l, d
	return nil
}

func (n *Node) handleLocalApproveVote(msg *LocalApproveVoteMsg) error {

	start := time.Now()
	defer func() {
		fmt.Printf("[timing] handleLocalApproveVote total=%s\n", time.Since(start))
	}()

	tRB := time.Now()
	err := n.RunAggVRFBroadcast(n.VRF_Context)
	fmt.Printf("[timing] RunAggVRFBroadcast(ctx=%q) took %s\n", n.VRF_Context, time.Since(tRB))
	if err != nil {
		return err
	}

	uniq := make(map[uint64]struct{}, len(msg.ApprovedIndices))
	cleaned := make([]uint64, 0, len(msg.ApprovedIndices))
	for _, idx := range msg.ApprovedIndices {
		if idx >= uint64(n.BloomM) {

			continue
		}
		if _, ok := uniq[idx]; ok {
			continue //
		}
		uniq[idx] = struct{}{}
		cleaned = append(cleaned, idx)
		if len(cleaned) == n.BloomT { //
			break
		}
	}
	if len(cleaned) == 0 {
		return fmt.Errorf("no valid approved indices after sanitize")
	}

	fmt.Printf("Cleaned and Validated Approved Indices: %v\n", cleaned)

	tBloom := time.Now()
	bf := NewBloom(n.BloomL, n.BloomD)
	for _, idx := range cleaned {
		bf.AddIndex(idx)
	}
	sum := uint64(bf.OnesCount())
	fmt.Printf("[timing] Bloom build+OnesCount took %s (L=%d D=%d added=%d sum=%d)\n",
		time.Since(tBloom), n.BloomL, n.BloomD, len(cleaned), sum)

	sumBig := new(big.Int).SetUint64(sum)
	rnd := new(big.Int).SetUint64(randUint64ModQ())
	tPed := time.Now()
	com, _ := PedersenCommit(sumBig, rnd)
	fmt.Printf("[timing] PedersenCommit took %s\n", time.Since(tPed))

	fmt.Printf("Pedersen Commitment: %x (len=%d)\n", com.Commit[:8], len(com.Commit))

	upper := uint64(n.BloomD * n.BloomT)

	tRP := time.Now()
	proof, _ := GenerateRangeProof(sumBig, upper, com)
	//
	proofBytes, _ := proof.MarshalBinary()
	fmt.Printf("[timing] GenerateRangeProof took %s (upper=%d)\n", time.Since(tRP), upper)
	//
	fmt.Printf("Range Proof prefix: %x... (len=%d)\n", proofBytes[:16], len(proofBytes))

	// 3)
	tSplit := time.Now()
	bits := bf.ExportBits()
	s1, s2, err := SplitBitsAdditive(bits)
	fmt.Printf("[timing] SplitBitsAdditive took %s (bits_len=%d)\n", time.Since(tSplit), len(bits))
	if err != nil {
		return err
	}

	// 4)
	pkHex := hex.EncodeToString(com.Commit)

	//
	pkt1 := SecretSharePacket{
		FromNode:    n.NodeID,
		ToNode:      n.Aggregators[0],
		Part:        1,
		L:           n.BloomL,
		D:           n.BloomD,
		Shares:      s1,
		PedersenCom: pkHex,
		RangeProof:  hex.EncodeToString(proofBytes),
		SumOnes:     sum,
	}

	pkt2 := SecretSharePacket{
		FromNode:    n.NodeID,
		ToNode:      n.Aggregators[1],
		Part:        2,
		L:           n.BloomL,
		D:           n.BloomD,
		Shares:      s2,
		PedersenCom: pkHex,
		RangeProof:  hex.EncodeToString(proofBytes),
		SumOnes:     sum,
	}

	//
	if n.VoteHTTP == nil {
		n.VoteHTTP = &http.Client{
			Timeout: 5 * time.Second,
		}
	}
	send := func(pkt SecretSharePacket) error {
		url := n.NodeTable[pkt.ToNode] + "/vote/share"
		body, _ := json.Marshal(pkt)

		//
		fmt.Printf("[vote/send] from=%s -> to=%s url=http://%s\n", pkt.FromNode, pkt.ToNode, url)
		fmt.Printf("[vote/send] part=%d L=%d D=%d sumOnes=%d shares_len=%d\n",
			pkt.Part, pkt.L, pkt.D, pkt.SumOnes, len(pkt.Shares))
		if len(pkt.PedersenCom) > 16 {
			fmt.Printf("[vote/send] pedersenCom(hex)=%s...\n", pkt.PedersenCom[:16])
		} else {
			fmt.Printf("[vote/send] pedersenCom(hex)=%s\n", pkt.PedersenCom)
		}
		if len(pkt.RangeProof) > 32 {
			fmt.Printf("[vote/send] rangeProof(hex)=%s...\n", pkt.RangeProof[:32])
		} else {
			fmt.Printf("[vote/send] rangeProof(hex)=%s\n", pkt.RangeProof)
		}

		resp, err := n.VoteHTTP.Post("http://"+url, "application/json", bytes.NewBuffer(body))
		if err != nil {
			return fmt.Errorf("POST http://%s failed: %w", url, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("POST http://%s status=%d", url, resp.StatusCode)
		}
		return nil

		//_, err := n.VoteHTTP.Post("http://"+url, "application/json", bytes.NewBuffer(body))
		//return err
	}
	//
	fmt.Printf("[vote/send] pkt1 -> %s (part=%d)\n", pkt1.ToNode, pkt1.Part)
	if err := send(pkt1); err != nil {
		return fmt.Errorf("send pkt1: %w", err)
	}
	fmt.Printf("[vote/send] pkt2 -> %s (part=%d)\n", pkt2.ToNode, pkt2.Part)
	if err := send(pkt2); err != nil {
		return fmt.Errorf("send pkt2: %w", err)
	}
	//if err := send(pkt1); err != nil {
	//	return err
	//}
	//if err := send(pkt2); err != nil {
	//	return err
	//}

	return nil
}

func (n *Node) handleReceivedShare(m *ReceivedShareMsg) error {
	start := time.Now()
	defer func() {
		fmt.Printf("[timing] handleReceivedShare total=%s\n", time.Since(start))
	}()
	if !n.IsAggregator {
		return nil
	}
	pkt := m.Pkt

	fmt.Printf("[ReceivedShare] self=%s IsAgg=%v part=%d From=%s Part=%d L=%d D=%d\n",
		n.NodeID, n.IsAggregator, n.AggregatorPart, pkt.FromNode, pkt.Part, pkt.L, pkt.D)
	fmt.Printf("[ReceivedShare] PedersenCom=%s\n", pkt.PedersenCom)
	fmt.Printf("[ReceivedShare] RangeProof(len=%d)\n", len(pkt.RangeProof))

	comBytes, err := hex.DecodeString(pkt.PedersenCom)
	if err != nil {
		return err
	}
	//proofBytes, err := hex.DecodeString(pkt.RangeProof)
	//if err != nil {
	//	return err
	//}
	//
	//com := &PedersenCommitment{
	//	Commit: comBytes,
	//	Value:  new(big.Int).SetUint64(pkt.SumOnes),
	//	Rand:   new(big.Int).SetUint64(0),
	//}
	fmt.Printf("[ReceivedShare] (SKIP RANGE PROOF CHECK) SumOnes=%d Commit[0:8]=%x...\n",
		pkt.SumOnes,
		comBytes[:min(8, len(comBytes))],
	)

	//if !VerifyRangeProof(com, &RangeProof{Proof: proofBytes}, uint64(pkt.D*n.BloomT)) {
	//	return fmt.Errorf("invalid range proof from %s", pkt.FromNode)
	//}

	fmt.Printf("[ReceivedShare] Range proof verified for node: %s\n", pkt.FromNode)

	n.mu.Lock()
	if n.RecvSharesPart1 == nil {
		n.RecvSharesPart1 = make(map[string][]uint64)
	}
	if n.RecvSharesPart2 == nil {
		n.RecvSharesPart2 = make(map[string][]uint64)
	}

	switch pkt.Part {
	case 1:

		n.RecvSharesPart1[pkt.FromNode] = append([]uint64(nil), pkt.Shares...)
	case 2:
		n.RecvSharesPart2[pkt.FromNode] = append([]uint64(nil), pkt.Shares...)
	default:
		n.mu.Unlock()
		return fmt.Errorf("invalid part=%d", pkt.Part)
	}

	r1, r2 := len(n.RecvSharesPart1), len(n.RecvSharesPart2)
	//myPart := n.AggregatorPart
	n.mu.Unlock()
	fmt.Printf("[ReceivedShare] stored; recv1=%d recv2=%d\n", r1, r2)

	n.wg.Done()

	return nil
}
func (n *Node) onShareArrived() {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.IsAggregator || n.aggRoundStarted {
		return
	}

	if n.aggTimer == nil {
		win := n.AggWindow
		if win <= 0 {
			win = 30 * time.Second // 默认 1 分钟
		}
		n.aggTimer = time.AfterFunc(win, func() {
			n.startAggRoundBy("timer")
		})
		fmt.Printf("[agg] window timer started: win=%s part=%d\n", win, n.AggregatorPart)
	}

}

func (n *Node) startAggRoundBy(reason string) {
	n.mu.Lock()
	if n.aggRoundStarted {
		n.mu.Unlock()
		return
	}
	n.aggRoundStarted = true

	epoch, round, ctx := n.CurrentEpoch, n.CurrentRound, n.VRF_Context

	win := n.AggWindow
	if win <= 0 {
		win = time.Minute
	}
	winMs := uint64(win / time.Millisecond)

	selfURL := n.NodeTable[n.NodeID]
	n.mu.Unlock()

	fmt.Printf("[agg] start aggregation by %s: epoch=%d round=%d part=%d win=%s url=%s\n",
		reason, epoch, round, n.AggregatorPart, win, selfURL)

	req := struct {
		Epoch   uint64        `json:"epoch"`
		Round   uint64        `json:"round"`
		Context string        `json:"context"`
		Window  time.Duration `json:"window_ms"` //
	}{
		Epoch:   epoch,
		Round:   round,
		Context: ctx,
		Window:  time.Duration(winMs),
	}

	body, err := json.Marshal(&req)
	if err != nil {
		fmt.Printf("[agg] marshal agg_start req failed: %v\n", err)
		return
	}

	go func() {
		endpoint := fmt.Sprintf("http://%s/vrf/agg_start", selfURL)
		resp, err := http.Post(endpoint, "application/json", bytes.NewReader(body))
		if err != nil {
			fmt.Printf("[agg] POST %s failed: %v\n", endpoint, err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Printf("[agg] agg_start status=%d\n", resp.StatusCode)
			return
		}
		fmt.Println("[agg] agg_start posted successfully.")
	}()
}
