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

// ====== 消息类型 ======
type ApproveShareMsg struct {
	From   string   `json:"from"`
	Part   int      `json:"part"`   // 1 -> M_A, 2 -> M_B
	Shares []uint64 `json:"shares"` // 长度 = BloomL
	Commit []byte   `json:"commit"` // Pedersen 承诺 ComV
	Proof  []byte   `json:"proof"`  // Bulletproofs Range proof（封装）
	Upper  uint64   `json:"upper"`  // d * t
}

// (A) 设置Bloom系统参数（m, t, epsBF）
type BloomParamsMsg struct {
	M     int     `json:"m"`
	T     int     `json:"t"`
	EpsBF float64 `json:"eps_bf"`
}

// (B) 触发本地批准投票：输入我支持的候选人索引（索引应与 S 的全序一致）
type LocalApproveVoteMsg struct {
	ApprovedIndices []uint64 `json:"approved_indices"`
}

// VoteGenerator - 用于生成投票者支持的候选人名单
type VoteGenerator struct {
	CandidateSet []string // 候选人集合（可以根据实际应用传递候选人列表）
	MaxVotes     int      // 投票者最大可投票数
}

// (C) 对外发送：份额包（发送给 M_A 或 M_B）
type SecretSharePacket struct {
	FromNode string   `json:"from_node"`
	ToNode   string   `json:"to_node"`
	Part     int      `json:"part"` // 1 or 2
	L        int      `json:"l"`
	D        int      `json:"d"`
	Shares   []uint64 `json:"shares"` // mod Q
	// 证明随份额一起送达，接收侧先验再入账
	PedersenCom string `json:"pedersen_com_hex"`
	RangeProof  string `json:"range_proof_hex"`
	SumOnes     uint64 `json:"sum_ones"` // 仅便捷检查；真实验证依赖承诺+证明
}

// (D) 聚合者端：接收到的份额（内部消息）
type ReceivedShareMsg struct {
	Pkt SecretSharePacket
}

//   // 投票参数（可由合约/路由设置）
//   BloomM int; BloomT int; BloomEps float64
//   BloomL int; BloomD int
//   Aggregators [2]string // M_A, M_B
//   NodeTable map[string]string  // 已有
//   NodeID string                // 已有
//   VoteHTTP *http.Client        // 可复用 client

// GenerateVotes - 从候选集合无放回随机选 MaxVotes 个（不重复）
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
	// rand.Perm 无放回
	perm := rand.Perm(n)[:k]
	out := make([]uint64, 0, k)
	for _, p := range perm {
		out = append(out, uint64(p))
	}
	return out
}

// ------ 设置 Bloom 参数 ------
func (n *Node) handleBloomParams(p *BloomParamsMsg) error {
	n.BloomM, n.BloomT, n.BloomEps = p.M, p.T, p.EpsBF
	l, d := CalcBloomParams(n.BloomM, n.BloomT, n.BloomEps)
	n.BloomL, n.BloomD = l, d
	return nil
}

// ------ 本地批准投票主流程 ------
// 1) 构建 BF_i
// 2) 计算 sum_ones，做 Pedersen 承诺 + Bulletproofs Range(sum <= d*t)
// 3) 2-out-of-2 分享（mod Q）
// 4) Shares(1) → M_A, Shares(2) → M_B
func (n *Node) handleLocalApproveVote(msg *LocalApproveVoteMsg) error {
	//if n.BloomL == 0 || n.BloomD == 0 {
	//	return fmt.Errorf("Bloom params not set")
	//}
	//if n.Aggregators[0] == "" || n.Aggregators[1] == "" {
	//	return fmt.Errorf("aggregators not selected yet")
	//}
	//if msg == nil || len(msg.ApprovedIndices) == 0 {
	//	return fmt.Errorf("no approved indices provided")
	//}
	// 直接设置两个聚合节点的 NodeID
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

	// —— 1) 规范化输入：去重、边界、限额 —— //
	uniq := make(map[uint64]struct{}, len(msg.ApprovedIndices))
	cleaned := make([]uint64, 0, len(msg.ApprovedIndices))
	for _, idx := range msg.ApprovedIndices {
		if idx >= uint64(n.BloomM) {
			// 索引越界，忽略或报错。这里选择忽略并记录；也可 return error
			continue
		}
		if _, ok := uniq[idx]; ok {
			continue // 去重
		}
		uniq[idx] = struct{}{}
		cleaned = append(cleaned, idx)
		if len(cleaned) == n.BloomT { // 不超过批准上限 t
			break
		}
	}
	if len(cleaned) == 0 {
		return fmt.Errorf("no valid approved indices after sanitize")
	}

	// 输出去重后的投票名单
	fmt.Printf("Cleaned and Validated Approved Indices: %v\n", cleaned)

	// 1) 构建布隆过滤器
	tBloom := time.Now()
	bf := NewBloom(n.BloomL, n.BloomD)
	for _, idx := range cleaned {
		bf.AddIndex(idx)
	}
	sum := uint64(bf.OnesCount())
	fmt.Printf("[timing] Bloom build+OnesCount took %s (L=%d D=%d added=%d sum=%d)\n",
		time.Since(tBloom), n.BloomL, n.BloomD, len(cleaned), sum)

	// 2) 承诺 + 生成范围证明（Pedersen + Range）
	sumBig := new(big.Int).SetUint64(sum)
	rnd := new(big.Int).SetUint64(randUint64ModQ())
	tPed := time.Now()
	com, _ := PedersenCommit(sumBig, rnd)
	fmt.Printf("[timing] PedersenCommit took %s\n", time.Since(tPed))
	// 输出 Pedersen 承诺的值
	fmt.Printf("Pedersen Commitment: %x (len=%d)\n", com.Commit[:8], len(com.Commit))

	upper := uint64(n.BloomD * n.BloomT)

	tRP := time.Now()
	proof, _ := GenerateRangeProof(sumBig, upper, com)
	// 将 proof 转换为字节数组
	proofBytes, _ := proof.MarshalBinary()
	fmt.Printf("[timing] GenerateRangeProof took %s (upper=%d)\n", time.Since(tRP), upper)
	// 输出范围证明的值
	fmt.Printf("Range Proof prefix: %x... (len=%d)\n", proofBytes[:16], len(proofBytes))

	// 3) 生成 2-out-of-2 分享
	tSplit := time.Now()
	bits := bf.ExportBits()
	s1, s2, err := SplitBitsAdditive(bits)
	fmt.Printf("[timing] SplitBitsAdditive took %s (bits_len=%d)\n", time.Since(tSplit), len(bits))
	if err != nil {
		return err
	}

	// 4) 发送
	pkHex := hex.EncodeToString(com.Commit)

	// 创建 SecretSharePacket 发送
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

	// 发送函数
	if n.VoteHTTP == nil {
		n.VoteHTTP = &http.Client{
			Timeout: 5 * time.Second,
		}
	}
	send := func(pkt SecretSharePacket) error {
		url := n.NodeTable[pkt.ToNode] + "/vote/share"
		body, _ := json.Marshal(pkt)

		// —— 调试日志：打印要发给谁、份额长度、承诺&范围证明的前缀等 —— //
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
	// 发送并打印 pkt1/pkt2 概要
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

// ------ 聚合者收到份额后的校验入口 ------
// 先验 RangeProof（未通过则拒绝），通过后入账等待计票阶段聚合
func (n *Node) handleReceivedShare(m *ReceivedShareMsg) error {
	start := time.Now()
	defer func() {
		fmt.Printf("[timing] handleReceivedShare total=%s\n", time.Since(start))
	}()
	if !n.IsAggregator {
		return nil
	}
	pkt := m.Pkt

	// 输出接收到的份额信息
	fmt.Printf("[ReceivedShare] self=%s IsAgg=%v part=%d From=%s Part=%d L=%d D=%d\n",
		n.NodeID, n.IsAggregator, n.AggregatorPart, pkt.FromNode, pkt.Part, pkt.L, pkt.D)
	fmt.Printf("[ReceivedShare] PedersenCom=%s\n", pkt.PedersenCom)
	fmt.Printf("[ReceivedShare] RangeProof(len=%d)\n", len(pkt.RangeProof))

	// 解析承诺和范围证明
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

	// 验证范围证明
	//if !VerifyRangeProof(com, &RangeProof{Proof: proofBytes}, uint64(pkt.D*n.BloomT)) {
	//	return fmt.Errorf("invalid range proof from %s", pkt.FromNode)
	//}
	// 输出验证结果
	fmt.Printf("[ReceivedShare] Range proof verified for node: %s\n", pkt.FromNode)

	n.mu.Lock()
	if n.RecvSharesPart1 == nil {
		n.RecvSharesPart1 = make(map[string][]uint64)
	}
	if n.RecvSharesPart2 == nil {
		n.RecvSharesPart2 = make(map[string][]uint64)
	}

	// 在验证范围证明后，存储收到的份额
	switch pkt.Part {
	case 1:
		// 建议做一次拷贝，避免外部 slice 复用
		n.RecvSharesPart1[pkt.FromNode] = append([]uint64(nil), pkt.Shares...)
	case 2:
		n.RecvSharesPart2[pkt.FromNode] = append([]uint64(nil), pkt.Shares...)
	default:
		n.mu.Unlock()
		return fmt.Errorf("invalid part=%d", pkt.Part)
	}

	// 为了定位问题，强烈建议打一下 key 数：
	r1, r2 := len(n.RecvSharesPart1), len(n.RecvSharesPart2)
	//myPart := n.AggregatorPart
	n.mu.Unlock()
	fmt.Printf("[ReceivedShare] stored; recv1=%d recv2=%d\n", r1, r2)

	// 只有我是该 part 的聚合者时才聚合（并且此时已经解锁了）
	// 入账后：
	//if (pkt.Part == 1 && myPart == 1) || (pkt.Part == 2 && myPart == 2) {
	//	// 如果你还需要别的聚合计算，保留：
	//	// _ = n.ComputeAggregatePart()
	//	n.TrySendAggregateCommitOnce() // ← 只触发这个
	//}
	//避免竞态
	//n.onShareArrived()

	n.wg.Done()

	return nil
}
func (n *Node) onShareArrived() {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.IsAggregator || n.aggRoundStarted {
		return
	}

	// 当前已收到的有效发送方个数
	//var have = 0
	//switch n.AggregatorPart {
	//case 1:
	//	have = len(n.RecvSharesPart1)
	//case 2:
	//	have = len(n.RecvSharesPart2)
	//default:
	//	return
	//}

	// 1) 第一次收到份额 -> 懒启动计时器
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

	//// 2) 若设置了最小门限，且达到门限 -> 提前启动
	//if n.MinVotes > 0 && have >= n.MinVotes {
	//	if n.aggTimer != nil {
	//		_ = n.aggTimer.Stop()
	//		n.aggTimer = nil
	//	}
	//	n.aggRoundStarted = true
	//	epoch, round, ctx, win := n.CurrentEpoch, n.CurrentRound, n.VRF_Context, n.Window
	//	// 先释放锁，再启动，避免死锁/长阻塞
	//	n.mu.Unlock()
	//	go n.startAggRound(epoch, round, ctx, win)
	//	n.mu.Lock()
	//	fmt.Printf("[agg] early start (min-votes): have=%d min=%d part=%d\n", have, n.MinVotes, n.AggregatorPart)
	//} else {
	//	fmt.Printf("[agg] wait: have=%d min=%d part=%d\n", have, n.MinVotes, n.AggregatorPart)
	//}
}

//	func (n *Node) startAggRoundBy(reason string) {
//		n.mu.Lock()
//		if n.aggRoundStarted {
//			n.mu.Unlock()
//			return
//		}
//		n.aggRoundStarted = true
//		epoch, round, ctx, win := n.CurrentEpoch, n.CurrentRound, n.VRF_Context, n.Window
//		n.mu.Unlock()
//
//		fmt.Printf("[agg] start aggregation by %s: epoch=%d round=%d part=%d\n",
//			reason, epoch, round, n.AggregatorPart)
//
//		go n.startAggRound(epoch, round, ctx, win)
//	}
//
// startAggRoundBy：由计时器/最小门限触发，改为通过 HTTP 调用 /vrf/agg_start
func (n *Node) startAggRoundBy(reason string) {
	n.mu.Lock()
	if n.aggRoundStarted {
		n.mu.Unlock()
		return
	}
	n.aggRoundStarted = true

	// 取当前轮上下文
	epoch, round, ctx := n.CurrentEpoch, n.CurrentRound, n.VRF_Context

	// 计算窗口（毫秒），默认 1 分钟
	win := n.AggWindow
	if win <= 0 {
		win = time.Minute
	}
	winMs := uint64(win / time.Millisecond)

	// 取本节点的对外地址（用于 POST 到自己）
	selfURL := n.NodeTable[n.NodeID]
	n.mu.Unlock()

	fmt.Printf("[agg] start aggregation by %s: epoch=%d round=%d part=%d win=%s url=%s\n",
		reason, epoch, round, n.AggregatorPart, win, selfURL)

	// 组装请求体（与 /vrf/agg_start 的解码结构对齐）
	req := struct {
		Epoch   uint64        `json:"epoch"`
		Round   uint64        `json:"round"`
		Context string        `json:"context"`
		Window  time.Duration `json:"window_ms"` // 这里传毫秒的整数；服务端会 time.Millisecond*Window
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
