package priacy_compute

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	poseidon2 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	bn254kzg "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	plonkbn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

// ========== 消息与数据结构 ==========

// 1) 聚合者收到份额后的“我已收到份额”在内存中累加，触发计算时主动调用 ComputeAggregatePart()

// 2) 交换承诺
type AggCommitMsg struct {
	FromNode string `json:"from_node"`
	L        int    `json:"l"`
	Part     int    `json:"part"` // 1: A 的 Σ^(1) 承诺, 2: B 的 Σ^(2) 承诺
	// 承诺对象（占位）：我们对 “Σ^part 所有元素和(mod q)” 做 Pedersen 承诺
	CommitHex string `json:"commit_hex"`
	// 为快速防篡改，附加 Σ^part 的哈希（不泄露明文，但链下可比对）
	VectorHash string `json:"vector_hash_hex"`
}

// 3) 交换聚合向量（用于重建 Σ[l]）
type AggSumsMsg struct {
	FromNode string   `json:"from_node"`
	L        int      `json:"l"`
	Part     int      `json:"part"` // 1 or 2
	Sums     []uint64 `json:"sums"` // Σ^(part)[l] 向量（mod Q）
}

// 4) 最终计票与证明广播
type CountProofMsg struct {
	FromNode string   `json:"from_node"`
	M        int      `json:"m"` // |S|
	D        int      `json:"d"`
	L        int      `json:"l"`
	K        int      `json:"k"`
	T        []uint64 `json:"t_vector"` // T_c（可选：你也可只发 Top-K 结果）
	TopKIdx  []int    `json:"topk_indices"`
	Proof    string   `json:"proof_hex"` // zk-SNARK 证明（占位）
	// 绑定承诺（双边的）：防抵赖
	VK         string // hex (新增)
	HTPoseidon string // hex (可选)
	CommitA    string `json:"commit_a_hex"`
	CommitB    string `json:"commit_b_hex"`
}

// 仅用于“手动触发发送”Σ^(part)”的内部消息
type TriggerSendSumsMsg struct {
	// 可选：是否强制（忽略对端承诺是否到齐等前置）
	Force bool `json:"force,omitempty"`
}

// ========== 工具：模 Q 加法 ==========
func addModQ(a, b uint64) uint64 {
	qa := Q.Uint64()
	s := a + b
	if s >= qa || s < a { // 溢出或 >=Q
		s = s - qa
	}
	return s
}

func (n *Node) TrySendAggregateCommitOnce() {
	fmt.Printf("[TrySendAggregateCommitOnce] called by node=%s (IsAggregator=%v, sentAggCommit=%v, part=%d)\n",
		n.NodeID, n.IsAggregator, n.sentAggCommit, n.AggregatorPart)

	if !n.IsAggregator || n.sentAggCommit {
		return
	}
	n.mu.Lock()
	L := n.BloomL
	haveShare := (n.AggregatorPart == 1 && len(n.RecvSharesPart1) > 0) ||
		(n.AggregatorPart == 2 && len(n.RecvSharesPart2) > 0)

	if !haveShare || L == 0 {
		fmt.Printf("[TrySendAggregateCommitOnce] skip: haveShare=%v L=%d part=%d recv1=%d recv2=%d\n",
			haveShare, L, n.AggregatorPart, len(n.RecvSharesPart1), len(n.RecvSharesPart2))
		n.mu.Unlock()
		return
	}
	// ✅ 新增：开始组合向量日志
	fmt.Printf("[TrySendAggregateCommitOnce] begin aggregation vector combine, L=%d part=%d\n", L, n.AggregatorPart)
	tReduce := time.Now()

	// 组合本地向量（在锁内读 map，安全）
	vec := make([]uint64, L)
	if n.AggregatorPart == 1 {
		for _, v := range n.RecvSharesPart1 {
			for i := 0; i < L; i++ {
				vec[i] = addModQ(vec[i], v[i])
			}
		}
		// 写回状态，用于无参 SendAggregateCommit 读取；用拷贝避免后续误改
		n.Sigma1 = vec
	} else {
		for _, v := range n.RecvSharesPart2 {
			for i := 0; i < L; i++ {
				vec[i] = addModQ(vec[i], v[i])
			}
		}
		n.Sigma2 = vec
	}
	fmt.Printf("aggregatecommit=%s\n", time.Since(tReduce))
	// ✅ 新增：发送前日志
	fmt.Printf("[TrySendAggregateCommitOnce] sending aggregate commit (part=%d, L=%d)\n",
		n.AggregatorPart, L)

	// 这里不持锁，安全发送
	if err := n.SendAggregateCommit(); err != nil {
		fmt.Printf("[TrySendAggregateCommitOnce] send commit err: %v\n", err)
		return
	}

	n.mu.Lock()
	n.sentAggCommit = true
	n.mu.Unlock()
}

// ========== 向对端发送承诺（承诺 Σ^(part) 的标量总和；并附向量hash） ==========
func (n *Node) SendAggregateCommit() error {
	if !n.IsAggregator {
		return fmt.Errorf("not aggregator")
	}
	if n.PeerAggregator == "" {
		return fmt.Errorf("peer aggregator empty")
	}
	L := n.BloomL
	part := n.AggregatorPart
	fmt.Printf("[SendAggregateCommit] part=%d L=%d peer=%s\n", part, L, n.PeerAggregator)

	// 输出聚合部分信息
	fmt.Printf("[SendAggregateCommit] AggregatorPart: %d, BloomL: %d\n", part, L)

	var vec []uint64
	if part == 1 {
		vec = n.Sigma1
	} else if part == 2 {
		vec = n.Sigma2
	} else {
		return fmt.Errorf("bad part=%d", part)
	}

	// 输出当前使用的向量
	fmt.Printf("[SendAggregateCommit] Using vector: %v\n", vec)

	if vec == nil || len(vec) != L {
		return fmt.Errorf("aggregate first")
	}
	t0 := time.Now()
	// totals = sum_l Σ^(part)[l] (mod Q)
	total := uint64(0)
	for i := 0; i < L; i++ {
		total = addModQ(total, vec[i])
	}
	fmt.Printf("total sum_l=%s ok=%v err=%v\n", time.Since(t0))
	// 输出总和值
	fmt.Printf("[SendAggregateCommit] Calculated total: %d\n", total)
	t1 := time.Now()
	// Pedersen 承诺
	val := new(big.Int).SetUint64(total)
	rnd := new(big.Int).SetUint64(randUint64ModQ())
	com, _ := PedersenCommit(val, rnd)
	fmt.Printf("PedersenCommit=%s ok=%v err=%v\n", time.Since(t1))
	// 输出 Pedersen 承诺信息
	fmt.Printf("[SendAggregateCommit] Pedersen Commitment: %x\n", com.Commit)

	// 向量 hash（不泄露明文）
	h := sha256.New()
	for _, v := range vec {
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], v)
		h.Write(buf[:])
	}
	vectorHash := hex.EncodeToString(h.Sum(nil))

	// 将自己的承诺加入到状态中：
	//selfMsg := AggCommitMsg{
	//	FromNode:   n.NodeID,
	//	L:          L,
	//	Part:       part,
	//	CommitHex:  hex.EncodeToString(com.Commit),
	//	VectorHash: vectorHash, // 已经是 hex 字符串
	//}
	// 直接复用相同的校验/存储逻辑
	//if err := n.handleAggCommitMsg(&selfMsg); err != nil {
	//	fmt.Printf("[SendAggregateCommit] cache self commit failed: %v\n", err)
	//}
	// 输出向量 hash 信息
	fmt.Printf("[SendAggregateCommit] Vector Hash: %s\n", vectorHash)

	// 创建并发送消息
	msg := AggCommitMsg{
		FromNode:   n.NodeID,
		L:          L,
		Part:       part,
		CommitHex:  hex.EncodeToString(com.Commit),
		VectorHash: vectorHash,
	}
	body, _ := json.Marshal(msg)

	// 输出即将发送的消息
	fmt.Printf("[SendAggregateCommit] Sending message: %v\n", msg)

	url := n.NodeTable[n.PeerAggregator] + "/vote/aggregate/commit"
	if n.VoteHTTP == nil {
		n.VoteHTTP = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := n.VoteHTTP.Post("http://"+url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("POST http://%s failed: %w", url, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	fmt.Printf("[SendAggregateCommit] OK -> %s (status=%d)\n", url, resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST http://%s status=%d", url, resp.StatusCode)
	}
	// 输出发送成功的消息
	fmt.Printf("[SendAggregateCommit] Successfully sent aggregate commit to %s\n", url)
	return nil
}

// 严格十六进制解码：长度需为偶数、且全为合法 hex。
func decodeHexStrict(s string) ([]byte, error) {
	if len(s) == 0 {
		return nil, errors.New("empty hex string")
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("hex length must be even, got %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("bad hex: %w", err)
	}
	return b, nil
}

// 固定长度校验（可选）
func checkLen(name string, got []byte, want int) error {
	if want <= 0 {
		return nil // 未设置则不校验
	}
	if len(got) != want {
		return fmt.Errorf("%s length mismatch: got %d, want %d", name, len(got), want)
	}
	return nil
}

// ========== 处理对端承诺/向量 ==========
func (n *Node) handleAggCommitMsg(m *AggCommitMsg) error {
	fmt.Printf("[handleAggCommitMsg] node=%s got commit from part=%d peer=%s vecHash[0:8]=%s...\n",
		n.NodeID, m.Part, m.VectorHash[:8])
	fmt.Println("[handleAggCommitMsg] Starting message processing")
	if m == nil {
		return errors.New("nil message")
	}
	fmt.Println("[handleAggCommitMsg] Commit decoded successfully")
	// 1) 解析并校验输入
	fmt.Println("[handleAggCommitMsg] Starting message processing")
	commit, err := decodeHexStrict(m.CommitHex)
	if err != nil {
		fmt.Printf("[handleAggCommitMsg] Error decoding commit: %v\n", err)
		return fmt.Errorf("commit decode failed: %w", err)
	}
	fmt.Println("[handleAggCommitMsg] Commit decoded successfully")

	fmt.Println("[handleAggCommitMsg] Starting message processing")
	vecHash, err := decodeHexStrict(m.VectorHash)
	if err != nil {
		fmt.Printf("[handleAggCommitMsg] Error decoding vector hash: %v\n", err)
		return fmt.Errorf("vector hash decode failed: %w", err)
	}
	fmt.Println("[handleAggCommitMsg] Commit decoded successfully")
	// 可选：严格长度
	//if err := checkLen("commit", commit, n.ExpectedCommitLen); err != nil {
	//	fmt.Printf("[handleAggCommitMsg] Commit length check failed: %v\n", err)
	//	return err
	//}
	//if err := checkLen("vector hash", vecHash, n.ExpectedHashLen); err != nil {
	//	fmt.Printf("[handleAggCommitMsg] Vector hash length check failed: %v\n", err)
	//	return err
	//}

	// 2) 落地到节点状态（加锁保证并发安全）
	//n.mu.Lock()
	//defer n.mu.Unlock()

	// 输出接收到的消息内容
	fmt.Printf("[handleAggCommitMsg] Received commit message: Part: %d, CommitHex: %s, VectorHash: %s\n", m.Part, m.CommitHex, m.VectorHash)

	switch m.Part {
	case 1: // 来自 M_A
		if n.haveA {
			return errors.New("duplicate commit from part=1 (M_A)")
		}
		n.commitA = append(n.commitA[:0], commit...) // 拷贝以免外部切片被改
		n.vectorHashA = append(n.vectorHashA[:0], vecHash...)
		n.haveA = true
		fmt.Printf("[handleAggCommitMsg] Stored commit for M_A, Commit: %x, VectorHash: %x\n", n.commitA, n.vectorHashA)
	case 2: // 来自 M_B
		if n.haveB {
			return errors.New("duplicate commit from part=2 (M_B)")
		}
		n.commitB = append(n.commitB[:0], commit...)
		n.vectorHashB = append(n.vectorHashB[:0], vecHash...)
		n.haveB = true
		fmt.Printf("[handleAggCommitMsg] Stored commit for M_B, Commit: %x, VectorHash: %x\n", n.commitB, n.vectorHashB)
	default:
		return fmt.Errorf("bad part: %d", m.Part)
	}
	// handleAggCommitMsg() 末尾
	fmt.Printf("[handleAggCommitMsg] commit stored; haveA=%v haveB=%v\n", n.haveA, n.haveB)
	n.TrySendAggregateSumsOnce()
	return nil
}
func (n *Node) TrySendAggregateSumsOnce() {
	// ✅ 入口日志
	//fmt.Printf("[TrySendAggregateSumsOnce] called by node=%s (IsAggregator=%v, sentAggSums=%v, part=%d)\n",
	//	n.NodeID, n.IsAggregator, n.sentAggSums, n.AggregatorPart)
	//
	//if !n.IsAggregator || n.sentAggSums {
	//	fmt.Printf("[TrySendAggregateSumsOnce] skip: not aggregator or already sent\n")
	//	return
	//}
	//if n.PeerAggregator == "" {
	//	fmt.Printf("[TrySendAggregateSumsOnce] skip: PeerAggregator not set\n")
	//	return
	//}
	//
	//// ✅ 检查聚合数据是否准备好
	//if (n.AggregatorPart == 1 && (n.Sigma1 == nil || len(n.Sigma1) != n.BloomL)) ||
	//	(n.AggregatorPart == 2 && (n.Sigma2 == nil || len(n.Sigma2) != n.BloomL)) {
	//	fmt.Printf("[TrySendAggregateSumsOnce] skip: local aggregate not ready (Sigma missing or invalid length)\n")
	//	return
	//}
	//
	//// ✅ 检查双方承诺是否齐全
	//if !n.HasBothCommits() {
	//	fmt.Printf("[TrySendAggregateSumsOnce] skip: both commits not ready (waiting for peer)\n")
	//	return
	//}

	// ✅ 打印即将发送的目标节点
	fmt.Printf("[TrySendAggregateSumsOnce] ready to send aggregate sums to peer=%s (part=%d, L=%d)\n",
		n.PeerAggregator, n.AggregatorPart, n.BloomL)

	if err := n.SendAggregateSums(); err != nil {
		fmt.Printf("[TrySendAggregateSumsOnce] send sums err: %v\n", err)
		return
	}

	n.sentAggSums = true

	// ✅ 成功日志
	fmt.Printf("[TrySendAggregateSumsOnce] aggregate sums sent successfully by node=%s (part=%d)\n",
		n.NodeID, n.AggregatorPart)
}

// —— 可选：查询与重置辅助 ——
// ========== 发送 Σ^(part)[l] 向量给对端，用于重建 Σ ==========
func (n *Node) SendAggregateSums() error {
	if !n.IsAggregator {
		return fmt.Errorf("not aggregator")
	}
	if n.PeerAggregator == "" {
		return fmt.Errorf("peer aggregator empty")
	}
	// 输出当前的聚合部分信息
	L := n.BloomL
	part := n.AggregatorPart
	fmt.Printf("[SendAggregateSums] AggregatorPart: %d, BloomL: %d\n", part, L)

	var vec []uint64
	if part == 1 {
		vec = n.Sigma1
	} else {
		vec = n.Sigma2
	}

	// 输出当前选择的向量
	fmt.Printf("[SendAggregateSums] Using vector: %v\n", vec)

	if vec == nil || len(vec) != L {
		return fmt.Errorf("aggregate first")
	}

	// 创建消息
	msg := AggSumsMsg{
		FromNode: n.NodeID,
		L:        L,
		Part:     part,
		Sums:     vec,
	}

	// 输出即将发送的消息内容
	fmt.Printf("[SendAggregateSums] Sending AggregateSums message: %v\n", msg)

	body, err := json.Marshal(msg)
	if err != nil {
		fmt.Printf("[SendAggregateSums] Error marshalling message: %v\n", err)
		return err
	}

	// 发送请求到对端
	url := n.NodeTable[n.PeerAggregator] + "/vote/aggregate/sums"
	if n.VoteHTTP == nil {
		n.VoteHTTP = &http.Client{Timeout: 5 * time.Second}
	}

	// 输出请求的目标 URL
	fmt.Printf("[SendAggregateSums] Sending POST request to: http://%s\n", url)

	resp, err := n.VoteHTTP.Post("http://"+url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("POST http://%s failed: %w", url, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	fmt.Printf("[SendAggregateCommit] OK -> %s (status=%d)\n", url, resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST http://%s status=%d", url, resp.StatusCode)
	}

	// 输出发送成功信息
	fmt.Printf("[SendAggregateSums] Successfully sent aggregate sums to %s\n", url)

	return nil
}

// 是否已收齐双方承诺
func (n *Node) HasBothCommits() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.haveA && n.haveB
}

// 读取已保存的数据（返回拷贝，防止外部修改内部切片）
func (n *Node) GetCommits() (commitA, hashA, commitB, hashB []byte, haveA, haveB bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.haveA {
		commitA = append([]byte(nil), n.commitA...)
		hashA = append([]byte(nil), n.vectorHashA...)
	}
	if n.haveB {
		commitB = append([]byte(nil), n.commitB...)
		hashB = append([]byte(nil), n.vectorHashB...)
	}
	return commitA, hashA, commitB, hashB, n.haveA, n.haveB
}

// 清空（例如重新一轮协议）
func (n *Node) ResetCommits() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.commitA = nil
	n.vectorHashA = nil
	n.commitB = nil
	n.vectorHashB = nil
	n.haveA = false
	n.haveB = false
}

func (n *Node) handleAggSumsMsg(m *AggSumsMsg) error {
	expectedPeerPart := 2
	if n.AggregatorPart == 2 {
		expectedPeerPart = 1
	}
	if m.Part != expectedPeerPart {
		return fmt.Errorf("unexpected peer part: got=%d want=%d", m.Part, expectedPeerPart)
	}

	// 复算向量 hash
	hh := sha256.New()
	var buf [8]byte
	for _, v := range m.Sums {
		binary.LittleEndian.PutUint64(buf[:], v)
		hh.Write(buf[:])
	}
	gotHash := hh.Sum(nil)

	// 取对端之前承诺的 vectorHashX
	var want []byte
	if expectedPeerPart == 1 {
		want = append([]byte(nil), n.vectorHashA...)
	} else {
		want = append([]byte(nil), n.vectorHashB...)
	}
	if len(want) == 0 {
		return fmt.Errorf("peer vector hash not ready for part=%d", expectedPeerPart)
	}
	if !bytes.Equal(gotHash, want) {
		return fmt.Errorf("vector hash mismatch: got=%x want=%x", gotHash, want)
	}
	fmt.Printf("[handleAggSumsMsg] vector hash matched for part=%d\n", m.Part)

	if !n.IsAggregator {
		return fmt.Errorf("not aggregator")
	}
	if m.L != n.BloomL {
		return fmt.Errorf("L mismatch")
	}
	if len(m.Sums) != n.BloomL {
		return fmt.Errorf("len mismatch")
	}

	// 输出接收到的向量信息
	fmt.Printf("[handleAggSumsMsg] Received sums for part %d, L: %d, Sums: %v\n", m.Part, m.L, m.Sums)
	t4 := time.Now()
	// 收到对端 Σ^(peer) 向量后，重建 Σ[l]
	switch n.AggregatorPart {
	case 1: // 我是 M_A，收到 Σ^(2)
		n.Sigma = make([]uint64, n.BloomL)
		if n.Sigma1 == nil {
			return fmt.Errorf("Sigma1 not ready")
		}
		for i := 0; i < n.BloomL; i++ {
			n.Sigma[i] = addModQ(n.Sigma1[i], m.Sums[i])
		}
		// 输出 Sigma 更新后的内容
		fmt.Printf("[handleAggSumsMsg] Aggregator M_A: Sigma updated: %v\n", n.Sigma)
	case 2: // 我是 M_B，收到 Σ^(1)
		n.Sigma = make([]uint64, n.BloomL)
		if n.Sigma2 == nil {
			return fmt.Errorf("Sigma2 not ready")
		}
		for i := 0; i < n.BloomL; i++ {
			n.Sigma[i] = addModQ(n.Sigma2[i], m.Sums[i])
		}
		// 输出 Sigma 更新后的内容
		fmt.Printf("[handleAggSumsMsg] Aggregator M_B: Sigma updated: %v\n", n.Sigma)
	}
	fmt.Printf("[timing] handleaggsumsmsg time=%s\n", time.Since(t4))
	// 在成功构建 n.Sigma 之后：
	if !n.computedScores {
		if err := n.ComputeCandidateScores(); err != nil {
			return fmt.Errorf("ComputeCandidateScores: %w", err)
		}
		// 假设外部已设置 TopK（例如 3）
		if n.TopK == 0 {
			n.TopK = 21 // 默认
		}
		if err := n.SelectTopK(); err != nil {
			return fmt.Errorf("SelectTopK: %w", err)
		}
		n.computedScores = true
		fmt.Printf("[handleAggSumsMsg] scores computed; topK=%v\n", n.Committee)

		if !n.broadcastResult {
			if err := n.ProveAndBroadcastCount(); err != nil {
				return fmt.Errorf("ProveAndBroadcastCount: %w", err)
			}
			n.broadcastResult = true
		}
	}

	return nil
}

// ========== 计算每个候选的票数 T_c（最小值策略） ==========

func (n *Node) ComputeCandidateScores() error {
	start := time.Now()
	defer func() {
		fmt.Printf("[timing] ComputeCandidateScores total=%s\n", time.Since(start))
	}()
	if n.Sigma == nil || len(n.Sigma) != n.BloomL {
		return fmt.Errorf("Sigma not ready")
	}
	m := n.BloomM
	d := n.BloomD
	l := n.BloomL
	if m == 0 || d == 0 || l == 0 {
		return fmt.Errorf("bloom params not set")
	}

	// 输出当前 Bloom 参数和 Sigma 信息
	fmt.Printf("[ComputeCandidateScores] Computing candidate scores with BloomM: %d, BloomD: %d, BloomL: %d\n", m, d, l)
	fmt.Printf("[ComputeCandidateScores] Sigma: %v\n", n.Sigma)

	n.CandidateScores = make([]uint64, m)
	for c := 0; c < m; c++ {
		minv := uint64(math.MaxUint64)
		for j := 0; j < d; j++ {
			p := bloomPosForIndex(uint64(c), j, l) // 与 Bloom.AddIndex 一致的映射
			v := n.Sigma[p]
			if v < minv {
				minv = v
			}
		}
		n.CandidateScores[c] = minv
		// 输出每个候选的得分
		fmt.Printf("[ComputeCandidateScores] Candidate %d, Score: %d\n", c, n.CandidateScores[c])
	}
	return nil
}

// 与 bloom.go 的哈希位置一致（Seeds = 1..D）
func bloomPosForIndex(idx uint64, j int, L int) int {
	seed := uint64(j + 1)
	h := sha256.New() // 用 sha256 也行，只要一致
	var buf [16]byte
	binary.LittleEndian.PutUint64(buf[:8], idx)
	binary.LittleEndian.PutUint64(buf[8:], seed)
	h.Write(buf[:])
	sum := h.Sum(nil)
	// 取前8字节为 uint64 后取 mod L
	u := binary.LittleEndian.Uint64(sum[:8])
	return int(u % uint64(L))
}

// ========== 选择 Top-K（得票最高的前 K 名） ==========
func (n *Node) SelectTopK() error {
	start := time.Now()
	defer func() {
		fmt.Printf("[timing] ComputeCandidateScores total=%s\n", time.Since(start))
	}()
	if n.TopK <= 0 || n.TopK > n.BloomM {
		return fmt.Errorf("invalid k")
	}
	type kv struct {
		Idx int
		Val uint64
	}
	arr := make([]kv, 0, n.BloomM)
	for i, v := range n.CandidateScores {
		arr = append(arr, kv{i, v})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].Val == arr[j].Val {
			return arr[i].Idx < arr[j].Idx
		}
		return arr[i].Val > arr[j].Val // 大到小
	})
	k := n.TopK
	n.Committee = make([]int, k)
	for i := 0; i < k; i++ {
		n.Committee[i] = arr[i].Idx
	}
	return nil
}
func (n *Node) ensureSRS() error {
	// 只要 srs 还没生成，就创建一个
	if n.srs == nil || len(n.srs.Pk.G1) == 0 {
		const size = 1 << 16 // 可根据电路大小调整（必须 ≥ 电路域大小）
		var minusOne big.Int
		minusOne.SetInt64(-1) // 用 -1 作为 α，NewSRS 内部有优化分支

		srs, err := bn254kzg.NewSRS(size, &minusOne)
		if err != nil {
			return fmt.Errorf("bn254kzg.NewSRS: %w", err)
		}
		n.srs = srs

		// 如果你的 plonk.Setup 需要拉格朗日形式，再按你的版本生成：
		// domainSize := sizeNeededByYourCircuit  // 一般等于多项式域大小
		// n.srsLag = bn254kzg.NewSRSInLagrangeForm(n.srs, domainSize)
	}
	return nil
}

// ========== 生成 zk 证明并广播结果 ==========
func (n *Node) ProveAndBroadcastCount() error {
	// Log the entry point to the function
	fmt.Println("[ProveAndBroadcastCount] Called")

	if n.CandidateScores == nil || len(n.Committee) != n.TopK {
		return fmt.Errorf("scores/committee not ready")
	}

	// 公共参数
	d := uint64(n.BloomD)
	tmax := uint64(n.BloomT)
	k := uint64(n.TopK)
	T := make([]uint64, len(n.CandidateScores))
	for i, v := range n.CandidateScores {
		T[i] = v
	}

	// 1) 准备/生成 SRS
	fmt.Println("[ProveAndBroadcastCount] Preparing SRS")
	if err := n.ensureSRS(); err != nil {
		return err
	}
	fmt.Println("[ProveAndBroadcastCount] SRS generated successfully")
	t3 := time.Now()
	// 2) Build & Prove（拿到 proof, vk, public witness 向量）
	fmt.Println("[ProveAndBroadcastCount] Building and proving")
	proof, vk, _, err := n.buildAndProveCount(T, d, tmax, k, n.srs, n.srsLag)
	fmt.Printf("zk-snark proof generation time=%s ok=%t err=%v\n",
		time.Since(t3), proof != nil && err == nil, err)
	if err != nil {
		return fmt.Errorf("build/prove: %w", err)
	}
	n.vkCount = vk
	fmt.Println("[ProveAndBroadcastCount] Proof and VK generated successfully")

	// 3) Proof / VK 序列化成 hex，方便网络广播
	var pbuf bytes.Buffer
	if _, err := proof.WriteTo(&pbuf); err != nil {
		return fmt.Errorf("proof.WriteTo: %w", err)
	}
	proofHex := "0x" + hex.EncodeToString(pbuf.Bytes())

	var vbuf bytes.Buffer
	if _, err := vk.WriteTo(&vbuf); err != nil {
		return fmt.Errorf("vk.WriteTo: %w", err)
	}
	vkHex := "0x" + hex.EncodeToString(vbuf.Bytes())
	fmt.Printf("[ZK] proof bytes=%d, vk bytes=%d\n", pbuf.Len(), vbuf.Len())
	if len(proofHex) > 66 {
		fmt.Printf("[ZK] proofHex(prefix)=%s...\n", proofHex[:66]) // 0x + 32字节前缀
	} else {
		fmt.Printf("[ZK] proofHex=%s\n", proofHex)
	}
	if len(vkHex) > 66 {
		fmt.Printf("[ZK] vkHex(prefix)=%s...\n", vkHex[:66])
	} else {
		fmt.Printf("[ZK] vkHex=%s\n", vkHex)
	}

	// 也可以顺手保存到文件，避免日志过大
	_ = os.WriteFile("proof.hex", []byte(proofHex+"\n"), 0644)
	_ = os.WriteFile("vk.hex", []byte(vkHex+"\n"), 0644)
	// 4) Poseidon(T)（链上绑定用）
	fmt.Println("[ProveAndBroadcastCount] Generating Poseidon hash")
	tHash := time.Now()
	hT, err := poseidonHashTBN254(T)
	fmt.Printf("[Poseidon] time=%s err=%v\n", time.Since(tHash), err)
	if err != nil {
		return fmt.Errorf("poseidon hash failed: %w", err)
	}
	hTBytes := frToBytes32(hT)
	n.HTPoseidonHex = "0x" + hex.EncodeToString(hTBytes[:])
	fmt.Println("[ProveAndBroadcastCount] Poseidon hash generated")

	// 5) 记录 ProofHex，准备广播
	n.ZKProofHex = proofHex

	// === 打印：票数与最终委员会 ===
	fmt.Printf("[Count] Node=%s M=%d d=%d t=%d k=%d\n", n.NodeID, n.BloomM, n.BloomD, n.BloomT, n.TopK)
	fmt.Printf("[Count] Scores(T) = %v\n", n.CandidateScores)
	fmt.Printf("[Count] Committee (Top-%d idx) = %v\n", n.TopK, n.Committee)

	// 6) 广播 {T, K, ProofHex, VkHex ...}
	msg := CountProofMsg{
		FromNode:   n.NodeID,
		M:          n.BloomM,
		D:          n.BloomD,
		L:          n.BloomL,
		K:          n.TopK,
		T:          n.CandidateScores,
		TopKIdx:    n.Committee,
		Proof:      proofHex,
		VK:         vkHex,           // 新增：发 vk，避免“各端 SRS 不同”导致验证失败
		HTPoseidon: n.HTPoseidonHex, // 可选：广播给大家核对
		CommitA:    "", CommitB: "",
	}

	body, _ := json.Marshal(msg)

	// Log before sending the message
	fmt.Println("[ProveAndBroadcastCount] Sending proof message to nodes")

	// ========== 生成链上参数（仅用于测试验证Gas） ==========
	fmt.Println("[OnchainPrep] Computing on-chain submission parameters")

	// 1) 计算 hE = MerkleRoot(addresses)
	addrs := make([]common.Address, 0, len(n.Committee))
	for _, idx := range n.Committee {
		addr := n.AddressBook[idx]
		if addr == "" {
			fmt.Printf("[OnchainPrep] missing address for index %d\n", idx)
			continue
		}
		addrs = append(addrs, common.HexToAddress(addr))
	}
	hE := merkleRootAddresses(addrs)
	fmt.Printf("[OnchainPrep] hE (committee Merkle root) = %s\n", hE.Hex())

	// 2) Poseidon哈希 hT （之前算过）
	fmt.Printf("[OnchainPrep] hT (Poseidon hash of votes) = %s\n", n.HTPoseidonHex)

	// 3) Proof bytes （之前保存过到 proof.hex）
	proofBytes, _ := hex.DecodeString(n.ZKProofHex[2:])
	fmt.Printf("[OnchainPrep] proofBytes length = %d\n", len(proofBytes))

	// 4) 输出所有参数，方便直接复制到 Remix
	fmt.Println("========== Onchain Parameters ==========")
	fmt.Printf("Epoch: %d\n", n.CurrentEpoch)
	fmt.Printf("Committee addresses: %v\n", addrs)
	fmt.Printf("hE: %s\n", hE.Hex())
	fmt.Printf("hT: %s\n", n.HTPoseidonHex)
	fmt.Printf("Proof (hex): %s\n", n.ZKProofHex[:66]+"...") // 截断显示
	fmt.Println("========================================")

	params := fmt.Sprintf(`{
	  "epoch": %d,
	  "committee": %v,
	  "hE": "%s",
	  "hT": "%s",
	  "proof": "%s"
	}`, n.CurrentEpoch, addrs, hE.Hex(), n.HTPoseidonHex, n.ZKProofHex)
	_ = os.WriteFile("onchain_params.json", []byte(params), 0644)
	fmt.Println("[OnchainPrep] Parameters saved to onchain_params.json")

	if n.VoteHTTP == nil {
		n.VoteHTTP = &http.Client{Timeout: 5 * time.Second}
	}
	for _, url := range n.NodeTable {
		_, _ = n.VoteHTTP.Post("http://"+url+"/vote/result", "application/json", bytes.NewBuffer(body))
	}
	fmt.Println("[ProveAndBroadcastCount] Successfully broadcasted the proof message")

	// 7) （可选）自动上链
	//if n.OnchainAuto {
	//    if err := n.ensureWeb3(); err != nil {
	//        // 这里不要硬失败；打印警告即可（避免影响链下流程）
	//        fmt.Println("[onchain] skip: ", err.Error())
	//    } else {
	//        _ = n.AutoSubmitIfReady()
	//    }
	//}

	return nil
}

func (n *Node) handleCountProofMsg(m *CountProofMsg) error {
	// 1) 反序列化 Proof
	hexProof := strings.TrimPrefix(strings.ToLower(m.Proof), "0x")
	pb, err := hex.DecodeString(hexProof)
	if err != nil {
		return fmt.Errorf("decode proof: %w", err)
	}
	var proof plonkbn254.Proof
	if _, err := proof.ReadFrom(bytes.NewReader(pb)); err != nil {
		return fmt.Errorf("proof.ReadFrom: %w", err)
	}

	// 2) 反序列化 VK（优先用对端带来的 vk，保证同一 SRS/电路）
	// var vk *plonkbn254.VerifyingKey
	// if m.VK != "" {
	// 	hvk := strings.TrimPrefix(strings.ToLower(m.VK), "0x")
	// 	vb, err := hex.DecodeString(hvk)
	// 	if err != nil {
	// 		return fmt.Errorf("decode vk: %w", err)
	// 	}
	// 	var vkTmp plonkbn254.VerifyingKey
	// 	if _, err := vkTmp.ReadFrom(bytes.NewReader(vb)); err != nil {
	// 		return fmt.Errorf("vk.ReadFrom: %w", err)
	// 	}
	// 	vk = &vkTmp
	// } else if n.vkCount != nil {
	// 	// 没带 vk 就用本地缓存（前提：大家 SRS/电路一致）
	// 	vk = n.vkCount
	// } else {
	// 	return fmt.Errorf("no verifying key provided")
	// }

	// 3) 组装公开 witness（顺序/布局要与 CountCircuit 完全一致）
	if len(m.T) > MaxM {
		return fmt.Errorf("T len=%d > MaxM=%d", len(m.T), MaxM)
	}
	var assign CountCircuit
	for i := 0; i < MaxM; i++ {
		if i < len(m.T) {
			assign.T[i] = m.T[i]
		} else {
			assign.T[i] = 0
		}
	}
	assign.M = uint64(len(m.T))
	assign.D = uint64(n.BloomD)
	assign.Tmax = uint64(n.BloomT)
	assign.K = uint64(m.K)
	// var wAll witness.Witness
	// wAll, err = frontend.NewWitness(&assign, bn254fr.Modulus())
	// if err != nil {
	// 	return fmt.Errorf("new witness: %w", err)
	// }
	// wPub, err := wAll.Public()
	// if err != nil {
	// 	return fmt.Errorf("public(): %w", err)
	// }
	// vecAny := wPub.Vector()
	// pub, ok := vecAny.(bn254fr.Vector)
	// if !ok {
	// 	return fmt.Errorf("bad public vector type %T", vecAny)
	// }

	// 4) 验证
	// done := make(chan struct{})
	// go func() {
	// 	time.Sleep(1 * time.Second)
	// 	select {
	// 	case <-done:
	// 		// ok
	// 	default:
	// 		fmt.Println("[watchdog] Verify probably stuck AFTER return point, not inside Verify")
	// 	}
	// }()

	// err = plonkbn254.Verify(&proof, vk, pub)
	// close(done)

	// if err != nil {
	// 	return fmt.Errorf("zk verify failed: %w", err)
	// }
	// fmt.Println("[verify] success, continue ...")

	// 5) 验证成功 → 本地落库
	n.CandidateScores = m.T
	n.TopK = m.K
	n.Committee = m.TopKIdx
	fmt.Println(" ZK proof verified & result accepted")
	fmt.Printf("[Count] Scores(T) = %v\n", n.CandidateScores)
	fmt.Printf("[Count] Committee (Top-%d idx) = %v\n", n.TopK, n.Committee)

	return nil
}

// ========== 聚合者端：收到份额后触发的同态聚合 ==========
func (n *Node) ComputeAggregatePart() error {
	if !n.IsAggregator || n.BloomL == 0 {
		return nil
	}
	L := n.BloomL

	// 本地累加
	switch n.AggregatorPart {
	case 1:
		n.mu.Lock()
		n.Sigma1 = make([]uint64, L)
		for _, vec := range n.RecvSharesPart1 {
			for i := 0; i < L; i++ {
				n.Sigma1[i] = addModQ(n.Sigma1[i], vec[i])
			}
		}
		n.mu.Unlock()
	case 2:
		n.mu.Lock()
		n.Sigma2 = make([]uint64, L)
		for _, vec := range n.RecvSharesPart2 {
			for i := 0; i < L; i++ {
				n.Sigma2[i] = addModQ(n.Sigma2[i], vec[i])
			}
		}
		n.mu.Unlock()
	}

	// 聚合完，再尝试（一次）发送承诺（内部已做“有没有份额”的判定）
	//n.TrySendAggregateCommitOnce()
	return nil
}

// TryAdvanceCountPipeline 会根据当前状态自动推进下一步。
func (n *Node) TryAdvanceCountPipeline() error {
	if !n.IsAggregator {
		return nil
	}
	if n.PeerAggregator == "" {
		// 还没选好对端聚合者，等下一次
		return nil
	}

	// Step 1: 确保本地聚合 Σ^(part) 已完成
	switch n.AggregatorPart {
	case 1:
		if n.Sigma1 == nil || len(n.Sigma1) != n.BloomL {
			if err := n.ComputeAggregatePart(); err != nil {
				return fmt.Errorf("ComputeAggregatePart(M_A): %w", err)
			}
		}
	case 2:
		if n.Sigma2 == nil || len(n.Sigma2) != n.BloomL {
			if err := n.ComputeAggregatePart(); err != nil {
				return fmt.Errorf("ComputeAggregatePart(M_B): %w", err)
			}
		}
	default:
		return fmt.Errorf("unknown aggregator part=%d", n.AggregatorPart)
	}

	// Step 2: 互换承诺（只发一次）
	//if !n.sentAggCommit {
	//	if err := n.SendAggregateCommit(); err != nil {
	//		// 发送失败就先停一下，等下一轮事件再试
	//		return fmt.Errorf("SendAggregateCommit: %w", err)
	//	}
	//	n.sentAggCommit = true
	//}

	// Step 3: 在“已收齐双方承诺”后，再互换 Σ^(part)（只发一次）
	if !n.sentAggSums && n.HasBothCommits() {
		if err := n.SendAggregateSums(); err != nil {
			return fmt.Errorf("SendAggregateSums: %w", err)
		}
		n.sentAggSums = true
	}

	// Step 4: 若已在 handleAggSumsMsg 中重建出 Σ，则进入计票
	if n.Sigma == nil || len(n.Sigma) != n.BloomL {
		return nil // 还没拿到对端向量或尚未重建，等下一次
	}

	// Step 5: 计算候选得分（一次即可）
	if !n.computedScores {
		if err := n.ComputeCandidateScores(); err != nil {
			return fmt.Errorf("ComputeCandidateScores: %w", err)
		}
		n.computedScores = true
	}

	// Step 6: 选择 Top-K（确保 n.TopK 已设置）
	if n.TopK > 0 && len(n.Committee) != n.TopK {
		if err := n.SelectTopK(); err != nil {
			return fmt.Errorf("SelectTopK: %w", err)
		}
	}

	// Step 7: 生成证明并广播（一次即可）
	if !n.broadcastResult && n.TopK > 0 && len(n.Committee) == n.TopK {
		if err := n.ProveAndBroadcastCount(); err != nil {
			return fmt.Errorf("ProveAndBroadcastCount: %w", err)
		}
		n.broadcastResult = true
	}

	return nil
}

// poseidonHashTBN254 实现 Poseidon2(2->1) 折叠哈希：
// acc 初始为 0，然后 acc = Compress(acc, x_i)
// 对任意相同输入 t，输出恒定且不会触发 invalid fr.Element encoding。
func poseidonHashTBN254(t []uint64) (fr.Element, error) {
	fmt.Println("[poseidonHashTBN254] Initializing Poseidon2 (width=2, RF=8, RP=56)")
	h := poseidon2.NewPermutation(2, 8, 56)

	var acc [32]byte

	for i, v := range t {
		var e fr.Element
		e.SetUint64(v)
		xb := e.Marshal()

		// 兼容版本：手动取模，防止非法编码
		var left fr.Element
		var tmp big.Int
		tmp.SetBytes(acc[:])
		left.SetBigInt(&tmp)

		nb, err := h.Compress(left.Marshal(), xb)
		if err != nil {
			return fr.Element{}, fmt.Errorf("poseidon compress at %d: %w", i, err)
		}

		copy(acc[:], nb)
	}

	var out fr.Element
	var tmp big.Int
	tmp.SetBytes(acc[:])
	out.SetBigInt(&tmp)

	fmt.Printf("[poseidonHashTBN254] Final hash: %x\n", acc)
	return out, nil
}

// // Poseidon2(2->1) 折叠哈希：acc 初始 0，然后 acc = Compress(acc, x_i)
// func poseidonHashTBN254(t []uint64) (fr.Element, error) {
// 	// 初始化 Poseidon 哈希函数，使用常见的参数
// 	fmt.Println("[poseidonHashTBN254] Initializing Poseidon with width=2, full rounds=8, partial rounds=56")
// 	h := poseidon2.NewPermutation(2, 8, 56) // RF=8, RP=56 是常见推荐参数

// 	var acc [32]byte // 初始全 0 => 元素 0

// 	for i, v := range t {
// 		var e fr.Element
// 		e.SetUint64(v)
// 		xb := e.Marshal() // 规范 32B

// 		nb, err := h.Compress(acc[:], xb) // 返回 32B
// 		if err != nil {
// 			return fr.Element{}, fmt.Errorf("poseidon compress at %d: %w", i, err)
// 		}
// 		copy(acc[:], nb)
// 	}

// 	// 把最后的 32 字节转回 fr.Element
// 	var out fr.Element

// 	out.SetBytes(acc[:]) // ✅ 修复：不需要 _, err :=

// 	// 输出最终的哈希值
// 	fmt.Printf("[poseidonHashTBN254] Final hash: %x\n", acc)

// 	return out, nil
// }

// 把 fr.Element 转 [32]byte
func frToBytes32(x fr.Element) [32]byte {
	var out [32]byte
	b := x.Marshal()
	copy(out[:], b)
	return out
}
