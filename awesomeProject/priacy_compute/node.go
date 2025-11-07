package priacy_compute

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254kzg "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	plonkbn254 "github.com/consensys/gnark/backend/plonk/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type VRFResult struct {
	NodeID  string  `json:"node_id"`
	PKHex   string  `json:"pk_hex"` // 广播时带上公钥，便于对端验证
	T       uint64  `json:"t"`
	Context string  `json:"context"`
	Proof   []byte  `json:"proof"` // π
	Value   float64 `json:"value"` // 本地 value（对端会自行从π计算校验）
}

type VRFRecord struct {
	NodeID   string
	PK       ed25519.PublicKey
	T        uint64
	Context  string
	Proof    []byte
	Value    float64
	Verified bool
	Chosen   bool
	RecvTime time.Time
}
type View struct {
	ID      int
	Primary string
}

// 发送队列单元（示意）
type SendMsg_go struct {
	url string
	msg []byte
}

type Node struct {
	mu           sync.Mutex
	roundStarted bool
	NodeID       string
	NodeTable    map[string]string

	MsgEntrance chan interface{}
	MsgDelivery chan interface{}
	MsgSend_go  chan SendMsg_go
	VoteSend_go chan SendMsg_go
	View        *View
	// —— 新增：vrf 运行参数 ——
	Tau         float64 // 阈值 τ = |S|/|N|
	VRF_T       uint64  // 触发用 t（也可放在共识上下文）
	VRF_Context string  // 上下文（epoch|height 等），需全网一致
	SelfPK      ed25519.PublicKey
	SelfSK      ed25519.PrivateKey

	// —— 新增：vrf 状态 ——
	VRFValue     float64
	VRFProof     []byte
	VRFChosen    bool
	CandidateSet map[string]*VRFRecord // key: NodeID
	hash         []byte

	// VRF选举 ——
	AggEpoch    uint64
	AggRound    uint64
	AggContext  string
	aggDeadline time.Time

	// 投票参数
	BloomM   int
	BloomT   int
	BloomEps float64
	BloomL   int
	BloomD   int
	VoteHTTP *http.Client

	// 二次聚合者
	Aggregators [2]string
	aggBox      map[string]uint8 // 收到的 tail 收集

	// ====== 计票阶段需要的聚合者状态 ======
	RecvSharesPart1 map[string][]uint64 // 仅在自己是 M_A 时使用
	RecvSharesPart2 map[string][]uint64 // 仅在自己是 M_B 时使用

	Sigma1 []uint64 // M_A 聚合结果 Σ^(1)[l]
	Sigma2 []uint64 // M_B 聚合结果 Σ^(2)[l]
	Sigma  []uint64 // 重建后的 Σ[l] = Σ1[l] + Σ2[l] (mod q)

	CandidateScores []uint64 // T_c
	TopK            int      // 选 k 名
	Committee       []int    // 最终委员会索引集合（长度 k）

	// 标识与对端信息
	IsAggregator   bool   // 是否为当前轮被选中的聚合者
	AggregatorPart int    // 1 表示 M_A, 2 表示 M_B
	PeerAggregator string // 对端聚合者 NodeID

	// 存储对端 M_A / M_B 的承诺与哈希
	commitA     []byte
	vectorHashA []byte
	commitB     []byte
	vectorHashB []byte

	// 是否已收到（用于防重复）
	haveA bool
	haveB bool

	// 可选：严格长度校验（=0 表示不校验）
	ExpectedCommitLen int // 例如 32/48/64 字节，视你的承诺编码而定
	ExpectedHashLen   int // 例如 32 字节（SHA-256）

	// 计票阶段执行标志（避免重复）
	sentAggCommit   bool
	sentAggSums     bool
	computedScores  bool
	broadcastResult bool

	wg         sync.WaitGroup // 用于同步等待所有份额提交
	totalNodes int            // 用来存储总节点数

	// 聚合触发相关
	aggRoundStarted bool          // 是否已启动
	aggTimer        *time.Timer   // 时间窗口计时器
	AggWindow       time.Duration // 时间窗口（例如 1*time.Minute）
	MinVotes        int           // 可选：提前触发的最小份额数（如 2f+1），0 表示无需最小门限
	Window          time.Duration
	web3            *Web3Handle
	// 自动上链
	AddressBook       map[int]string // 索引 -> 0x地址（字符串保存，便于配置）
	OnchainAuto       bool           // 自动提交开关
	OnchainSubmitted  bool           // 已提交标志（避免重复提交）
	CurrentEpoch      uint64         // 当前 epoch（由路由设置或你内部计算）
	CurrentRound      uint64
	ZKProofHex        string    // 最近生成的 zk 证明 hex（用于上链）
	HTPoseidonHex     string    //保存 Poseidon 哈希的 hex
	AddressBookPath   string    // 默认 "addresses.csv"
	OnchainLastTxHash string    // 最近一次 submitResult 的 tx hash
	OnchainLastSubmit time.Time // 最近一次提交时间
	//PrivateKey        ed25519.PrivateKey
	//PublicKey         ed25519.PublicKey
	srs     *bn254kzg.SRS            // KZG SRS（monomial form）
	srsLag  bn254kzg.SRS             // Lagrange form（有的版本需要；可由 srs 派生）
	vkCount *plonkbn254.VerifyingKey // 验证键缓存（当前计票电路）

	cachedCfg     *OnchainConfig // 缓存最近一次 /onchain/config 的配置
	web3Once      sync.Once      // 可选：防止多处并发重复初始化
	sprCount      *cs.SparseR1CS
	pkCount       *plonkbn254.ProvingKey
	SetupCacheDir string
	setupOnce     sync.Once
}

// ---- 序列化/反序列化 ----
func (n *Node) saveSetupToDisk(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if n.sprCount != nil {
		f, _ := os.Create(filepath.Join(dir, "count.spr"))
		defer f.Close()
		if _, err := n.sprCount.WriteTo(f); err != nil {
			return err
		}
	}
	if n.pkCount != nil {
		f, _ := os.Create(filepath.Join(dir, "count.pk"))
		defer f.Close()
		if _, err := n.pkCount.WriteTo(f); err != nil {
			return err
		}
	}
	if n.vkCount != nil {
		f, _ := os.Create(filepath.Join(dir, "count.vk"))
		defer f.Close()
		if _, err := n.vkCount.WriteTo(f); err != nil {
			return err
		}
	}
	return nil
}

func (n *Node) loadSetupFromDisk(dir string) error {
	// spr
	if f, err := os.Open(filepath.Join(dir, "count.spr")); err == nil {
		defer f.Close()
		var spr cs.SparseR1CS
		if _, err := spr.ReadFrom(f); err != nil {
			return err
		}
		n.sprCount = &spr
	}
	// pk
	if f, err := os.Open(filepath.Join(dir, "count.pk")); err == nil {
		defer f.Close()
		var pk plonkbn254.ProvingKey
		if _, err := pk.ReadFrom(f); err != nil {
			return err
		}
		n.pkCount = &pk
	}
	// vk
	if f, err := os.Open(filepath.Join(dir, "count.vk")); err == nil {
		defer f.Close()
		var vk plonkbn254.VerifyingKey
		if _, err := vk.ReadFrom(f); err != nil {
			return err
		}
		n.vkCount = &vk
	}
	if n.sprCount == nil || n.pkCount == nil || n.vkCount == nil {
		return fmt.Errorf("incomplete setup cache")
	}
	return nil
}
func circuitShapeHash() string {
	// 用 MaxM 等常量 + 源码版本拼个字符串做 hash；这里简单示意：
	h := sha256.Sum256([]byte(fmt.Sprintf("CountCircuit-MaxM=%d", MaxM)))
	return hex.EncodeToString(h[:8])
}
func (n *Node) ensureSetupCount() error {
	var retErr error
	n.setupOnce.Do(func() {
		cacheDir := n.SetupCacheDir
		if cacheDir != "" {
			cacheDir = filepath.Join(cacheDir, "count-"+circuitShapeHash())
			if err := n.loadSetupFromDisk(cacheDir); err == nil {
				fmt.Println("[setup] loaded from disk cache:", cacheDir)
				return
			}
		}

		tAll := time.Now()
		var circuit CountCircuit
		ccs, err := frontend.Compile(bn254fr.Modulus(), r1cs.NewBuilder, &circuit)
		if err != nil {
			retErr = err
			return
		}
		spr, ok := ccs.(*cs.SparseR1CS)
		if !ok {
			retErr = fmt.Errorf("expected *cs.SparseR1CS, got %T", ccs)
			return
		}
		n.sprCount = spr

		pk, vk, err := plonkbn254.Setup(n.sprCount, *n.srs, n.srsLag)
		if err != nil {
			retErr = err
			return
		}
		n.pkCount, n.vkCount = pk, vk
		fmt.Printf("[setup] compile+setup took %s\n", time.Since(tAll))

		if n.SetupCacheDir != "" {
			_ = n.saveSetupToDisk(cacheDir)
		}
	})
	return retErr
}

func NewNode(nodeID string) *Node {
	// 读 NodeTable
	a, err := ioutil.ReadFile("nodetable1.csv")
	if err != nil {
		fmt.Print(err)
	}
	NodeTable := map[string]string{}
	if err := json.Unmarshal(a, &NodeTable); err != nil {
		panic(err)
	}
	viewID := 1 // temporary
	node := &Node{
		NodeID:    nodeID,
		NodeTable: NodeTable,

		MsgEntrance: make(chan interface{}, 2048),
		MsgDelivery: make(chan interface{}, 2048),
		MsgSend_go:  make(chan SendMsg_go, 1),
		VoteSend_go: make(chan SendMsg_go, 10),
		View: &View{
			ID:      viewID,
			Primary: "1",
		},
		// vrf 相关默认值（你可从合约/配置中心动态刷新）
		Tau:          0.3,
		VRF_T:        100,
		VRF_Context:  "epoch1:block100",
		CandidateSet: make(map[string]*VRFRecord),

		// 投票参数（初始为0，等 /params/bloom 路由下发后再计算 L/D）
		BloomM:   0,
		BloomT:   0,
		BloomEps: 0,
		BloomL:   0,
		BloomD:   0,
		VoteHTTP: &http.Client{},

		// 二次聚合者
		Aggregators: [2]string{"", ""},
		aggBox:      make(map[string]uint8),

		RecvSharesPart1:   make(map[string][]uint64),
		RecvSharesPart2:   make(map[string][]uint64),
		Sigma1:            nil,
		Sigma2:            nil,
		Sigma:             nil,
		CandidateScores:   nil,
		TopK:              0,
		Committee:         nil,
		IsAggregator:      false,
		AggregatorPart:    0,
		PeerAggregator:    "",
		sentAggCommit:     false,
		sentAggSums:       false,
		computedScores:    false,
		broadcastResult:   false,
		AddressBook:       make(map[int]string),
		OnchainAuto:       false,
		OnchainSubmitted:  false,
		CurrentEpoch:      0,
		ZKProofHex:        "",
		AddressBookPath:   "addresses.csv",
		OnchainLastTxHash: "",
		OnchainLastSubmit: time.Time{},
	}

	// —— vrf 密钥初始化：若 nodeTsk 是 32 字节十六进制，则用它作为种子；否则随机 ——
	pk, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	node.SelfPK, node.SelfSK = pk, sk

	// 启动消息分发/解析/发送协程（保持你的模式）
	go node.dispatchMsg()
	go node.resolveMsg()
	go node.sendMsg()

	return node
}

//	func (n *Node) startAggRound(epoch, round uint64, context string, window time.Duration) {
//		n.resetRoundState()
//
//		n.AggEpoch = epoch
//		n.AggRound = round
//		n.AggContext = context
//		n.aggBox = make(map[string]uint8)
//		n.aggDeadline = time.Now().Add(window)
//
//		// 调用 RunAggVRFBroadcast 开始 VRF 计算和广播
//		err := n.RunAggVRFBroadcast(context)
//		if err != nil {
//			fmt.Printf("Error in RunAggVRFBroadcast: %v\n", err)
//			return
//		}
//		// === 新增：到时再聚合一次（防止只收到部分份额时多次跑）===
//		go func(deadline time.Time) {
//			d := time.Until(deadline)
//			if d < 0 {
//				d = 0
//			}
//			<-time.After(d)
//			if !n.IsAggregator {
//				return
//			}
//
//			// 非阻塞地尝试拿锁，避免和其它地方的聚合并发死锁
//			if !n.mu.TryLock() {
//				fmt.Printf("[AggDeadline] skip: lock busy\n")
//				return
//			}
//			haveShare := (n.AggregatorPart == 1 && len(n.RecvSharesPart1) > 0) ||
//				(n.AggregatorPart == 2 && len(n.RecvSharesPart2) > 0)
//			n.mu.Unlock()
//
//			if !haveShare {
//				fmt.Printf("[AggDeadline] skip: no shares yet\n")
//				return
//			}
//			fmt.Printf("[AggDeadline] trigger final aggregate: self=%s part=%d\n", n.NodeID, n.AggregatorPart)
//			if err := n.ComputeAggregatePart(); err != nil {
//				fmt.Printf("[AggDeadline] ComputeAggregatePart err: %v\n", err)
//			}
//		}(n.aggDeadline)
//
// }
// 只在“确实是新一轮”的时候才 reset；否则忽略
func (n *Node) startAggRound(epoch, round uint64, context string, window time.Duration) {
	n.mu.Lock()
	//sameRound := n.roundStarted &&
	//	n.AggEpoch == epoch &&
	//	n.AggRound == round &&
	//	n.AggContext == context
	//if sameRound {
	//	n.mu.Unlock()
	//	fmt.Printf("[startAggRound] duplicate start ignored: epoch=%d round=%d ctx=%s\n", epoch, round, context)
	//	return
	//}

	// 新一轮：先清状态，再写入新的 round 标识
	//n.resetRoundStateLocked() // 版本：锁内调用的 reset
	n.AggEpoch = epoch
	n.AggRound = round
	n.AggContext = context
	n.roundStarted = true

	// 计算截止时间
	n.aggBox = make(map[string]uint8)
	n.aggDeadline = time.Now().Add(window)
	n.mu.Unlock()

	// 锁外做耗时工作
	//if err := n.RunAggVRFBroadcast(context); err != nil {
	//	fmt.Printf("Error in RunAggVRFBroadcast: %v\n", err)
	//	return
	//}

	//n.addTestShares()

	go func(deadline time.Time) {
		d := time.Until(deadline)
		if d < 0 {
			d = 0
		}
		<-time.After(d)

		// 首先安全地抓一份快照
		n.mu.Lock()
		isAgg := n.IsAggregator
		part := n.AggregatorPart
		haveShare := (part == 1 && len(n.RecvSharesPart1) > 0) ||
			(part == 2 && len(n.RecvSharesPart2) > 0)
		n.mu.Unlock()

		if !isAgg {
			return
		}
		if !haveShare {
			fmt.Printf("[AggDeadline] skip: no shares yet\n")
			return
		}

		// TrySendAggregateCommitOnce 做的事本身好像会再拿锁，
		// 所以这里可以不用 TryLock 5 次那段复杂逻辑了
		fmt.Printf("[AggDeadline] trigger final aggregate: self=%s part=%d (final)\n",
			n.NodeID, part)
		n.TrySendAggregateCommitOnce()
	}(n.aggDeadline)

}

// 手动向 RecvSharesPart1 和 RecvSharesPart2 中添加数据
//
//	func (n *Node) addTestShares() {
//		// 手动向 RecvSharesPart1 添加数据，长度应为 L=29
//		n.mu.Lock()
//		if n.RecvSharesPart1 == nil {
//			n.RecvSharesPart1 = make(map[string][]uint64)
//		}
//		// 填充数据，使其长度为 29
//		n.RecvSharesPart1["test_node_1"] = make([]uint64, 29) // 创建一个长度为 29 的切片
//		for i := 0; i < 29; i++ {
//			n.RecvSharesPart1["test_node_1"][i] = uint64(i + 1) // 填充一些数据
//		}
//		n.mu.Unlock()
//
//		// 手动向 RecvSharesPart2 添加数据，长度应为 L=29
//		n.mu.Lock()
//		if n.RecvSharesPart2 == nil {
//			n.RecvSharesPart2 = make(map[string][]uint64)
//		}
//		// 填充数据，使其长度为 29
//		n.RecvSharesPart2["test_node_2"] = make([]uint64, 29) // 创建一个长度为 29 的切片
//		for i := 0; i < 29; i++ {
//			n.RecvSharesPart2["test_node_2"][i] = uint64(i + 1) // 填充一些数据
//		}
//		n.mu.Unlock()
//
//		// 输出测试数据，确保数据已添加
//		fmt.Printf("Test data added to RecvSharesPart1 and RecvSharesPart2\n")
//	}
func (n *Node) addTestShares() {
	n.mu.Lock()
	defer n.mu.Unlock()

	L := 29         // Bloom filter length
	q := uint64(97) // 模数（仅示例，可换为系统使用的 q）

	// 模拟布隆过滤器（随机 0/1）
	BFi := make([]uint64, L)
	for i := 0; i < L; i++ {
		if rand.Float64() < 0.4 { // 约40%的比特为1
			BFi[i] = 1
		} else {
			BFi[i] = 0
		}
	}

	// 初始化 RecvSharesPart1 和 RecvSharesPart2
	if n.RecvSharesPart1 == nil {
		n.RecvSharesPart1 = make(map[string][]uint64)
	}
	if n.RecvSharesPart2 == nil {
		n.RecvSharesPart2 = make(map[string][]uint64)
	}

	part1 := make([]uint64, L)
	part2 := make([]uint64, L)

	for l := 0; l < L; l++ {
		r := uint64(rand.Intn(int(q))) // 随机 r_l
		part1[l] = r
		part2[l] = (BFi[l] + q - r) % q // 保证 s1+s2 ≡ BF[l] (mod q)
	}

	n.RecvSharesPart1["test_node_1"] = part1
	n.RecvSharesPart2["test_node_2"] = part2

	fmt.Printf("[addTestShares] Added test shares for Bloom filter: %v\n", BFi)
	fmt.Printf("[addTestShares] s^(1) = %v\n", part1)
	fmt.Printf("[addTestShares] s^(2) = %v\n", part2)
}

func (n *Node) isCandidate(nodeID string) bool {
	rec, ok := n.CandidateSet[nodeID]
	return ok && rec.Verified && rec.Chosen
}

//func (n *Node) resetRoundState() {
//	n.mu.Lock()
//	defer n.mu.Unlock()
//	n.RecvSharesPart1 = make(map[string][]uint64)
//	n.RecvSharesPart2 = make(map[string][]uint64)
//
//	n.Sigma1 = nil
//	n.Sigma2 = nil
//	n.sentAggCommit = false
//}

// 分发：把入口消息转发到 MsgDelivery
func (node *Node) dispatchMsg() {
	for {
		select {
		case msg := <-node.MsgEntrance:
			fmt.Println("Received message in dispatch:", msg)
			fmt.Printf("[dispatchMsg] Forwarding message: %T\n", msg)
			_ = node.routeMsg(msg)
		}
	}
}

func (node *Node) routeMsg(msg interface{}) []error {
	fmt.Printf("Routing message of type: %T\n", msg)
	// 加日志打印信息，确认消息是否顺利进入 MsgDelivery
	select {
	case node.MsgDelivery <- msg:
		fmt.Printf("[routeMsg] Message of type %T forwarded to MsgDelivery\n", msg)
	default:
		fmt.Printf("[routeMsg] Failed to forward message of type %T to MsgDelivery\n", msg)
	}
	return nil
}

// 发送协程（保持你的风格）
var httpClient *http.Client

func (node *Node) sendMsg() {
	httpClient = &http.Client{}
	httpClient.Transport = &http.Transport{MaxIdleConnsPerHost: 1000}
	for {
		select {
		case sendmsg := <-node.VoteSend_go:
			buff := bytes.NewBuffer(sendmsg.msg)
			_, _ = httpClient.Post("http://"+sendmsg.url, "application/json", buff)
		default:
			select {
			case sendmsg := <-node.MsgSend_go:
				buff := bytes.NewBuffer(sendmsg.msg)
				_, _ = httpClient.Post("http://"+sendmsg.url, "application/json", buff)
			default:
				time.Sleep(time.Microsecond)
			}
			time.Sleep(time.Microsecond)
		}
	}
}

// 按类型路由（UnderBlock / VRFResult）
func (node *Node) resolveMsg() {
	for {
		msg := <-node.MsgDelivery
		fmt.Println("Resolving message:", msg)
		switch m := msg.(type) {
		case *VRFResult:
			_ = node.resolveVRFResult(m)
		case *TriggerVRFMsg:
			_ = node.RunRandomElectAndBroadcast()
		// —— 投票参数设置（未用） ——
		case *BloomParamsMsg:
			_ = node.handleBloomParams(m)

		// —— 本地批准投票(未用) ——
		case *LocalApproveVoteMsg:
			_ = node.handleLocalApproveVote(m)

		// —— 聚合者收到份额 ——
		case *ReceivedShareMsg:
			node.wg.Add(1)
			fmt.Printf("[ReceivedShareMsg] Received share from node: %s\n", m.Pkt.FromNode)
			_ = node.handleReceivedShare(m)
			//go func() {
			//	err := node.TryAdvanceCountPipeline()
			//	if err != nil {
			//
			//	}
			//}()

		// —— 聚合者二次VRF提案 ——
		case *AggVRFMsg:
			fmt.Printf("[resolveMsg] Handling AggVRFMSG from %s\n", m.NodeID)
			_ = node.handleAggVRFMsg(m)
		// 承诺/向量交换
		case *AggCommitMsg:
			fmt.Printf("[resolveMsg] Handling AggCommitMsg from %s\n", m.FromNode)
			// 等待所有节点的份额信息提交完成
			//node.wg.Wait() // 阻塞直到所有节点都完成份额提交

			_ = node.handleAggCommitMsg(m)
			//go func() {
			//	err := node.TryAdvanceCountPipeline()
			//	if err != nil {
			//
			//	}
			//}()
		case *AggSumsMsg:
			fmt.Printf("[resolveMsg] Handling AggSumsMsg from %s\n", m.FromNode)
			_ = node.handleAggSumsMsg(m)
			//go func() {
			//	err := node.TryAdvanceCountPipeline()
			//	if err != nil {
			//
			//	}
			//}()

		// 最终结果 + 证明广播
		case *CountProofMsg:
			_ = node.handleCountProofMsg(m)
			//case *ApproveShareMsg:
			//	_ = node.handleApproveShare(m)
			//	_ = node.TryAdvanceCountPipeline()
		}
	}
}

func (node *Node) resolveVRFResult(v *VRFResult) error {
	return node.VerifyAndSaveVRF(v)
}

// 懒加载初始化：如果 web3 尚未初始化，且已有 cachedCfg，则调用 InitWeb3
func (n *Node) ensureWeb3() error {
	if n.web3 != nil {
		return nil
	}
	if n.cachedCfg == nil {
		return fmt.Errorf("web3 not initialized: missing /onchain/config")
	}
	// 可选：用 sync.Once 防抖
	var initErr error
	n.web3Once.Do(func() { initErr = n.InitWeb3(*n.cachedCfg) })
	if initErr != nil {
		return fmt.Errorf("InitWeb3 failed: %w", initErr)
	}
	return nil
}

//func (n *Node) createWitness() interface{} {
//
//	return nil
//}
//
//func (n *Node) getSRS() (interface{}, interface{}) {
//
//	return nil, nil
//}
