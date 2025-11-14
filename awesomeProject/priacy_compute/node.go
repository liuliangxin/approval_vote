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
	PKHex   string  `json:"pk_hex"` 
	T       uint64  `json:"t"`
	Context string  `json:"context"`
	Proof   []byte  `json:"proof"` 
	Value   float64 `json:"value"` 
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
	
	Tau         float64 
	VRF_T       uint64  
	VRF_Context string  
	SelfPK      ed25519.PublicKey
	SelfSK      ed25519.PrivateKey

	
	VRFValue     float64
	VRFProof     []byte
	VRFChosen    bool
	CandidateSet map[string]*VRFRecord 
	hash         []byte

	
	AggEpoch    uint64
	AggRound    uint64
	AggContext  string
	aggDeadline time.Time

	
	BloomM   int
	BloomT   int
	BloomEps float64
	BloomL   int
	BloomD   int
	VoteHTTP *http.Client

	
	Aggregators [2]string
	aggBox      map[string]uint8 

	
	RecvSharesPart1 map[string][]uint64 
	RecvSharesPart2 map[string][]uint64 

	Sigma1 []uint64 
	Sigma2 []uint64 
	Sigma  []uint64 

	CandidateScores []uint64 
	TopK            int      
	Committee       []int    

	
	IsAggregator   bool   
	AggregatorPart int    
	PeerAggregator string 

	
	commitA     []byte
	vectorHashA []byte
	commitB     []byte
	vectorHashB []byte

	
	haveA bool
	haveB bool

	
	ExpectedCommitLen int 
	ExpectedHashLen   int 

	
	sentAggCommit   bool
	sentAggSums     bool
	computedScores  bool
	broadcastResult bool

	wg         sync.WaitGroup 
	totalNodes int            

	
	aggRoundStarted bool          
	aggTimer        *time.Timer   
	AggWindow       time.Duration 
	MinVotes        int           
	Window          time.Duration
	web3            *Web3Handle
	
	AddressBook       map[int]string 
	OnchainAuto       bool           
	OnchainSubmitted  bool           
	CurrentEpoch      uint64         
	CurrentRound      uint64
	ZKProofHex        string    
	HTPoseidonHex     string    
	AddressBookPath   string    
	OnchainLastTxHash string    
	OnchainLastSubmit time.Time 
	
	
	srs     *bn254kzg.SRS            
	srsLag  bn254kzg.SRS             
	vkCount *plonkbn254.VerifyingKey 

	cachedCfg     *OnchainConfig 
	web3Once      sync.Once      
	sprCount      *cs.SparseR1CS
	pkCount       *plonkbn254.ProvingKey
	SetupCacheDir string
	setupOnce     sync.Once
}


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
	
	if f, err := os.Open(filepath.Join(dir, "count.spr")); err == nil {
		defer f.Close()
		var spr cs.SparseR1CS
		if _, err := spr.ReadFrom(f); err != nil {
			return err
		}
		n.sprCount = &spr
	}
	
	if f, err := os.Open(filepath.Join(dir, "count.pk")); err == nil {
		defer f.Close()
		var pk plonkbn254.ProvingKey
		if _, err := pk.ReadFrom(f); err != nil {
			return err
		}
		n.pkCount = &pk
	}
	
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
	
	a, err := ioutil.ReadFile("nodetable1.csv")
	if err != nil {
		fmt.Print(err)
	}
	NodeTable := map[string]string{}
	if err := json.Unmarshal(a, &NodeTable); err != nil {
		panic(err)
	}
	viewID := 1 
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
		
		Tau:          0.3,
		VRF_T:        100,
		VRF_Context:  "epoch1:block100",
		CandidateSet: make(map[string]*VRFRecord),

		
		BloomM:   0,
		BloomT:   0,
		BloomEps: 0,
		BloomL:   0,
		BloomD:   0,
		VoteHTTP: &http.Client{},

		
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

	
	pk, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	node.SelfPK, node.SelfSK = pk, sk

	
	go node.dispatchMsg()
	go node.resolveMsg()
	go node.sendMsg()

	return node
}
















































func (n *Node) startAggRound(epoch, round uint64, context string, window time.Duration) {
	n.mu.Lock()
	
	
	
	
	
	
	
	
	

	
	
	n.AggEpoch = epoch
	n.AggRound = round
	n.AggContext = context
	n.roundStarted = true

	
	n.aggBox = make(map[string]uint8)
	n.aggDeadline = time.Now().Add(window)
	n.mu.Unlock()

	
	
	
	
	

	

	go func(deadline time.Time) {
		d := time.Until(deadline)
		if d < 0 {
			d = 0
		}
		<-time.After(d)

		
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

		
		
		fmt.Printf("[AggDeadline] trigger final aggregate: self=%s part=%d (final)\n",
			n.NodeID, part)
		n.TrySendAggregateCommitOnce()
	}(n.aggDeadline)

}































func (n *Node) addTestShares() {
	n.mu.Lock()
	defer n.mu.Unlock()

	L := 29         
	q := uint64(97) 

	
	BFi := make([]uint64, L)
	for i := 0; i < L; i++ {
		if rand.Float64() < 0.4 { 
			BFi[i] = 1
		} else {
			BFi[i] = 0
		}
	}

	
	if n.RecvSharesPart1 == nil {
		n.RecvSharesPart1 = make(map[string][]uint64)
	}
	if n.RecvSharesPart2 == nil {
		n.RecvSharesPart2 = make(map[string][]uint64)
	}

	part1 := make([]uint64, L)
	part2 := make([]uint64, L)

	for l := 0; l < L; l++ {
		r := uint64(rand.Intn(int(q))) 
		part1[l] = r
		part2[l] = (BFi[l] + q - r) % q 
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
	
	select {
	case node.MsgDelivery <- msg:
		fmt.Printf("[routeMsg] Message of type %T forwarded to MsgDelivery\n", msg)
	default:
		fmt.Printf("[routeMsg] Failed to forward message of type %T to MsgDelivery\n", msg)
	}
	return nil
}


var httpClient *http.Client

func (node *Node) sendMsg() {
	httpClient = &http.Client{}
	httpClient.Transport = &http.Transport{MaxIdleConnsPerHost: 1000}
	for {
		select {
		case sendmsg := <-node.VoteSend_go:
			buff := bytes.NewBuffer(sendmsg.msg)
			_, _ = httpClient.Post("http:
		default:
			select {
			case sendmsg := <-node.MsgSend_go:
				buff := bytes.NewBuffer(sendmsg.msg)
				_, _ = httpClient.Post("http:
			default:
				time.Sleep(time.Microsecond)
			}
			time.Sleep(time.Microsecond)
		}
	}
}


func (node *Node) resolveMsg() {
	for {
		msg := <-node.MsgDelivery
		fmt.Println("Resolving message:", msg)
		switch m := msg.(type) {
		case *VRFResult:
			_ = node.resolveVRFResult(m)
		case *TriggerVRFMsg:
			_ = node.RunRandomElectAndBroadcast()
		
		case *BloomParamsMsg:
			_ = node.handleBloomParams(m)

		
		case *LocalApproveVoteMsg:
			_ = node.handleLocalApproveVote(m)

		
		case *ReceivedShareMsg:
			node.wg.Add(1)
			fmt.Printf("[ReceivedShareMsg] Received share from node: %s\n", m.Pkt.FromNode)
			_ = node.handleReceivedShare(m)
			
			
			
			
			
			

		
		case *AggVRFMsg:
			fmt.Printf("[resolveMsg] Handling AggVRFMSG from %s\n", m.NodeID)
			_ = node.handleAggVRFMsg(m)
		
		case *AggCommitMsg:
			fmt.Printf("[resolveMsg] Handling AggCommitMsg from %s\n", m.FromNode)
			
			

			_ = node.handleAggCommitMsg(m)
			
			
			
			
			
			
		case *AggSumsMsg:
			fmt.Printf("[resolveMsg] Handling AggSumsMsg from %s\n", m.FromNode)
			_ = node.handleAggSumsMsg(m)
			
			
			
			
			
			

		
		case *CountProofMsg:
			_ = node.handleCountProofMsg(m)
			
			
			
		}
	}
}

func (node *Node) resolveVRFResult(v *VRFResult) error {
	return node.VerifyAndSaveVRF(v)
}


func (n *Node) ensureWeb3() error {
	if n.web3 != nil {
		return nil
	}
	if n.cachedCfg == nil {
		return fmt.Errorf("web3 not initialized: missing /onchain/config")
	}
	
	var initErr error
	n.web3Once.Do(func() { initErr = n.InitWeb3(*n.cachedCfg) })
	if initErr != nil {
		return fmt.Errorf("InitWeb3 failed: %w", initErr)
	}
	return nil
}










