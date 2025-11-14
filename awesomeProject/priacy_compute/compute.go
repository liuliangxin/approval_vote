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

type AggCommitMsg struct {
	FromNode string `json:"from_node"`
	L        int    `json:"l"`
	Part     int    `json:"part"`

	CommitHex string `json:"commit_hex"`

	VectorHash string `json:"vector_hash_hex"`
}

type AggSumsMsg struct {
	FromNode string   `json:"from_node"`
	L        int      `json:"l"`
	Part     int      `json:"part"` 
	Sums     []uint64 `json:"sums"`
}

type CountProofMsg struct {
	FromNode string   `json:"from_node"`
	M        int      `json:"m"` 
	D        int      `json:"d"`
	L        int      `json:"l"`
	K        int      `json:"k"`
	T        []uint64 `json:"t_vector"` 
	TopKIdx  []int    `json:"topk_indices"`
	Proof    string   `json:"proof_hex"` 

	VK         string 
	HTPoseidon string 
	CommitA    string `json:"commit_a_hex"`
	CommitB    string `json:"commit_b_hex"`
}

type TriggerSendSumsMsg struct {
	
	Force bool `json:"force,omitempty"`
}

func addModQ(a, b uint64) uint64 {
	qa := Q.Uint64()
	s := a + b
	if s >= qa || s < a {
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

	fmt.Printf("[TrySendAggregateCommitOnce] begin aggregation vector combine, L=%d part=%d\n", L, n.AggregatorPart)
	tReduce := time.Now()

	vec := make([]uint64, L)
	if n.AggregatorPart == 1 {
		for _, v := range n.RecvSharesPart1 {
			for i := 0; i < L; i++ {
				vec[i] = addModQ(vec[i], v[i])
			}
		}

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

	fmt.Printf("[TrySendAggregateCommitOnce] sending aggregate commit (part=%d, L=%d)\n",
		n.AggregatorPart, L)

	if err := n.SendAggregateCommit(); err != nil {
		fmt.Printf("[TrySendAggregateCommitOnce] send commit err: %v\n", err)
		return
	}

	n.mu.Lock()
	n.sentAggCommit = true
	n.mu.Unlock()
}

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

	fmt.Printf("[SendAggregateCommit] AggregatorPart: %d, BloomL: %d\n", part, L)

	var vec []uint64
	if part == 1 {
		vec = n.Sigma1
	} else if part == 2 {
		vec = n.Sigma2
	} else {
		return fmt.Errorf("bad part=%d", part)
	}

	
	fmt.Printf("[SendAggregateCommit] Using vector: %v\n", vec)

	if vec == nil || len(vec) != L {
		return fmt.Errorf("aggregate first")
	}
	t0 := time.Now()
	
	total := uint64(0)
	for i := 0; i < L; i++ {
		total = addModQ(total, vec[i])
	}
	fmt.Printf("total sum_l=%s ok=%v err=%v\n", time.Since(t0))
	
	fmt.Printf("[SendAggregateCommit] Calculated total: %d\n", total)
	t1 := time.Now()
	
	val := new(big.Int).SetUint64(total)
	rnd := new(big.Int).SetUint64(randUint64ModQ())
	com, _ := PedersenCommit(val, rnd)
	fmt.Printf("PedersenCommit=%s ok=%v err=%v\n", time.Since(t1))
	
	fmt.Printf("[SendAggregateCommit] Pedersen Commitment: %x\n", com.Commit)

	
	h := sha256.New()
	for _, v := range vec {
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], v)
		h.Write(buf[:])
	}
	vectorHash := hex.EncodeToString(h.Sum(nil))

	
	selfMsg := AggCommitMsg{
		FromNode:   n.NodeID,
		L:          L,
		Part:       part,
		CommitHex:  hex.EncodeToString(com.Commit),
		VectorHash: vectorHash, 
	}
	
	if err := n.handleAggCommitMsg(&selfMsg); err != nil {
		fmt.Printf("[SendAggregateCommit] cache self commit failed: %v\n", err)
	}
	
	fmt.Printf("[SendAggregateCommit] Vector Hash: %s\n", vectorHash)

	
	msg := AggCommitMsg{
		FromNode:   n.NodeID,
		L:          L,
		Part:       part,
		CommitHex:  hex.EncodeToString(com.Commit),
		VectorHash: vectorHash,
	}
	body, _ := json.Marshal(msg)

	
	fmt.Printf("[SendAggregateCommit] Sending message: %v\n", msg)

	url := n.NodeTable[n.PeerAggregator] + "/vote/aggregate/commit"
	if n.VoteHTTP == nil {
		n.VoteHTTP = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := n.VoteHTTP.Post("http:
	if err != nil {
		return fmt.Errorf("POST http:
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	fmt.Printf("[SendAggregateCommit] OK -> %s (status=%d)\n", url, resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST http:
	}
	
	fmt.Printf("[SendAggregateCommit] Successfully sent aggregate commit to %s\n", url)
	return nil
}


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


func checkLen(name string, got []byte, want int) error {
	if want <= 0 {
		return nil 
	}
	if len(got) != want {
		return fmt.Errorf("%s length mismatch: got %d, want %d", name, len(got), want)
	}
	return nil
}


func (n *Node) handleAggCommitMsg(m *AggCommitMsg) error {
	fmt.Printf("[handleAggCommitMsg] node=%s got commit from part=%d peer=%s vecHash[0:8]=%s...\n",
		n.NodeID, m.Part, m.VectorHash[:8])
	fmt.Println("[handleAggCommitMsg] Starting message processing")
	if m == nil {
		return errors.New("nil message")
	}
	fmt.Println("[handleAggCommitMsg] Commit decoded successfully")
	
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
	
	
	
	
	
	
	
	
	

	
	
	

	
	fmt.Printf("[handleAggCommitMsg] Received commit message: Part: %d, CommitHex: %s, VectorHash: %s\n", m.Part, m.CommitHex, m.VectorHash)

	switch m.Part {
	case 1: 
		if n.haveA {
			return errors.New("duplicate commit from part=1 (M_A)")
		}
		n.commitA = append(n.commitA[:0], commit...) 
		n.vectorHashA = append(n.vectorHashA[:0], vecHash...)
		n.haveA = true
		fmt.Printf("[handleAggCommitMsg] Stored commit for M_A, Commit: %x, VectorHash: %x\n", n.commitA, n.vectorHashA)
	case 2: 
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
	
	fmt.Printf("[handleAggCommitMsg] commit stored; haveA=%v haveB=%v\n", n.haveA, n.haveB)
	n.TrySendAggregateSumsOnce()
	return nil
}
func (n *Node) TrySendAggregateSumsOnce() {
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

	
	fmt.Printf("[TrySendAggregateSumsOnce] ready to send aggregate sums to peer=%s (part=%d, L=%d)\n",
		n.PeerAggregator, n.AggregatorPart, n.BloomL)

	if err := n.SendAggregateSums(); err != nil {
		fmt.Printf("[TrySendAggregateSumsOnce] send sums err: %v\n", err)
		return
	}

	n.sentAggSums = true

	
	fmt.Printf("[TrySendAggregateSumsOnce] aggregate sums sent successfully by node=%s (part=%d)\n",
		n.NodeID, n.AggregatorPart)
}



func (n *Node) SendAggregateSums() error {
	if !n.IsAggregator {
		return fmt.Errorf("not aggregator")
	}
	if n.PeerAggregator == "" {
		return fmt.Errorf("peer aggregator empty")
	}
	
	L := n.BloomL
	part := n.AggregatorPart
	fmt.Printf("[SendAggregateSums] AggregatorPart: %d, BloomL: %d\n", part, L)

	var vec []uint64
	if part == 1 {
		vec = n.Sigma1
	} else {
		vec = n.Sigma2
	}

	
	fmt.Printf("[SendAggregateSums] Using vector: %v\n", vec)

	if vec == nil || len(vec) != L {
		return fmt.Errorf("aggregate first")
	}

	
	msg := AggSumsMsg{
		FromNode: n.NodeID,
		L:        L,
		Part:     part,
		Sums:     vec,
	}

	
	fmt.Printf("[SendAggregateSums] Sending AggregateSums message: %v\n", msg)

	body, err := json.Marshal(msg)
	if err != nil {
		fmt.Printf("[SendAggregateSums] Error marshalling message: %v\n", err)
		return err
	}

	
	url := n.NodeTable[n.PeerAggregator] + "/vote/aggregate/sums"
	if n.VoteHTTP == nil {
		n.VoteHTTP = &http.Client{Timeout: 5 * time.Second}
	}

	
	fmt.Printf("[SendAggregateSums] Sending POST request to: http:

	resp, err := n.VoteHTTP.Post("http:
	if err != nil {
		return fmt.Errorf("POST http:
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	fmt.Printf("[SendAggregateCommit] OK -> %s (status=%d)\n", url, resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST http:
	}

	
	fmt.Printf("[SendAggregateSums] Successfully sent aggregate sums to %s\n", url)

	return nil
}


func (n *Node) HasBothCommits() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.haveA && n.haveB
}


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

	
	hh := sha256.New()
	var buf [8]byte
	for _, v := range m.Sums {
		binary.LittleEndian.PutUint64(buf[:], v)
		hh.Write(buf[:])
	}
	gotHash := hh.Sum(nil)

	
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

	
	fmt.Printf("[handleAggSumsMsg] Received sums for part %d, L: %d, Sums: %v\n", m.Part, m.L, m.Sums)
	t4 := time.Now()
	
	switch n.AggregatorPart {
	case 1: 
		n.Sigma = make([]uint64, n.BloomL)
		if n.Sigma1 == nil {
			return fmt.Errorf("Sigma1 not ready")
		}
		for i := 0; i < n.BloomL; i++ {
			n.Sigma[i] = addModQ(n.Sigma1[i], m.Sums[i])
		}
		
		fmt.Printf("[handleAggSumsMsg] Aggregator M_A: Sigma updated: %v\n", n.Sigma)
	case 2: 
		n.Sigma = make([]uint64, n.BloomL)
		if n.Sigma2 == nil {
			return fmt.Errorf("Sigma2 not ready")
		}
		for i := 0; i < n.BloomL; i++ {
			n.Sigma[i] = addModQ(n.Sigma2[i], m.Sums[i])
		}
		
		fmt.Printf("[handleAggSumsMsg] Aggregator M_B: Sigma updated: %v\n", n.Sigma)
	}
	fmt.Printf("[timing] handleaggsumsmsg time=%s\n", time.Since(t4))
	
	if !n.computedScores {
		if err := n.ComputeCandidateScores(); err != nil {
			return fmt.Errorf("ComputeCandidateScores: %w", err)
		}
		
		if n.TopK == 0 {
			n.TopK = 21 
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

	
	fmt.Printf("[ComputeCandidateScores] Computing candidate scores with BloomM: %d, BloomD: %d, BloomL: %d\n", m, d, l)
	fmt.Printf("[ComputeCandidateScores] Sigma: %v\n", n.Sigma)

	n.CandidateScores = make([]uint64, m)
	for c := 0; c < m; c++ {
		minv := uint64(math.MaxUint64)
		for j := 0; j < d; j++ {
			p := bloomPosForIndex(uint64(c), j, l) 
			v := n.Sigma[p]
			if v < minv {
				minv = v
			}
		}
		n.CandidateScores[c] = minv
		
		fmt.Printf("[ComputeCandidateScores] Candidate %d, Score: %d\n", c, n.CandidateScores[c])
	}
	return nil
}


func bloomPosForIndex(idx uint64, j int, L int) int {
	seed := uint64(j + 1)
	h := sha256.New() 
	var buf [16]byte
	binary.LittleEndian.PutUint64(buf[:8], idx)
	binary.LittleEndian.PutUint64(buf[8:], seed)
	h.Write(buf[:])
	sum := h.Sum(nil)
	
	u := binary.LittleEndian.Uint64(sum[:8])
	return int(u % uint64(L))
}


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
		return arr[i].Val > arr[j].Val 
	})
	k := n.TopK
	n.Committee = make([]int, k)
	for i := 0; i < k; i++ {
		n.Committee[i] = arr[i].Idx
	}
	return nil
}
func (n *Node) ensureSRS() error {
	
	if n.srs == nil || len(n.srs.Pk.G1) == 0 {
		const size = 1 << 16 
		var minusOne big.Int
		minusOne.SetInt64(-1) 

		srs, err := bn254kzg.NewSRS(size, &minusOne)
		if err != nil {
			return fmt.Errorf("bn254kzg.NewSRS: %w", err)
		}
		n.srs = srs

		
		
		
	}
	return nil
}


func (n *Node) ProveAndBroadcastCount() error {
	
	fmt.Println("[ProveAndBroadcastCount] Called")

	if n.CandidateScores == nil || len(n.Committee) != n.TopK {
		return fmt.Errorf("scores/committee not ready")
	}

	
	d := uint64(n.BloomD)
	tmax := uint64(n.BloomT)
	k := uint64(n.TopK)
	T := make([]uint64, len(n.CandidateScores))
	for i, v := range n.CandidateScores {
		T[i] = v
	}

	
	fmt.Println("[ProveAndBroadcastCount] Preparing SRS")
	if err := n.ensureSRS(); err != nil {
		return err
	}
	fmt.Println("[ProveAndBroadcastCount] SRS generated successfully")
	t3 := time.Now()
	
	fmt.Println("[ProveAndBroadcastCount] Building and proving")
	proof, vk, _, err := n.buildAndProveCount(T, d, tmax, k, n.srs, n.srsLag)
	fmt.Printf("zk-snark proof generation time=%s ok=%t err=%v\n",
		time.Since(t3), proof != nil && err == nil, err)
	if err != nil {
		return fmt.Errorf("build/prove: %w", err)
	}
	n.vkCount = vk
	fmt.Println("[ProveAndBroadcastCount] Proof and VK generated successfully")

	
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
		fmt.Printf("[ZK] proofHex(prefix)=%s...\n", proofHex[:66]) 
	} else {
		fmt.Printf("[ZK] proofHex=%s\n", proofHex)
	}
	if len(vkHex) > 66 {
		fmt.Printf("[ZK] vkHex(prefix)=%s...\n", vkHex[:66])
	} else {
		fmt.Printf("[ZK] vkHex=%s\n", vkHex)
	}

	
	_ = os.WriteFile("proof.hex", []byte(proofHex+"\n"), 0644)
	_ = os.WriteFile("vk.hex", []byte(vkHex+"\n"), 0644)
	
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

	
	n.ZKProofHex = proofHex

	
	fmt.Printf("[Count] Node=%s M=%d d=%d t=%d k=%d\n", n.NodeID, n.BloomM, n.BloomD, n.BloomT, n.TopK)
	fmt.Printf("[Count] Scores(T) = %v\n", n.CandidateScores)
	fmt.Printf("[Count] Committee (Top-%d idx) = %v\n", n.TopK, n.Committee)

	
	msg := CountProofMsg{
		FromNode:   n.NodeID,
		M:          n.BloomM,
		D:          n.BloomD,
		L:          n.BloomL,
		K:          n.TopK,
		T:          n.CandidateScores,
		TopKIdx:    n.Committee,
		Proof:      proofHex,
		VK:         vkHex,           
		HTPoseidon: n.HTPoseidonHex, 
		CommitA:    "", CommitB: "",
	}

	body, _ := json.Marshal(msg)

	
	fmt.Println("[ProveAndBroadcastCount] Sending proof message to nodes")

	
	fmt.Println("[OnchainPrep] Computing on-chain submission parameters")

	
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

	
	fmt.Printf("[OnchainPrep] hT (Poseidon hash of votes) = %s\n", n.HTPoseidonHex)

	
	proofBytes, _ := hex.DecodeString(n.ZKProofHex[2:])
	fmt.Printf("[OnchainPrep] proofBytes length = %d\n", len(proofBytes))

	
	fmt.Println("========== Onchain Parameters ==========")
	fmt.Printf("Epoch: %d\n", n.CurrentEpoch)
	fmt.Printf("Committee addresses: %v\n", addrs)
	fmt.Printf("hE: %s\n", hE.Hex())
	fmt.Printf("hT: %s\n", n.HTPoseidonHex)
	fmt.Printf("Proof (hex): %s\n", n.ZKProofHex[:66]+"...") 
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
		_, _ = n.VoteHTTP.Post("http:
	}
	fmt.Println("[ProveAndBroadcastCount] Successfully broadcasted the proof message")

	
	
	
	
	
	
	
	
	

	return nil
}

func (n *Node) handleCountProofMsg(m *CountProofMsg) error {
	
	hexProof := strings.TrimPrefix(strings.ToLower(m.Proof), "0x")
	pb, err := hex.DecodeString(hexProof)
	if err != nil {
		return fmt.Errorf("decode proof: %w", err)
	}
	var proof plonkbn254.Proof
	if _, err := proof.ReadFrom(bytes.NewReader(pb)); err != nil {
		return fmt.Errorf("proof.ReadFrom: %w", err)
	}

	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

	
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
	
	
	
	
	
	
	
	
	
	
	
	
	
	

	
	
	
	
	
	
	
	
	
	
	

	
	

	
	
	
	

	
	n.CandidateScores = m.T
	n.TopK = m.K
	n.Committee = m.TopKIdx
	fmt.Println(" ZK proof verified & result accepted")
	fmt.Printf("[Count] Scores(T) = %v\n", n.CandidateScores)
	fmt.Printf("[Count] Committee (Top-%d idx) = %v\n", n.TopK, n.Committee)

	return nil
}


func (n *Node) ComputeAggregatePart() error {
	if !n.IsAggregator || n.BloomL == 0 {
		return nil
	}
	L := n.BloomL

	
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

	
	
	return nil
}


func (n *Node) TryAdvanceCountPipeline() error {
	if !n.IsAggregator {
		return nil
	}
	if n.PeerAggregator == "" {
		
		return nil
	}

	
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

	
	
	
	
	
	
	
	

	
	if !n.sentAggSums && n.HasBothCommits() {
		if err := n.SendAggregateSums(); err != nil {
			return fmt.Errorf("SendAggregateSums: %w", err)
		}
		n.sentAggSums = true
	}

	
	if n.Sigma == nil || len(n.Sigma) != n.BloomL {
		return nil 
	}

	
	if !n.computedScores {
		if err := n.ComputeCandidateScores(); err != nil {
			return fmt.Errorf("ComputeCandidateScores: %w", err)
		}
		n.computedScores = true
	}

	
	if n.TopK > 0 && len(n.Committee) != n.TopK {
		if err := n.SelectTopK(); err != nil {
			return fmt.Errorf("SelectTopK: %w", err)
		}
	}

	
	if !n.broadcastResult && n.TopK > 0 && len(n.Committee) == n.TopK {
		if err := n.ProveAndBroadcastCount(); err != nil {
			return fmt.Errorf("ProveAndBroadcastCount: %w", err)
		}
		n.broadcastResult = true
	}

	return nil
}




func poseidonHashTBN254(t []uint64) (fr.Element, error) {
	fmt.Println("[poseidonHashTBN254] Initializing Poseidon2 (width=2, RF=8, RP=56)")
	h := poseidon2.NewPermutation(2, 8, 56)

	var acc [32]byte

	for i, v := range t {
		var e fr.Element
		e.SetUint64(v)
		xb := e.Marshal()

		
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

































func frToBytes32(x fr.Element) [32]byte {
	var out [32]byte
	b := x.Marshal()
	copy(out[:], b)
	return out
}
