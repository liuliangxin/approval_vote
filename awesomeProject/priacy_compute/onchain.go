package priacy_compute

import (
	"context"
	"crypto/ecdsa"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/crypto/sha3"
)

const ElectionOnChainABI = `[
  {"inputs":[
    {"internalType":"uint256","name":"epoch","type":"uint256"},
    {"internalType":"bytes32","name":"hE","type":"bytes32"},
    {"internalType":"bytes32","name":"hT","type":"bytes32"},
    {"internalType":"bytes","name":"proof","type":"bytes"},
    {"internalType":"address[]","name":"committeeAddrs","type":"address[]"},
    {"internalType":"bytes32","name":"commitAHint","type":"bytes32"},
    {"internalType":"bytes32","name":"commitBHint","type":"bytes32"}
  ],
  "name":"submitResult","outputs":[],"stateMutability":"nonpayable","type":"function"}]`

type Web3Handle struct {
	Client       *ethclient.Client
	ContractAddr common.Address
	ABI          abi.ABI
	Priv         *ecdsa.PrivateKey
	From         common.Address
	ChainID      *big.Int
	Contract     *bind.BoundContract
}

type OnchainConfig struct {
	RPCURL        string `json:"rpc_url"`
	ContractAddr  string `json:"contract_address"`
	PrivateKeyHex string `json:"private_key_hex"`
	ChainID       int64  `json:"chain_id"`
}

func (n *Node) InitWeb3(cfg OnchainConfig) error {
	if cfg.RPCURL == "" || cfg.ContractAddr == "" || cfg.PrivateKeyHex == "" || cfg.ChainID == 0 {
		return errors.New("missing web3 config")
	}
	if !strings.HasPrefix(cfg.PrivateKeyHex, "0x") {
		cfg.PrivateKeyHex = "0x" + cfg.PrivateKeyHex
	}
	priv, err := crypto.HexToECDSA(cfg.PrivateKeyHex[2:])
	if err != nil {
		return err
	}
	fromAddr := crypto.PubkeyToAddress(priv.PublicKey)
	client, err := ethclient.Dial(cfg.RPCURL)
	if err != nil {
		return err
	}
	parsed, err := abi.JSON(strings.NewReader(ElectionOnChainABI))
	if err != nil {
		return err
	}
	contractAddr := common.HexToAddress(cfg.ContractAddr)
	contract := bind.NewBoundContract(contractAddr, parsed, client, client, client)

	n.web3 = &Web3Handle{
		Client:       client,
		ContractAddr: contractAddr,
		ABI:          parsed,
		Priv:         priv,
		From:         fromAddr,
		ChainID:      big.NewInt(cfg.ChainID),
		Contract:     contract,
	}
	return nil
}

type OnchainSubmitReq struct {
	Epoch       uint64   `json:"epoch"`
	Committee   []string `json:"committee"`
	ProofHex    string   `json:"proof_hex"`
	Counts      []uint64 `json:"t_counts,omitempty"`
	HTHex       string   `json:"ht_hex,omitempty"`
	CommitAHint string   `json:"commit_a_hex,omitempty"`
	CommitBHint string   `json:"commit_b_hex,omitempty"`
}

func (n *Node) OnchainSubmit(ctx context.Context, req *OnchainSubmitReq) (txHash string, err error) {
	if n.web3 == nil {
		return "", errors.New("web3 not initialized; call /onchain/config first")
	}
	if err := n.ensureWeb3(); err != nil {
		return "", err
	}

	addrs := make([]common.Address, 0, len(req.Committee))
	for _, s := range req.Committee {
		addrs = append(addrs, common.HexToAddress(s))
	}
	hE := merkleRootAddresses(addrs)

	var hT common.Hash
	if len(req.HTHex) > 0 {
		hT = common.HexToHash(req.HTHex)
	} else if len(req.Counts) > 0 {
		hT = merkleRootUint256s(req.Counts)
	} else {
		return "", errors.New("must provide either t_counts or ht_hex")
	}

	if !strings.HasPrefix(req.ProofHex, "0x") {
		req.ProofHex = "0x" + req.ProofHex
	}
	proofBytes, err := hex.DecodeString(req.ProofHex[2:])
	if err != nil {
		return "", err
	}

	commitA := strToBytes32(req.CommitAHint)
	commitB := strToBytes32(req.CommitBHint)

	opts, err := bind.NewKeyedTransactorWithChainID(n.web3.Priv, n.web3.ChainID)
	if err != nil {
		return "", err
	}
	opts.From = n.web3.From
	opts.Context = ctx

	tx, err := n.web3.Contract.Transact(
		opts,
		"submitResult",
		new(big.Int).SetUint64(req.Epoch),
		hE,
		hT,
		proofBytes,
		addrs,
		commitA,
		commitB,
	)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

func merkleRootAddresses(addrs []common.Address) common.Hash {
	if len(addrs) == 0 {
		return common.Hash{}
	}
	leaves := make([]common.Hash, len(addrs))
	for i, a := range addrs {
		h := sha3.NewLegacyKeccak256()
		h.Write(a.Bytes())
		var out common.Hash
		h.Sum(out[:0])
		leaves[i] = out
	}
	return merkleRoot(leaves)
}

func merkleRootUint256s(vals []uint64) common.Hash {
	if len(vals) == 0 {
		return common.Hash{}
	}
	leaves := make([]common.Hash, len(vals))
	for i, v := range vals {

		var buf [32]byte
		b := new(big.Int).SetUint64(v).Bytes()
		copy(buf[32-len(b):], b)

		h := sha3.NewLegacyKeccak256()
		h.Write(buf[:])
		var out common.Hash
		h.Sum(out[:0])
		leaves[i] = out
	}
	return merkleRoot(leaves)
}

func merkleRoot(leaves []common.Hash) common.Hash {
	level := leaves
	for len(level) > 1 {
		n := len(level)
		m := (n + 1) / 2
		next := make([]common.Hash, m)
		for i := 0; i < m; i++ {
			a := level[2*i]
			var b common.Hash
			if 2*i+1 < n {
				b = level[2*i+1]
			} else {
				b = a
			}
			h := sha3.NewLegacyKeccak256()
			h.Write(a[:])
			h.Write(b[:])
			h.Sum(next[i][:0])
		}
		level = next
	}
	return level[0]
}

func strToBytes32(hexStr string) [32]byte {
	var out [32]byte
	if hexStr == "" {
		return out
	}
	if !strings.HasPrefix(hexStr, "0x") {
		hexStr = "0x" + hexStr
	}
	b, err := hex.DecodeString(hexStr[2:])
	if err != nil {
		return out
	}
	if len(b) > 32 {
		b = b[len(b)-32:]
	}
	copy(out[32-len(b):], b)
	return out
}

func (n *Node) SetAddressBookFromMap(m map[string]string) error {
	if n.AddressBook == nil {
		n.AddressBook = make(map[int]string)
	}
	for k, v := range m {
		idx, ok := new(big.Int).SetString(k, 10)
		if !ok {
			return errors.New("bad index: " + k)
		}
		n.AddressBook[int(idx.Int64())] = v
	}
	return nil
}

func (n *Node) committeeAddrsFromIndices() ([]string, error) {
	if len(n.Committee) == 0 {
		return nil, errors.New("committee empty")
	}
	out := make([]string, len(n.Committee))
	for i, idx := range n.Committee {
		addr := n.AddressBook[idx]
		if addr == "" {
			return nil, errors.New("missing address for index: " + fmtInt(idx))
		}
		out[i] = addr
	}
	return out, nil
}

func (n *Node) AutoSubmitIfReady() error {
	if !n.OnchainAuto || n.web3 == nil || n.OnchainSubmitted {
		return nil
	}
	if !n.IsAggregator || n.AggregatorPart != 1 {
		return nil
	}

	if len(n.Committee) == 0 || len(n.CandidateScores) == 0 || len(n.ZKProofHex) == 0 {
		return nil
	}
	addrsStr, err := n.committeeAddrsFromIndices()
	if err != nil {
		return err
	}

	req := &OnchainSubmitReq{
		Epoch:       n.CurrentEpoch,
		Committee:   addrsStr,
		ProofHex:    n.ZKProofHex,
		Counts:      n.CandidateScores,
		CommitAHint: "",
		CommitBHint: "",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	txh, err := n.OnchainSubmit(ctx, req)
	if err != nil {
		return err
	}

	n.OnchainSubmitted = true
	_ = txh
	return nil
}

func fmtInt(x int) string { return new(big.Int).SetInt64(int64(x)).String() }

func (n *Node) LoadAddressBookCSV(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.TrimLeadingSpace = true
	records, err := r.ReadAll()
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return errors.New("addresses.csv empty")
	}

	start := 0
	if len(records[0]) >= 2 &&
		strings.EqualFold(strings.TrimSpace(records[0][0]), "index") &&
		strings.EqualFold(strings.TrimSpace(records[0][1]), "address") {
		start = 1
	}

	if n.AddressBook == nil {
		n.AddressBook = make(map[int]string)
	}
	for i := start; i < len(records); i++ {
		row := records[i]

		if len(row) == 0 || (len(row) == 1 && strings.TrimSpace(row[0]) == "") {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(row[0]), "#") {
			continue
		}
		if len(row) < 2 {
			return fmt.Errorf("bad csv at line %d: need 2 columns", i+1)
		}
		idxStr := strings.TrimSpace(row[0])
		addr := strings.TrimSpace(row[1])
		idx, err := strconv.Atoi(idxStr)
		if err != nil {
			return fmt.Errorf("bad index '%s' at line %d", idxStr, i+1)
		}
		if !common.IsHexAddress(addr) {
			return fmt.Errorf("bad eth address '%s' at line %d", addr, i+1)
		}
		n.AddressBook[idx] = common.HexToAddress(addr).Hex()
	}
	n.AddressBookPath = path
	return nil
}
