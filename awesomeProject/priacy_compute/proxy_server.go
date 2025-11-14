package priacy_compute

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Server：
type Server struct {
	url  string
	node *Node
}
type TriggerVRFMsg struct{}

func NewServer(nodeID string) *Server {

	n := NewNode(nodeID)
	url := n.NodeTable[nodeID]
	s := &Server{url: url, node: n}
	s.setRoute()
	return s
}

func (s *Server) Start() {
	fmt.Printf("Server will be started at %s...\n", s.url)

	go s.triggerVRFRequest()

	if err := http.ListenAndServe(s.url, nil); err != nil {
		fmt.Println(err)
	}
}

func (s *Server) triggerVRFRequest() {

	resp, err := http.Post(fmt.Sprintf("http://%s/vrf/eval", s.url), "application/json", nil)
	if err != nil {
		fmt.Printf("Error triggering VRF: %v\n", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		fmt.Println("Successfully triggered VRF evaluation.")
	} else {
		fmt.Printf("Failed to trigger VRF, status code: %d\n", resp.StatusCode)
	}

	fmt.Println("Waiting for 30s before triggering aggregation...")
	time.Sleep(30 * time.Second) //

	aggRequest := struct {
		Epoch   uint64        `json:"epoch"`
		Round   uint64        `json:"round"`
		Context string        `json:"context"`
		Window  time.Duration `json:"window_ms"`
	}{
		Epoch:   1,                   //
		Round:   1,                   //
		Context: "exampleContext",    //
		Window:  time.Duration(1000), //
	}

	aggBody, err := json.Marshal(aggRequest)
	if err != nil {
		fmt.Printf("Error marshaling aggregation request: %v\n", err)
		return
	}

	aggResp, err := http.Post(fmt.Sprintf("http://%s/vrf/agg_start", s.url), "application/json", bytes.NewReader(aggBody))
	if err != nil {
		fmt.Printf("Error triggering aggregation: %v\n", err)
		return
	}
	defer aggResp.Body.Close()
	if aggResp.StatusCode == http.StatusOK {
		fmt.Println("Successfully triggered aggregation process.")
	} else {
		fmt.Printf("Failed to trigger aggregation, status code: %d\n", aggResp.StatusCode)
	}
}

func (s *Server) setRoute() {

	http.HandleFunc("/vrf/eval", func(w http.ResponseWriter, r *http.Request) {
		s.node.MsgEntrance <- &TriggerVRFMsg{}
		w.Write([]byte("ok"))
	})

	http.HandleFunc("/vrf/result", s.recvVRFResult)

	//
	http.HandleFunc("/vrf/agg_start", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Epoch   uint64        `json:"epoch"`
			Round   uint64        `json:"round"`
			Context string        `json:"context"`
			Window  time.Duration `json:"window_ms"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		s.node.startAggRound(request.Epoch, request.Round, request.Context, time.Millisecond*request.Window)
		w.Write([]byte("ok"))
	})

	//
	http.HandleFunc("/vrf/agg_proposal", func(w http.ResponseWriter, r *http.Request) {
		var m AggVRFMsg
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		s.node.MsgEntrance <- &m
		_, _ = w.Write([]byte("ok"))
	})

	//
	http.HandleFunc("/status", s.status)

	//
	http.HandleFunc("/params/bloom", func(w http.ResponseWriter, r *http.Request) {
		var m BloomParamsMsg
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		s.node.MsgEntrance <- &m
		_, _ = w.Write([]byte("ok"))
	})

	http.HandleFunc("/vote/approve", func(w http.ResponseWriter, r *http.Request) {
		var m LocalApproveVoteMsg
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		s.node.MsgEntrance <- &m
		_, _ = w.Write([]byte("ok"))
	})

	http.HandleFunc("/vote/share", func(w http.ResponseWriter, r *http.Request) {
		var pkt SecretSharePacket
		if err := json.NewDecoder(r.Body).Decode(&pkt); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		s.node.MsgEntrance <- &ReceivedShareMsg{Pkt: pkt}
		_, _ = w.Write([]byte("ok"))
	})

	http.HandleFunc("/vote/aggregate/commit", func(w http.ResponseWriter, r *http.Request) {
		var m AggCommitMsg
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		s.node.MsgEntrance <- &m
		_, _ = w.Write([]byte("ok"))
	})

	//
	http.HandleFunc("/vote/aggregate/sums", func(w http.ResponseWriter, r *http.Request) {
		var m AggSumsMsg
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		s.node.MsgEntrance <- &m
		_, _ = w.Write([]byte("ok"))
	})

	//
	http.HandleFunc("/vote/result", func(w http.ResponseWriter, r *http.Request) {
		var m CountProofMsg
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		s.node.MsgEntrance <- &m
		_, _ = w.Write([]byte("ok"))
	})

	http.HandleFunc("/onchain/config", func(w http.ResponseWriter, r *http.Request) {
		var cfg OnchainConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "bad json: "+err.Error(), 400)
			return
		}
		//
		s.node.cachedCfg = &cfg

		//
		if err := s.node.InitWeb3(cfg); err != nil {
			http.Error(w, "init web3 failed: "+err.Error(), 500)
			return
		}

		w.Write([]byte("ok"))
	})

	//
	http.HandleFunc("/onchain/submit", func(w http.ResponseWriter, r *http.Request) {
		var req OnchainSubmitReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json: "+err.Error(), 400)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		txh, err := s.node.OnchainSubmit(ctx, &req)
		if err != nil {
			http.Error(w, "submit failed: "+err.Error(), 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"tx_hash": txh})
	})

	// 1)
	// POST /onchain/addressbook  {"0":"0x...","1":"0x..."}
	http.HandleFunc("/onchain/addressbook", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]string
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			http.Error(w, "bad json: "+err.Error(), 400)
			return
		}
		if err := s.node.SetAddressBookFromMap(m); err != nil {
			http.Error(w, "set addressbook fail: "+err.Error(), 400)
			return
		}
		w.Write([]byte("ok"))
	})

	// 2)
	// POST /onchain/auto/enable  {"enable":true}
	http.HandleFunc("/onchain/auto/enable", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Enable bool `json:"enable"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json: "+err.Error(), 400)
			return
		}
		s.node.OnchainAuto = body.Enable

		_ = s.node.AutoSubmitIfReady()
		w.Write([]byte("ok"))
	})

	// 3)
	// POST /onchain/epoch {"epoch":123}
	http.HandleFunc("/onchain/epoch", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Epoch uint64 `json:"epoch"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json: "+err.Error(), 400)
			return
		}
		s.node.CurrentEpoch = body.Epoch
		w.Write([]byte("ok"))
	})

	// 4)
	// POST /onchain/autosubmit {}
	http.HandleFunc("/onchain/autosubmit", func(w http.ResponseWriter, r *http.Request) {
		if err := s.node.AutoSubmitIfReady(); err != nil {
			http.Error(w, "autosubmit failed: "+err.Error(), 500)
			return
		}
		w.Write([]byte("ok"))
	})

	// POST /onchain/addressbook/load  {"path":"addresses.csv"}
	http.HandleFunc("/onchain/addressbook/load", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Path string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json: "+err.Error(), 400)
			return
		}
		if body.Path == "" {
			body.Path = s.node.AddressBookPath
		}
		if err := s.node.LoadAddressBookCSV(body.Path); err != nil {
			http.Error(w, "load csv failed: "+err.Error(), 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
			"path":   s.node.AddressBookPath,
			"size":   fmt.Sprintf("%d", len(s.node.AddressBook)),
		})
	})

}

func (s *Server) triggerLocalVRF(w http.ResponseWriter, r *http.Request) {
	if err := s.node.RunRandomElectAndBroadcast(); err != nil {
		http.Error(w, "RunRandomElect failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) recvVRFResult(w http.ResponseWriter, r *http.Request) {
	var v VRFResult
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.node.MsgEntrance <- &v
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	resp := struct {
		NodeID   string  `json:"node_id"`
		Chosen   bool    `json:"chosen"`
		Value    float64 `json:"value"`
		Tau      float64 `json:"tau"`
		T        uint64  `json:"t"`
		Context  string  `json:"context"`
		CandSize int     `json:"candidate_size"`

		OnchainAuto       bool   `json:"onchain_auto"`
		OnchainSubmitted  bool   `json:"onchain_submitted"`
		OnchainLastTxHash string `json:"onchain_last_tx"`
		CurrentEpoch      uint64 `json:"current_epoch"`
		AddressBookSize   int    `json:"addressbook_size"`
	}{
		NodeID: s.node.NodeID, Chosen: s.node.VRFChosen, Value: s.node.VRFValue,
		Tau: s.node.Tau, T: s.node.VRF_T, Context: s.node.VRF_Context,
		CandSize: len(s.node.CandidateSet),

		OnchainAuto:       s.node.OnchainAuto,
		OnchainSubmitted:  s.node.OnchainSubmitted,
		OnchainLastTxHash: s.node.OnchainLastTxHash,
		CurrentEpoch:      s.node.CurrentEpoch,
		AddressBookSize:   len(s.node.AddressBook),
	}
	_ = json.NewEncoder(w).Encode(resp)
}
