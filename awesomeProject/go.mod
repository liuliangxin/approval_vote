module awesomeProject

go 1.24.0

toolchain go1.24.1

replace (
	DKG => ../DKG
// 如果 vrf 也想用本地源码，按需加这一行：
// github.com/r2ishiguro/vrf => D:\Dr_document\...\third_party\vrf
//github.com/Consensys/gnark => github.com/consensys/gnark v0.14.0
// 指向你本地的 kryptology 源码根目录（该目录里要有 go.mod: module github.com/coinbase/kryptology）
//github.com/coinbase/kryptology/pkg/bulletproof => D:\golangProjects\pkg\mod\github.com\coinbase\kryptology@v1.8.0\pkg\bulletproof
//github.com/ethereum/go-ethereum => D:\golangProjects\pkg\mod\github.com\ethereum\go-ethereum@v1.16.3
)

require (
	github.com/coinbase/kryptology v1.8.0
	github.com/consensys/gnark v0.14.0
	github.com/consensys/gnark-crypto v0.19.2
	github.com/ethereum/go-ethereum v1.10.26
	github.com/gtank/merlin v0.1.1
	github.com/pkg/errors v0.9.1
	github.com/r2ishiguro/vrf v0.0.0-20180716233122-192de52975eb
	golang.org/x/crypto v0.41.0
)

require (
	filippo.io/edwards25519 v1.0.0-rc.1 // indirect
	github.com/StackExchange/wmi v1.2.1 // indirect
	github.com/bits-and-blooms/bitset v1.24.0 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/btcsuite/btcd v0.21.0-beta.0.20201114000516-e9c7a5ac6401 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.2.0 // indirect
	github.com/bwesterb/go-ristretto v1.2.0 // indirect
	github.com/deckarep/golang-set v1.8.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/google/pprof v0.0.0-20250820193118-f64d9cf942d6 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/gorilla/websocket v1.4.2 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mimoo/StrobeGo v0.0.0-20181016162300-f8f6d4d2b643 // indirect
	github.com/rjeczalik/notify v0.9.1 // indirect
	github.com/ronanh/intcomp v1.1.1 // indirect
	github.com/rs/zerolog v1.34.0 // indirect
	github.com/shirou/gopsutil v3.21.4-0.20210419000835-c7a38de76ee5+incompatible // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/yahoo/coname v0.0.0-20170609175141-84592ddf8673 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	gopkg.in/natefinch/npipe.v2 v2.0.0-20160621034901-c1b8fa8bdcce // indirect
)
