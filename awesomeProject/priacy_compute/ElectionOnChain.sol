// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice 外部 zk 验证器接口（示例）
/// 建议把 hE, hT, m, d, k 等作为公共输入；proof 为 Groth16/PLONK 证明
interface IVerifier {
    function verifyProof(
        bytes calldata proof,
        bytes32 hE,
        bytes32 hT,
        uint256 m,
        uint256 d,
        uint256 k
    ) external view returns (bool ok);
}

contract ElectionOnChain {
    // ============ 事件 ============
    event EpochOpened(uint256 indexed epoch, uint64 submitStart, uint64 submitEnd, uint64 disputeEnd);
    event ResultSubmitted(uint256 indexed epoch, address indexed aggregator, bytes32 hE, bytes32 hT);
    event ResultAccepted(uint256 indexed epoch, address indexed aggregator, bytes32 hE, bytes32 hT);
    event Finalized(uint256 indexed epoch, address[] committee);
    event Challenged(uint256 indexed epoch, address indexed challenger, string reason);
    event Slashed(uint256 indexed epoch, address indexed aggregator, uint256 amount);
    event Reopened(uint256 indexed epoch);

    // ============ 配置/依赖 ============
    IVerifier public immutable verifier;
    address public owner;
    uint256 public minBond; // 聚合者质押下限（可被罚没）
    uint256 public currentEpoch;

    // ============ 储值/押金 ============
    mapping(address => uint256) public bondOf;

    // ============ Epoch 窗口状态 ============
    struct Window {
        uint64 submitStart; // 结果提交期起
        uint64 submitEnd;   // 结果提交期止
        uint64 disputeEnd;  // 争议期止（> submitEnd）
    }
    struct Pending {
        bool    exists;
        address aggregator;
        bytes32 hE;      // Merkle root of committee E
        bytes32 hT;      // Merkle root of counts T
        bytes    proof;  // zk proof (opaque to contract)
        bytes32  commitAHint; // 可选：绑定聚合承诺（扩展位）
        bytes32  commitBHint;
    }

    enum EpochStatus { CLOSED, OPEN, SUBMITTED, ACCEPTED, CHALLENGED, FINALIZED }
    struct EpochState {
        EpochStatus status;
        Window      win;
        Pending     pending;
        address[]   committee;   // 通过验证后落库的新一届委员会地址
        bytes32     committeeRoot; // hE
        bytes32     countsRoot;    // hT
        uint256     m; // |S|
        uint256     d; // 哈希数
        uint256     k; // Top-K
        address     acceptedAggregator;
    }

    mapping(uint256 => EpochState) public epochs;

    // ============ 访问控制 ============
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    constructor(IVerifier _verifier, uint256 _minBond) {
        verifier = _verifier;
        owner = msg.sender;
        minBond = _minBond;
    }

    // ============ 质押 ============
    function bond() external payable {
        require(msg.value > 0, "no value");
        bondOf[msg.sender] += msg.value;
    }

    // ============ 创世委员会/Genesis ============
    function setGenesisCommittee(address[] calldata addrs) external onlyOwner {
        require(currentEpoch == 0, "already started");
        epochs[0].committee = addrs;
        epochs[0].committeeRoot = _merkleRootAddresses(addrs);
        epochs[0].status = EpochStatus.FINALIZED;
        emit Finalized(0, addrs);
    }

    // ============ 打开新的 Epoch ============
    function openEpoch(
        uint256 epoch,
        uint64 submitStart,
        uint64 submitEnd,
        uint64 disputeEnd,
        uint256 m, uint256 d, uint256 k
    ) external onlyOwner {
        require(epochs[epoch].status == EpochStatus.CLOSED, "epoch exists");
        require(submitStart < submitEnd && submitEnd < disputeEnd, "bad window");
        epochs[epoch].status = EpochStatus.OPEN;
        epochs[epoch].win = Window(submitStart, submitEnd, disputeEnd);
        epochs[epoch].m = m; epochs[epoch].d = d; epochs[epoch].k = k;
        currentEpoch = epoch;
        emit EpochOpened(epoch, submitStart, submitEnd, disputeEnd);
    }

    // ============ 提交结果（hE, hT, 证明），并携带委员会地址列表以便链上立即可读 ============
    function submitResult(
        uint256 epoch,
        bytes32 hE,
        bytes32 hT,
        bytes calldata proof,
        address[] calldata committeeAddrs,
        bytes32 commitAHint,
        bytes32 commitBHint
    ) external {
        EpochState storage st = epochs[epoch];
        require(st.status == EpochStatus.OPEN || st.status == EpochStatus.CHALLENGED, "not open");
        _requireInSubmitWindow(st.win);
        require(bondOf[msg.sender] >= minBond, "insufficient bond");
        require(committeeAddrs.length == st.k, "committee len != k");
        // 校验链上计算的 hE 等于传入 hE
        bytes32 calcHE = _merkleRootAddresses(committeeAddrs);
        require(calcHE == hE, "hE mismatch");

        // 先保存 pending（仅允许一份处于 SUBMITTED；若想允许多候选提交，可扩展为队列+选择最先通过的）
        st.pending = Pending({
            exists: true,
            aggregator: msg.sender,
            hE: hE,
            hT: hT,
            proof: proof,
            commitAHint: commitAHint,
            commitBHint: commitBHint
        });

        st.status = EpochStatus.SUBMITTED;
        emit ResultSubmitted(epoch, msg.sender, hE, hT);

        // 立即调用 zk 验证器
        bool ok = verifier.verifyProof(proof, hE, hT, st.m, st.d, st.k);
        require(ok, "zk verify fail");

        // 通过：接受为本轮结果，进入 ACCEPTED，写入可读的委员会地址与根
        st.status = EpochStatus.ACCEPTED;
        st.committee = committeeAddrs;
        st.committeeRoot = hE;
        st.countsRoot = hT;
        st.acceptedAggregator = msg.sender;
        emit ResultAccepted(epoch, msg.sender, hE, hT);
    }

    // ============ 在争议期结束后“最终确定” ============
    function finalize(uint256 epoch) external {
        EpochState storage st = epochs[epoch];
        require(st.status == EpochStatus.ACCEPTED, "not accepted");
        require(block.timestamp > st.win.disputeEnd, "in dispute window");
        st.status = EpochStatus.FINALIZED;
        emit Finalized(epoch, st.committee);
    }

    // ============ 争议/挑战机制 ============
    /// @notice 挑战需要在争议期内发起；若成功，罚没聚合者押金并重开本轮
    function challenge(uint256 epoch, string calldata reason) external {
        EpochState storage st = epochs[epoch];
        require(st.status == EpochStatus.ACCEPTED || st.status == EpochStatus.SUBMITTED, "no target");
        require(block.timestamp <= st.win.disputeEnd, "dispute over");

        // 在占位版里，我们无法链上重算 vrf/票据，只做“流程挑战”
        // 真实系统可增加：提交反证、双重提交检测、或由治理合约/仲裁器回调结果
        // 这里直接进入 CHALLENGED 并 slash
        address agg = st.acceptedAggregator != address(0) ? st.acceptedAggregator : st.pending.aggregator;
        require(agg != address(0), "no aggregator");

        uint256 slashAmt = _slash(agg);
        emit Slashed(epoch, agg, slashAmt);

        st.status = EpochStatus.CHALLENGED;
        emit Challenged(epoch, msg.sender, reason);

        // 清理 pending，允许在同一窗口内重提；若窗口已近结束，可由 owner 延长/重开
        delete st.pending;
        emit Reopened(epoch);
    }

    // ============ 读取接口 ============
    function getCommittee(uint256 epoch) external view returns (address[] memory) {
        return epochs[epoch].committee;
    }

    function getRoots(uint256 epoch) external view returns (bytes32 hE, bytes32 hT) {
        EpochState storage st = epochs[epoch];
        return (st.committeeRoot, st.countsRoot);
    }

    function statusOf(uint256 epoch) external view returns (EpochStatus) {
        return epochs[epoch].status;
    }

    // ============ 管理：调整参数 ============
    function setMinBond(uint256 v) external onlyOwner { minBond = v; }
    function transferOwnership(address n) external onlyOwner { owner = n; }

    // ============ 内部工具 ============
    function _requireInSubmitWindow(Window memory w) internal view {
        uint64 nowTs = uint64(block.timestamp);
        require(nowTs >= w.submitStart && nowTs <= w.submitEnd, "not in submit window");
    }

    function _slash(address a) internal returns (uint256) {
        uint256 amt = bondOf[a];
        if (amt > 0) {
            bondOf[a] = 0;
            // 将罚没款留在合约（可改为发送到国库/保险库）
            // payable(owner).transfer(amt); // 若要立即转走
        }
        return amt;
    }

    // 使用 keccak 作为 Merkle 聚合（偶数：一对一对；奇数：最后一个复制自身）
    function _merkleRoot(bytes32[] memory leaves) internal pure returns (bytes32) {
        require(leaves.length > 0, "no leaves");
        while (leaves.length > 1) {
            uint256 n = leaves.length;
            uint256 m = (n + 1) / 2;
            bytes32[] memory next = new bytes32[](m);
            for (uint256 i = 0; i < m; i++) {
                bytes32 a = leaves[2*i];
                bytes32 b = (2*i + 1 < n) ? leaves[2*i + 1] : leaves[2*i];
                next[i] = keccak256(abi.encodePacked(a, b));
            }
            leaves = next;
        }
        return leaves[0];
    }

    function _merkleRootAddresses(address[] memory addrs) internal pure returns (bytes32) {
        bytes32[] memory leaves = new bytes32[](addrs.length);
        for (uint256 i = 0; i < addrs.length; i++) {
            leaves[i] = keccak256(abi.encodePacked(addrs[i]));
        }
        return _merkleRoot(leaves);
    }
}
