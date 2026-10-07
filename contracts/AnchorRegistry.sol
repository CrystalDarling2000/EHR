// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AnchorRegistry -- public-chain side of the HyL-EHR hybrid ledger.
/// @notice Stores one commitment per epoch of the private ledger. It never
///         sees patient data, identities or record hashes: only two Merkle
///         roots and the block range they cover.
contract AnchorRegistry {
    struct Anchor {
        bytes32 ledgerRoot;   // Merkle root over the private block hashes
        bytes32 consentRoot;  // Merkle root over the consent table
        uint64 firstHeight;
        uint64 lastHeight;
        uint64 timestamp;
        uint8 trigger;        // 0 score, 1 critical event, 2 timeout
    }

    address public immutable consortium;
    uint64 public epoch;
    uint64 public lastHeight;
    bool private started;
    bytes32 public chainHash;                 // hash chain over all anchors
    mapping(uint64 => Anchor) public anchors;

    event Anchored(uint64 indexed epoch, bytes32 ledgerRoot, bytes32 consentRoot,
                   uint64 firstHeight, uint64 lastHeight, uint8 trigger);

    constructor() {
        consortium = msg.sender;
    }

    modifier onlyConsortium() {
        require(msg.sender == consortium, "not consortium");
        _;
    }

    function _advance(bytes32 ledgerRoot, bytes32 consentRoot, uint64 first, uint64 last)
        private returns (uint64 e)
    {
        require(first <= last, "bad range");
        require(started ? first == lastHeight + 1 : first == 0, "gap in history");
        started = true;
        e = epoch + 1;
        epoch = e;
        lastHeight = last;
        chainHash = sha256(abi.encodePacked(chainHash, ledgerRoot, consentRoot, first, last));
    }

    /// Full variant: the anchor is kept in contract storage, so other
    /// contracts (and verifyBlock below) can read it.
    function anchor(bytes32 ledgerRoot, bytes32 consentRoot, uint64 first, uint64 last,
                    uint8 trigger) external onlyConsortium {
        uint64 e = _advance(ledgerRoot, consentRoot, first, last);
        anchors[e] = Anchor(ledgerRoot, consentRoot, first, last, uint64(block.timestamp), trigger);
        emit Anchored(e, ledgerRoot, consentRoot, first, last, trigger);
    }

    /// Compact variant: only the running hash chain is stored; the roots
    /// live in the event log, which light clients can still prove against.
    function anchorCompact(bytes32 ledgerRoot, bytes32 consentRoot, uint64 first, uint64 last,
                           uint8 trigger) external onlyConsortium {
        uint64 e = _advance(ledgerRoot, consentRoot, first, last);
        emit Anchored(e, ledgerRoot, consentRoot, first, last, trigger);
    }

    /// Second hop of the dual-ledger proof: is `blockHash` one of the
    /// private blocks committed in epoch `e`?
    function verifyBlock(uint64 e, bytes32 blockHash, uint256 index, bytes32[] calldata path)
        external view returns (bool)
    {
        bytes32 node = sha256(abi.encodePacked(bytes1(0x00), blockHash));
        for (uint256 i = 0; i < path.length; i++) {
            node = (index & 1 == 1)
                ? sha256(abi.encodePacked(bytes1(0x01), path[i], node))
                : sha256(abi.encodePacked(bytes1(0x01), node, path[i]));
            index >>= 1;
        }
        return node == anchors[e].ledgerRoot;
    }
}
