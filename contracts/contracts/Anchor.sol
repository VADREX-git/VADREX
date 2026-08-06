// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title Append-only anchor registry for one institution's audit log.
/// @notice One instance is deployed per institution, owned by that institution's anchoring wallet.
///         It stores nothing but the five fields below - no patient data, no consent identifiers,
///         no image references - and keeps every past record so a verifier can compare any two
///         anchors. batchId and anchoredAt are assigned here rather than by the caller, so the
///         ordering and timing of anchors cannot be backdated by whoever submits them.
contract Anchor is Ownable {
    struct AnchorRecord {
        uint64 batchId;
        bytes32 rootHash;
        uint64 treeSize;
        bytes32 mapRoot;
        uint64 anchoredAt;
    }

    mapping(uint64 => AnchorRecord) private anchors;
    uint64 private count;
    uint64 private lastTreeSize;

    event AnchorRegistered(
        uint64 indexed batchId,
        bytes32 rootHash,
        uint64 treeSize,
        bytes32 mapRoot,
        uint64 anchoredAt
    );

    constructor() Ownable(msg.sender) {}

    function registerAnchor(bytes32 rootHash, uint64 treeSize, bytes32 mapRoot) external onlyOwner {
        // A strictly growing treeSize is what makes the log append-only on chain: an institution
        // cannot anchor a shortened log to erase entries it has already committed to.
        require(treeSize > lastTreeSize, "treeSize must increase");

        uint64 batchId = count + 1;
        uint64 anchoredAt = uint64(block.timestamp);

        anchors[batchId] = AnchorRecord({
            batchId: batchId,
            rootHash: rootHash,
            treeSize: treeSize,
            mapRoot: mapRoot,
            anchoredAt: anchoredAt
        });

        count = batchId;
        lastTreeSize = treeSize;

        emit AnchorRegistered(batchId, rootHash, treeSize, mapRoot, anchoredAt);
    }

    function getAnchor(uint64 batchId) external view returns (AnchorRecord memory) {
        require(batchId != 0 && batchId <= count, "anchor not found");
        return anchors[batchId];
    }

    function latestAnchor() external view returns (AnchorRecord memory) {
        require(count != 0, "anchor not found");
        return anchors[count];
    }

    function anchorCount() external view returns (uint64) {
        return count;
    }
}
