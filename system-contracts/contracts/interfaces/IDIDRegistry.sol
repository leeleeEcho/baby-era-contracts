// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IDIDRegistry {
    // ── Structs ────────────────────────────────────────────────
    struct DIDDocument {
        bytes32[] verificationMethods; // keccak256 of each public key
        address controller;            // address that controls this DID
        uint64 created;
        uint64 updated;
        bool active;
        bytes32 serviceEndpointHash;   // hash of off-chain service endpoints JSON
    }

    // ── Events ─────────────────────────────────────────────────
    event DIDCreated(address indexed identity, address controller);
    event DIDUpdated(address indexed identity, bytes32 documentHash);
    event DIDDeactivated(address indexed identity);
    event DelegateAdded(address indexed identity, address indexed delegate, uint256 validity);
    event DelegateRevoked(address indexed identity, address indexed delegate);

    // ── Identity Management ────────────────────────────────────
    function createDID(bytes32[] calldata verificationMethods, bytes32 serviceEndpointHash) external;
    function updateDocument(bytes32[] calldata verificationMethods, bytes32 serviceEndpointHash) external;
    function deactivateDID() external;

    // ── Delegation ─────────────────────────────────────────────
    function addDelegate(address delegate, uint256 validity) external;
    function revokeDelegate(address delegate) external;

    // ── Queries (view) ─────────────────────────────────────────
    function resolveDID(address identity) external view returns (DIDDocument memory);
    function isActive(address identity) external view returns (bool);
    function isDelegate(address identity, address delegate) external view returns (bool);
    function getNonce(address identity) external view returns (uint256);
}
