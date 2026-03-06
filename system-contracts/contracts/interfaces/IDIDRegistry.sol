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

    // ── Social Recovery Events ────────────────────────────────
    event RecoveryConfigured(address indexed identity, uint8 threshold, uint8 guardianCount);
    event RecoveryInitiated(address indexed identity, address indexed newController, address indexed initiator);
    event RecoveryApproved(address indexed identity, address indexed guardian, uint8 approvalCount);
    event RecoveryExecuted(address indexed identity, address indexed oldController, address indexed newController);
    event RecoveryCancelled(address indexed identity);

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

    // ── Social Recovery ──────────────────────────────────────
    function setRecovery(address[] calldata guardians, uint8 threshold, uint64 timelockDuration) external;
    function initiateRecovery(address identity, address newController) external;
    function approveRecovery(address identity) external;
    function executeRecovery(address identity) external;
    function cancelRecovery() external;
    function getRecoveryConfig(address identity) external view returns (address[] memory guardians, uint8 threshold, uint64 timelockDuration);
    function getRecoveryRequest(address identity) external view returns (address newController, uint64 initiatedAt, uint8 approvalCount, bool executable);
}
