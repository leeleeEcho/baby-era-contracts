// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IDIDRegistry} from "./interfaces/IDIDRegistry.sol";
import {SystemContractBase} from "./abstract/SystemContractBase.sol";
import {CREDENTIAL_REGISTRY_SYSTEM_CONTRACT, IDENTITY_VERIFIER_SYSTEM_CONTRACT} from "./Constants.sol";

/// @title DIDRegistry — BabyDriver Decentralized Identity Registry
/// @notice System contract at 0x8017. Manages did:ethr:baby identities.
/// @dev Follows ethr-did-registry pattern adapted for zksync system contracts.
contract DIDRegistry is IDIDRegistry, SystemContractBase {
    // ── Storage ────────────────────────────────────────────────
    mapping(address => DIDDocument) private _documents;
    mapping(address => mapping(address => uint256)) private _delegateExpiry;
    // delegate → identity → expiry timestamp
    mapping(address => address[]) private _delegateList;
    mapping(address => uint256) private _nonces;

    // ── Errors ─────────────────────────────────────────────────
    error DIDAlreadyExists(address identity);
    error DIDNotFound(address identity);
    error DIDNotActive(address identity);
    error NotController(address caller, address controller);
    error DelegateAlreadyExists(address delegate);
    error DelegateNotFound(address delegate);
    error InvalidValidityPeriod();
    error EmptyVerificationMethods();

    // ── Modifiers ──────────────────────────────────────────────
    modifier onlyController(address identity) {
        DIDDocument storage doc = _documents[identity];
        if (doc.controller == address(0)) revert DIDNotFound(identity);
        if (doc.controller != msg.sender) revert NotController(msg.sender, doc.controller);
        _;
    }

    modifier didExists(address identity) {
        if (_documents[identity].controller == address(0)) revert DIDNotFound(identity);
        _;
    }

    modifier didActive(address identity) {
        DIDDocument storage doc = _documents[identity];
        if (doc.controller == address(0)) revert DIDNotFound(identity);
        if (!doc.active) revert DIDNotActive(identity);
        _;
    }

    // ── Identity Management ────────────────────────────────────

    /// @notice Create a new DID for msg.sender.
    /// @param verificationMethods Array of keccak256(pubkey) for this identity.
    /// @param serviceEndpointHash Hash of off-chain service endpoints JSON.
    function createDID(
        bytes32[] calldata verificationMethods,
        bytes32 serviceEndpointHash
    ) external override onlySystemCall {
        if (_documents[msg.sender].controller != address(0)) {
            revert DIDAlreadyExists(msg.sender);
        }
        if (verificationMethods.length == 0) revert EmptyVerificationMethods();

        DIDDocument storage doc = _documents[msg.sender];
        doc.controller = msg.sender;
        doc.created = uint64(block.timestamp);
        doc.updated = uint64(block.timestamp);
        doc.active = true;
        doc.serviceEndpointHash = serviceEndpointHash;
        for (uint256 i = 0; i < verificationMethods.length; i++) {
            doc.verificationMethods.push(verificationMethods[i]);
        }

        _nonces[msg.sender] = 1;
        emit DIDCreated(msg.sender, msg.sender);
    }

    /// @notice Update the DID document for msg.sender.
    function updateDocument(
        bytes32[] calldata verificationMethods,
        bytes32 serviceEndpointHash
    ) external override onlyController(msg.sender) {
        if (!_documents[msg.sender].active) revert DIDNotActive(msg.sender);
        if (verificationMethods.length == 0) revert EmptyVerificationMethods();

        DIDDocument storage doc = _documents[msg.sender];

        // Replace verification methods
        delete doc.verificationMethods;
        for (uint256 i = 0; i < verificationMethods.length; i++) {
            doc.verificationMethods.push(verificationMethods[i]);
        }
        doc.serviceEndpointHash = serviceEndpointHash;
        doc.updated = uint64(block.timestamp);
        _nonces[msg.sender]++;

        emit DIDUpdated(
            msg.sender,
            keccak256(abi.encode(verificationMethods, serviceEndpointHash))
        );
    }

    /// @notice Deactivate the DID for msg.sender. Irreversible.
    function deactivateDID() external override onlyController(msg.sender) {
        _documents[msg.sender].active = false;
        _documents[msg.sender].updated = uint64(block.timestamp);
        _nonces[msg.sender]++;
        emit DIDDeactivated(msg.sender);
    }

    // ── Delegation ─────────────────────────────────────────────

    /// @notice Add a delegate for the caller's DID.
    /// @param delegate Address to delegate to.
    /// @param validity Duration in seconds for which the delegation is valid.
    function addDelegate(
        address delegate,
        uint256 validity
    ) external override onlyController(msg.sender) {
        if (!_documents[msg.sender].active) revert DIDNotActive(msg.sender);
        if (validity == 0) revert InvalidValidityPeriod();

        uint256 expiry = block.timestamp + validity;
        if (_delegateExpiry[msg.sender][delegate] > block.timestamp) {
            // Update existing delegation
            _delegateExpiry[msg.sender][delegate] = expiry;
        } else {
            _delegateExpiry[msg.sender][delegate] = expiry;
            _delegateList[msg.sender].push(delegate);
        }
        _nonces[msg.sender]++;
        emit DelegateAdded(msg.sender, delegate, expiry);
    }

    /// @notice Revoke a delegate.
    function revokeDelegate(
        address delegate
    ) external override onlyController(msg.sender) {
        if (_delegateExpiry[msg.sender][delegate] == 0) revert DelegateNotFound(delegate);
        _delegateExpiry[msg.sender][delegate] = 0;
        _nonces[msg.sender]++;
        emit DelegateRevoked(msg.sender, delegate);
    }

    // ── Queries ────────────────────────────────────────────────

    /// @notice Resolve a DID document.
    function resolveDID(address identity) external view override returns (DIDDocument memory) {
        if (_documents[identity].controller == address(0)) revert DIDNotFound(identity);
        return _documents[identity];
    }

    /// @notice Check if a DID is active.
    function isActive(address identity) external view override returns (bool) {
        DIDDocument storage doc = _documents[identity];
        return doc.controller != address(0) && doc.active;
    }

    /// @notice Check if an address is a valid delegate for an identity.
    function isDelegate(address identity, address delegate) external view override returns (bool) {
        return _delegateExpiry[identity][delegate] > block.timestamp;
    }

    /// @notice Get the current nonce for an identity.
    function getNonce(address identity) external view override returns (uint256) {
        return _nonces[identity];
    }
}
