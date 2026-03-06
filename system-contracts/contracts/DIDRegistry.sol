// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IDIDRegistry} from "./interfaces/IDIDRegistry.sol";
import {SystemContractBase} from "./abstract/SystemContractBase.sol";
import {CREDENTIAL_REGISTRY_SYSTEM_CONTRACT, IDENTITY_VERIFIER_SYSTEM_CONTRACT, L1_MESSENGER_CONTRACT} from "./Constants.sol";
import {IL1Messenger} from "./interfaces/IL1Messenger.sol";

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

    // ── Recovery Storage ─────────────────────────────────────
    struct RecoveryConfig {
        address[] guardians;
        uint8 threshold;
        uint64 timelockDuration;
    }

    struct RecoveryRequestData {
        address newController;
        uint64 initiatedAt;
        uint8 approvalCount;
    }

    mapping(address => RecoveryConfig) private _recoveryConfigs;
    mapping(address => RecoveryRequestData) private _recoveryRequests;
    mapping(address => mapping(address => bool)) private _recoveryApprovals;

    // ── Errors ─────────────────────────────────────────────────
    error DIDAlreadyExists(address identity);
    error DIDNotFound(address identity);
    error DIDNotActive(address identity);
    error NotController(address caller, address controller);
    error DelegateAlreadyExists(address delegate);
    error DelegateNotFound(address delegate);
    error InvalidValidityPeriod();
    error EmptyVerificationMethods();
    error RecoveryNotConfigured(address identity);
    error RecoveryAlreadyPending(address identity);
    error RecoveryNotPending(address identity);
    error NotGuardian(address caller);
    error AlreadyApproved(address guardian);
    error RecoveryNotExecutable();
    error InvalidRecoveryConfig();
    error GuardianIsSelf(address identity);
    error DuplicateGuardian(address guardian);
    error TimelockTooShort();

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

        L1_MESSENGER_CONTRACT.sendToL1(
            abi.encode(uint8(0), msg.sender, verificationMethods, serviceEndpointHash, _nonces[msg.sender])
        );
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

        L1_MESSENGER_CONTRACT.sendToL1(
            abi.encode(uint8(1), msg.sender, verificationMethods, serviceEndpointHash, _nonces[msg.sender])
        );
    }

    /// @notice Deactivate the DID for msg.sender. Irreversible.
    function deactivateDID() external override onlyController(msg.sender) {
        _documents[msg.sender].active = false;
        _documents[msg.sender].updated = uint64(block.timestamp);
        _nonces[msg.sender]++;
        emit DIDDeactivated(msg.sender);

        L1_MESSENGER_CONTRACT.sendToL1(
            abi.encode(uint8(2), msg.sender, _nonces[msg.sender])
        );
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

    // ── Social Recovery ──────────────────────────────────────

    /// @notice Configure social recovery for the caller's DID.
    function setRecovery(
        address[] calldata guardians,
        uint8 threshold,
        uint64 timelockDuration
    ) external override onlyController(msg.sender) {
        if (!_documents[msg.sender].active) revert DIDNotActive(msg.sender);
        if (threshold == 0 || threshold > guardians.length || guardians.length > 7) revert InvalidRecoveryConfig();
        if (timelockDuration < 1 hours) revert TimelockTooShort();

        for (uint256 i = 0; i < guardians.length; i++) {
            if (guardians[i] == msg.sender) revert GuardianIsSelf(msg.sender);
            for (uint256 j = i + 1; j < guardians.length; j++) {
                if (guardians[i] == guardians[j]) revert DuplicateGuardian(guardians[i]);
            }
        }

        _recoveryConfigs[msg.sender] = RecoveryConfig({
            guardians: guardians,
            threshold: threshold,
            timelockDuration: timelockDuration
        });

        _clearRecoveryRequest(msg.sender);
        emit RecoveryConfigured(msg.sender, threshold, uint8(guardians.length));
    }

    /// @notice Initiate a recovery process. Only callable by a guardian.
    function initiateRecovery(
        address identity,
        address newController
    ) external override {
        RecoveryConfig storage config = _recoveryConfigs[identity];
        if (config.guardians.length == 0) revert RecoveryNotConfigured(identity);
        if (_recoveryRequests[identity].initiatedAt != 0) revert RecoveryAlreadyPending(identity);
        if (!_isGuardian(identity, msg.sender)) revert NotGuardian(msg.sender);
        if (newController == address(0)) revert InvalidRecoveryConfig();

        _recoveryRequests[identity] = RecoveryRequestData({
            newController: newController,
            initiatedAt: uint64(block.timestamp),
            approvalCount: 1
        });
        _recoveryApprovals[identity][msg.sender] = true;

        emit RecoveryInitiated(identity, newController, msg.sender);

        L1_MESSENGER_CONTRACT.sendToL1(
            abi.encode(uint8(8), identity, newController, block.timestamp)
        );
    }

    /// @notice Approve an ongoing recovery. Only callable by a guardian.
    function approveRecovery(address identity) external override {
        if (_recoveryRequests[identity].initiatedAt == 0) revert RecoveryNotPending(identity);
        if (!_isGuardian(identity, msg.sender)) revert NotGuardian(msg.sender);
        if (_recoveryApprovals[identity][msg.sender]) revert AlreadyApproved(msg.sender);

        _recoveryApprovals[identity][msg.sender] = true;
        _recoveryRequests[identity].approvalCount++;

        emit RecoveryApproved(identity, msg.sender, _recoveryRequests[identity].approvalCount);
    }

    /// @notice Execute a recovery after threshold approvals and timelock.
    function executeRecovery(address identity) external override {
        RecoveryRequestData storage req = _recoveryRequests[identity];
        RecoveryConfig storage config = _recoveryConfigs[identity];
        if (req.initiatedAt == 0) revert RecoveryNotPending(identity);
        if (req.approvalCount < config.threshold) revert RecoveryNotExecutable();
        if (block.timestamp < req.initiatedAt + config.timelockDuration) revert RecoveryNotExecutable();

        address oldController = _documents[identity].controller;
        address newController = req.newController;

        _documents[identity].controller = newController;
        _documents[identity].updated = uint64(block.timestamp);
        _nonces[identity]++;

        _clearRecoveryRequest(identity);

        emit RecoveryExecuted(identity, oldController, newController);

        L1_MESSENGER_CONTRACT.sendToL1(
            abi.encode(uint8(9), identity, oldController, newController, _nonces[identity])
        );
    }

    /// @notice Cancel an ongoing recovery. Only the current controller can cancel.
    function cancelRecovery() external override onlyController(msg.sender) {
        if (_recoveryRequests[msg.sender].initiatedAt == 0) revert RecoveryNotPending(msg.sender);
        _clearRecoveryRequest(msg.sender);
        emit RecoveryCancelled(msg.sender);
    }

    /// @notice Get recovery configuration for an identity.
    function getRecoveryConfig(address identity) external view override returns (
        address[] memory guardians, uint8 threshold, uint64 timelockDuration
    ) {
        RecoveryConfig storage config = _recoveryConfigs[identity];
        return (config.guardians, config.threshold, config.timelockDuration);
    }

    /// @notice Get the current recovery request for an identity.
    function getRecoveryRequest(address identity) external view override returns (
        address newController, uint64 initiatedAt, uint8 approvalCount, bool executable
    ) {
        RecoveryRequestData storage req = _recoveryRequests[identity];
        RecoveryConfig storage config = _recoveryConfigs[identity];
        bool exec = req.initiatedAt != 0
            && req.approvalCount >= config.threshold
            && block.timestamp >= req.initiatedAt + config.timelockDuration;
        return (req.newController, req.initiatedAt, req.approvalCount, exec);
    }

    // ── Recovery Helpers ─────────────────────────────────────

    function _isGuardian(address identity, address account) internal view returns (bool) {
        RecoveryConfig storage config = _recoveryConfigs[identity];
        for (uint256 i = 0; i < config.guardians.length; i++) {
            if (config.guardians[i] == account) return true;
        }
        return false;
    }

    function _clearRecoveryRequest(address identity) internal {
        RecoveryConfig storage config = _recoveryConfigs[identity];
        for (uint256 i = 0; i < config.guardians.length; i++) {
            _recoveryApprovals[identity][config.guardians[i]] = false;
        }
        delete _recoveryRequests[identity];
    }
}
