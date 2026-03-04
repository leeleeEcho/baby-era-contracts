// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IIdentityVerifier} from "./interfaces/IIdentityVerifier.sol";
import {SystemContractBase} from "./abstract/SystemContractBase.sol";
import {DID_REGISTRY_SYSTEM_CONTRACT, CREDENTIAL_REGISTRY_SYSTEM_CONTRACT, ORACLE_HUB_SYSTEM_CONTRACT} from "./Constants.sol";
import {IDIDRegistry} from "./interfaces/IDIDRegistry.sol";
import {ICredentialRegistry} from "./interfaces/ICredentialRegistry.sol";

/// @title IdentityVerifier — BabyDriver Identity Verification Engine
/// @notice System contract at 0x8019. Verifies identity + credentials for compliance.
/// @dev P0: ECDSA mode (credential signature verification).
///      P1: ZK_PLONK mode (zero-knowledge proof verification via boojum).
contract IdentityVerifier is IIdentityVerifier, SystemContractBase {
    // ── Storage ────────────────────────────────────────────────
    VerificationMode private _currentMode;
    mapping(address => bool) private _trustedIssuers;
    mapping(address => mapping(bytes32 => bool)) private _compliance;
    // identity → requirement → isCompliant
    mapping(uint8 => address) private _circuitVerifiers;
    mapping(bytes32 => bool) private _usedProofs;

    // ── Errors ─────────────────────────────────────────────────
    error IssuerNotTrusted(address issuer);
    error IdentityNotActive(address identity);
    error AlreadyTrustedIssuer(address issuer);
    error NotTrustedIssuer(address issuer);
    error CircuitNotRegistered(uint8 circuitType);
    error ProofAlreadyUsed(bytes32 proofHash);
    error InvalidProof();

    // ── Constructor ────────────────────────────────────────────

    // System contracts don't use constructors — state is set at genesis or via admin calls.

    // ── Internal Helpers ───────────────────────────────────────

    function _didRegistry() internal pure returns (IDIDRegistry) {
        return IDIDRegistry(DID_REGISTRY_SYSTEM_CONTRACT);
    }

    function _credentialRegistry() internal pure returns (ICredentialRegistry) {
        return ICredentialRegistry(CREDENTIAL_REGISTRY_SYSTEM_CONTRACT);
    }

    // ── Verification ───────────────────────────────────────────

    /// @notice Verify that an identity has a valid credential of the given type
    ///         issued by a trusted issuer.
    /// @param identity The address to verify.
    /// @param credentialType The required credential type (e.g., keccak256("KYC")).
    /// @return True if the identity has a valid, non-revoked, non-expired credential
    ///         of the specified type from a trusted issuer.
    function verifyIdentity(
        address identity,
        bytes32 credentialType
    ) external view override returns (bool) {
        // Identity must have an active DID
        if (!_didRegistry().isActive(identity)) return false;

        // Check if any credential of this type is valid and from a trusted issuer
        bytes32[] memory credIds = _credentialRegistry().getCredentialsBySubject(identity);
        for (uint256 i = 0; i < credIds.length; i++) {
            if (!_credentialRegistry().isCredentialValid(credIds[i])) continue;

            ICredentialRegistry.Credential memory cred = _credentialRegistry().getCredential(credIds[i]);
            if (cred.credentialType == credentialType && _trustedIssuers[cred.issuer]) {
                return true;
            }
        }
        return false;
    }

    /// @notice Check if an identity meets a specific compliance requirement.
    /// @dev Compliance is set by trusted issuers via setCompliance().
    function checkCompliance(
        address identity,
        bytes32 requirement
    ) external view override returns (bool) {
        if (!_didRegistry().isActive(identity)) return false;
        return _compliance[identity][requirement];
    }

    // ── Compliance Management ──────────────────────────────────

    /// @notice Set compliance status for an identity. Only callable by trusted issuers.
    /// @param identity The identity to update.
    /// @param requirement The compliance requirement (e.g., keccak256("AML_CLEAR")).
    /// @param status Whether the identity meets the requirement.
    function setCompliance(
        address identity,
        bytes32 requirement,
        bool status
    ) external override onlySystemCall {
        if (!_trustedIssuers[msg.sender]) revert IssuerNotTrusted(msg.sender);
        if (!_didRegistry().isActive(identity)) revert IdentityNotActive(identity);

        _compliance[identity][requirement] = status;
        emit ComplianceUpdated(identity, requirement, status);
    }

    // ── Admin ──────────────────────────────────────────────────

    /// @notice Add a trusted credential issuer.
    function addTrustedIssuer(address issuer) external override onlyCallFromBootloader {
        if (_trustedIssuers[issuer]) revert AlreadyTrustedIssuer(issuer);
        _trustedIssuers[issuer] = true;
        emit TrustedIssuerAdded(issuer);
    }

    /// @notice Remove a trusted credential issuer.
    function removeTrustedIssuer(address issuer) external override onlyCallFromBootloader {
        if (!_trustedIssuers[issuer]) revert NotTrustedIssuer(issuer);
        _trustedIssuers[issuer] = false;
        emit TrustedIssuerRemoved(issuer);
    }

    /// @notice Check if an address is a trusted issuer.
    function isTrustedIssuer(address issuer) external view override returns (bool) {
        return _trustedIssuers[issuer];
    }

    /// @notice Change verification mode. Only bootloader (genesis/upgrade).
    function setVerificationMode(VerificationMode mode) external override onlyCallFromBootloader {
        VerificationMode oldMode = _currentMode;
        _currentMode = mode;
        emit VerificationModeChanged(oldMode, mode);
    }

    /// @notice Get current verification mode.
    function currentMode() external view override returns (VerificationMode) {
        return _currentMode;
    }

    // ── ZK Proof Verification ───────────────────────────────────

    /// @notice Verify a ZK proof and set compliance for the identity.
    /// @param identity The address whose compliance will be set on success.
    /// @param circuitType The circuit identifier (0=KYC, 1=Credit, 2=Enterprise).
    /// @param _pA Proof point A.
    /// @param _pB Proof point B.
    /// @param _pC Proof point C.
    /// @param publicInputs Public signals for the proof.
    /// @return True if the proof is valid and compliance was set.
    function verifyZKProof(
        address identity,
        uint8 circuitType,
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[] calldata publicInputs
    ) external override onlySystemCall returns (bool) {
        // Identity must have an active DID
        if (!_didRegistry().isActive(identity)) revert IdentityNotActive(identity);

        // Circuit must be registered
        address verifierAddr = _circuitVerifiers[circuitType];
        if (verifierAddr == address(0)) revert CircuitNotRegistered(circuitType);

        // Replay protection
        bytes32 proofHash = keccak256(abi.encode(_pA, _pB, _pC, publicInputs));
        if (_usedProofs[proofHash]) revert ProofAlreadyUsed(proofHash);

        // Verify the proof via the circuit verifier (staticcall — verifyProof is view)
        (bool ok, bytes memory result) = verifierAddr.staticcall(
            abi.encodeWithSignature(
                "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[])",
                _pA, _pB, _pC, publicInputs
            )
        );
        if (!ok || result.length < 32) revert InvalidProof();
        bool valid = abi.decode(result, (bool));
        if (!valid) revert InvalidProof();

        // Mark proof as used
        _usedProofs[proofHash] = true;

        // Set compliance based on circuit type
        bytes32 complianceKey;
        if (circuitType == 0) {
            complianceKey = keccak256("ZK_KYC_VERIFIED");
        } else if (circuitType == 1) {
            complianceKey = keccak256("ZK_CREDIT_VERIFIED");
        } else if (circuitType == 2) {
            complianceKey = keccak256("ZK_ENTERPRISE_VERIFIED");
        } else {
            complianceKey = keccak256(abi.encodePacked("ZK_CIRCUIT_", _toHexString(circuitType)));
        }
        _compliance[identity][complianceKey] = true;
        emit ComplianceUpdated(identity, complianceKey, true);
        emit ZKProofVerified(identity, circuitType);

        return true;
    }

    /// @notice Register a Groth16 verifier for a circuit type. Only bootloader.
    function setCircuitVerifier(uint8 circuitType, address verifier) external override onlyCallFromBootloader {
        _circuitVerifiers[circuitType] = verifier;
        emit CircuitVerifierSet(circuitType, verifier);
    }

    /// @notice Get the verifier address for a circuit type.
    function getCircuitVerifier(uint8 circuitType) external view override returns (address) {
        return _circuitVerifiers[circuitType];
    }

    // ── Credit Score Queries ────────────────────────────────────

    /// @notice Get personal credit score from OracleHub.
    function getPersonalCreditScore(address identity) external view override returns (uint256) {
        return _getCreditScore(identity, "CREDIT_PERSONAL_");
    }

    /// @notice Get organization credit score from OracleHub.
    function getOrgCreditScore(address identity) external view override returns (uint256) {
        return _getCreditScore(identity, "CREDIT_ORG_");
    }

    /// @notice Get composite credit score from OracleHub.
    function getCompositeCreditScore(address identity) external view override returns (uint256) {
        return _getCreditScore(identity, "CREDIT_COMPOSITE_");
    }

    // ── Internal Helpers ────────────────────────────────────────

    function _getCreditScore(address identity, string memory prefix) internal view returns (uint256) {
        string memory symbol = string(abi.encodePacked(prefix, _toHexString(identity)));
        // staticcall getLatestPrice(string) on OracleHub system contract
        (bool ok, bytes memory data) = address(ORACLE_HUB_SYSTEM_CONTRACT).staticcall(
            abi.encodeWithSignature("getLatestPrice(string)", symbol)
        );
        if (!ok || data.length < 32) return 0;
        (uint256 price,) = abi.decode(data, (uint256, uint256));
        return price;
    }

    function _toHexString(address addr) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes20 value = bytes20(addr);
        bytes memory str = new bytes(42);
        str[0] = "0";
        str[1] = "x";
        for (uint256 i = 0; i < 20; i++) {
            str[2 + i * 2] = alphabet[uint8(value[i] >> 4)];
            str[3 + i * 2] = alphabet[uint8(value[i] & 0x0f)];
        }
        return string(str);
    }

    function _toHexString(uint8 val) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(2);
        str[0] = alphabet[val >> 4];
        str[1] = alphabet[val & 0x0f];
        return string(str);
    }
}
