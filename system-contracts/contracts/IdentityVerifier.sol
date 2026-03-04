// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IIdentityVerifier} from "./interfaces/IIdentityVerifier.sol";
import {SystemContractBase} from "./abstract/SystemContractBase.sol";
import {DID_REGISTRY_SYSTEM_CONTRACT, CREDENTIAL_REGISTRY_SYSTEM_CONTRACT} from "./Constants.sol";
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

    // ── Errors ─────────────────────────────────────────────────
    error IssuerNotTrusted(address issuer);
    error IdentityNotActive(address identity);
    error AlreadyTrustedIssuer(address issuer);
    error NotTrustedIssuer(address issuer);

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
}
