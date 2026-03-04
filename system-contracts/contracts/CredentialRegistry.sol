// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ICredentialRegistry} from "./interfaces/ICredentialRegistry.sol";
import {SystemContractBase} from "./abstract/SystemContractBase.sol";
import {DID_REGISTRY_SYSTEM_CONTRACT} from "./Constants.sol";
import {IDIDRegistry} from "./interfaces/IDIDRegistry.sol";

/// @title CredentialRegistry — BabyDriver Verifiable Credential Registry
/// @notice System contract at 0x8018. Manages Verifiable Credentials issuance and revocation.
/// @dev Issuer must have an active DID in DIDRegistry. Subject must have an active DID.
contract CredentialRegistry is ICredentialRegistry, SystemContractBase {
    // ── Storage ────────────────────────────────────────────────
    mapping(bytes32 => Credential) private _credentials;
    mapping(bytes32 => bool) private _revoked;
    mapping(address => bytes32[]) private _issuedByIssuer;
    mapping(address => bytes32[]) private _heldBySubject;

    // ── Errors ─────────────────────────────────────────────────
    error CredentialNotFound(bytes32 credentialId);
    error CredentialAlreadyRevoked(bytes32 credentialId);
    error NotCredentialIssuer(address caller, address issuer);
    error IssuerDIDNotActive(address issuer);
    error SubjectDIDNotActive(address subject);
    error InvalidExpiry();
    error EmptyClaimHash();

    // ── Internal Helpers ───────────────────────────────────────

    function _didRegistry() internal pure returns (IDIDRegistry) {
        return IDIDRegistry(DID_REGISTRY_SYSTEM_CONTRACT);
    }

    function _computeCredentialId(
        address issuer,
        address subject,
        bytes32 credentialType,
        bytes32 claimHash,
        uint64 issuedAt
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(issuer, subject, credentialType, claimHash, issuedAt));
    }

    // ── Issuance ───────────────────────────────────────────────

    /// @notice Issue a new Verifiable Credential.
    /// @dev Both issuer (msg.sender) and subject must have active DIDs.
    /// @param subject The credential holder.
    /// @param credentialType Type hash (e.g., keccak256("KYC")).
    /// @param claimHash Hash of off-chain claim data.
    /// @param expiresAt Expiration timestamp. 0 = never expires.
    /// @return credentialId The unique credential identifier.
    function issueCredential(
        address subject,
        bytes32 credentialType,
        bytes32 claimHash,
        uint64 expiresAt
    ) external override onlySystemCall returns (bytes32 credentialId) {
        if (claimHash == bytes32(0)) revert EmptyClaimHash();
        if (expiresAt != 0 && expiresAt <= block.timestamp) revert InvalidExpiry();

        // Verify both issuer and subject have active DIDs
        if (!_didRegistry().isActive(msg.sender)) revert IssuerDIDNotActive(msg.sender);
        if (!_didRegistry().isActive(subject)) revert SubjectDIDNotActive(subject);

        uint64 issuedAt = uint64(block.timestamp);
        credentialId = _computeCredentialId(msg.sender, subject, credentialType, claimHash, issuedAt);

        _credentials[credentialId] = Credential({
            issuer: msg.sender,
            subject: subject,
            credentialType: credentialType,
            claimHash: claimHash,
            issuedAt: issuedAt,
            expiresAt: expiresAt
        });

        _issuedByIssuer[msg.sender].push(credentialId);
        _heldBySubject[subject].push(credentialId);

        emit CredentialIssued(credentialId, msg.sender, subject, credentialType);
    }

    // ── Revocation ─────────────────────────────────────────────

    /// @notice Revoke a credential. Only the original issuer can revoke.
    function revokeCredential(bytes32 credentialId) external override onlySystemCall {
        Credential storage cred = _credentials[credentialId];
        if (cred.issuer == address(0)) revert CredentialNotFound(credentialId);
        if (cred.issuer != msg.sender) revert NotCredentialIssuer(msg.sender, cred.issuer);
        if (_revoked[credentialId]) revert CredentialAlreadyRevoked(credentialId);

        _revoked[credentialId] = true;
        emit CredentialRevoked(credentialId, msg.sender);
    }

    // ── Queries ────────────────────────────────────────────────

    /// @notice Get a credential by ID.
    function getCredential(bytes32 credentialId) external view override returns (Credential memory) {
        Credential storage cred = _credentials[credentialId];
        if (cred.issuer == address(0)) revert CredentialNotFound(credentialId);
        return cred;
    }

    /// @notice Check if a credential is currently valid (not revoked, not expired, issuer DID active).
    function isCredentialValid(bytes32 credentialId) external view override returns (bool) {
        Credential storage cred = _credentials[credentialId];
        if (cred.issuer == address(0)) return false;
        if (_revoked[credentialId]) return false;
        if (cred.expiresAt != 0 && cred.expiresAt <= block.timestamp) return false;
        // Issuer DID must still be active for credential to be valid
        if (!_didRegistry().isActive(cred.issuer)) return false;
        return true;
    }

    /// @notice Get all credential IDs held by a subject.
    function getCredentialsBySubject(address subject) external view override returns (bytes32[] memory) {
        return _heldBySubject[subject];
    }

    /// @notice Get all credential IDs issued by an issuer.
    function getCredentialsByIssuer(address issuer) external view override returns (bytes32[] memory) {
        return _issuedByIssuer[issuer];
    }

    /// @notice Check if a credential has been revoked.
    function isRevoked(bytes32 credentialId) external view override returns (bool) {
        return _revoked[credentialId];
    }
}
