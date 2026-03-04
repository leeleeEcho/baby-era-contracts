// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ICredentialRegistry {
    // ── Structs ────────────────────────────────────────────────
    struct Credential {
        address issuer;
        address subject;
        bytes32 credentialType; // keccak256("KYC"), keccak256("CREDIT_SCORE"), etc.
        bytes32 claimHash;     // hash of off-chain claim data
        uint64 issuedAt;
        uint64 expiresAt;
    }

    // ── Events ─────────────────────────────────────────────────
    event CredentialIssued(
        bytes32 indexed credentialId,
        address indexed issuer,
        address indexed subject,
        bytes32 credentialType
    );
    event CredentialRevoked(bytes32 indexed credentialId, address indexed issuer);

    // ── Issuance ───────────────────────────────────────────────
    function issueCredential(
        address subject,
        bytes32 credentialType,
        bytes32 claimHash,
        uint64 expiresAt
    ) external returns (bytes32 credentialId);

    // ── Revocation ─────────────────────────────────────────────
    function revokeCredential(bytes32 credentialId) external;

    // ── Queries ────────────────────────────────────────────────
    function getCredential(bytes32 credentialId) external view returns (Credential memory);
    function isCredentialValid(bytes32 credentialId) external view returns (bool);
    function getCredentialsBySubject(address subject) external view returns (bytes32[] memory);
    function getCredentialsByIssuer(address issuer) external view returns (bytes32[] memory);
    function isRevoked(bytes32 credentialId) external view returns (bool);
}
