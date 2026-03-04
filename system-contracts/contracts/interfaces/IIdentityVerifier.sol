// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IIdentityVerifier {
    // ── Enums ──────────────────────────────────────────────────
    enum VerificationMode { ECDSA, ZK_PLONK }

    // ── Events ─────────────────────────────────────────────────
    event ComplianceUpdated(address indexed identity, bytes32 indexed requirement, bool status);
    event VerificationModeChanged(VerificationMode oldMode, VerificationMode newMode);
    event TrustedIssuerAdded(address indexed issuer);
    event TrustedIssuerRemoved(address indexed issuer);

    // ── Verification ───────────────────────────────────────────
    function verifyIdentity(address identity, bytes32 credentialType) external view returns (bool);
    function checkCompliance(address identity, bytes32 requirement) external view returns (bool);

    // ── Compliance Management ──────────────────────────────────
    function setCompliance(address identity, bytes32 requirement, bool status) external;

    // ── Admin ──────────────────────────────────────────────────
    function addTrustedIssuer(address issuer) external;
    function removeTrustedIssuer(address issuer) external;
    function isTrustedIssuer(address issuer) external view returns (bool);
    function setVerificationMode(VerificationMode mode) external;
    function currentMode() external view returns (VerificationMode);
}
