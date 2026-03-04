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

    // ── ZK Proof Verification ───────────────────────────────────
    event ZKProofVerified(address indexed identity, uint8 indexed circuitType);
    event CircuitVerifierSet(uint8 indexed circuitType, address verifier);

    function verifyZKProof(
        address identity, uint8 circuitType,
        uint256[2] calldata _pA, uint256[2][2] calldata _pB, uint256[2] calldata _pC,
        uint256[] calldata publicInputs
    ) external returns (bool);
    function setCircuitVerifier(uint8 circuitType, address verifier) external;
    function getCircuitVerifier(uint8 circuitType) external view returns (address);

    // ── Credit Score Queries ────────────────────────────────────
    function getPersonalCreditScore(address identity) external view returns (uint256);
    function getOrgCreditScore(address identity) external view returns (uint256);
    function getCompositeCreditScore(address identity) external view returns (uint256);
}
