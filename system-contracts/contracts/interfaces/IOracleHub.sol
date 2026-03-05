// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IOracleHub
 * @notice BabyDriver native Oracle system contract interface.
 *         Provides on-chain price feeds updated by the operator at each batch.
 *         All DApps read for free (view calls).
 */
interface IOracleHub {
    struct PriceData {
        uint128 price;       // 18 decimals
        uint128 timestamp;   // packed with price to save storage slots
        uint64 confidence;   // basis points (e.g., 50 = 0.50%)
        uint8 sourceCount;
    }

    // --- Events ---
    event PriceUpdated(bytes32 indexed symbolHash, uint128 price, uint128 timestamp, uint8 sourceCount);
    event AnomalyDetected(bytes32 indexed symbolHash, uint128 newPrice, uint128 oldPrice, uint256 deviationBps);
    event SymbolAdded(bytes32 indexed symbolHash);
    event SymbolRemoved(bytes32 indexed symbolHash);
    event ConfigUpdated(uint256 stalenessThreshold, uint256 deviationThreshold, uint8 minSourceCount);
    event OperatorUpdated(address indexed operator);

    // --- Price Updates (operator only) ---
    function batchUpdatePrices(
        bytes32[] calldata symbolHashes,
        uint128[] calldata prices,
        uint64[] calldata confidences,
        uint8[] calldata sourceCounts
    ) external;

    // --- Price Queries (view, free for DApps) ---
    function getLatestPrice(bytes32 symbolHash) external view returns (uint128 price, uint128 timestamp);
    function getPriceData(bytes32 symbolHash) external view returns (PriceData memory);
    function isPriceFresh(bytes32 symbolHash) external view returns (bool);

    // --- Admin (system call only) ---
    function addSymbol(bytes32 symbolHash) external;
    function removeSymbol(bytes32 symbolHash) external;
    function setConfig(uint256 stalenessThreshold, uint256 deviationThreshold, uint8 minSourceCount) external;
    function setOperator(address _operator) external;
    function operator() external view returns (address);
}
