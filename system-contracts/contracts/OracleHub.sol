// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IOracleHub} from "./interfaces/IOracleHub.sol";
import {SystemContractBase} from "./abstract/SystemContractBase.sol";
import {SystemContractHelper} from "./libraries/SystemContractHelper.sol";
import {ORACLE_HUB_SYSTEM_CONTRACT} from "./Constants.sol";

/**
 * @title OracleHub
 * @notice BabyDriver native Oracle — L2 system contract at address 0x8016.
 *
 * Price data is injected by the operator via synthetic L2 transaction at the start of each L1 Batch.
 * All DApps can read prices via view calls at zero gas cost.
 *
 * Design decisions:
 *   - Uses bytes32 symbol hashes instead of string keys (gas efficient in system contract context)
 *   - Packs price + timestamp into a single struct to minimize storage slots
 *   - Only the operator can update prices (onlyOperator)
 *   - Admin operations require system call privileges
 */
contract OracleHub is IOracleHub, SystemContractBase {
    // ==================== Storage ====================

    /// @notice Price data keyed by symbol hash (e.g., keccak256("ETH/USD"))
    mapping(bytes32 => PriceData) private _prices;

    /// @notice Set of supported symbol hashes
    mapping(bytes32 => bool) public isSymbolSupported;

    /// @notice List of supported symbol hashes (for enumeration)
    bytes32[] private _supportedSymbols;

    /// @notice Maximum age of a price before it's considered stale (seconds)
    uint256 public stalenessThreshold;

    /// @notice Maximum allowed price deviation from previous value (basis points)
    uint256 public deviationThreshold;

    /// @notice Minimum number of sources required for a valid price update
    uint8 public minSourceCount;

    // ==================== Constants ====================

    uint256 private constant BPS_DENOMINATOR = 10_000;

    // ==================== Operator ====================

    /// @notice Operator address authorized to call batchUpdatePrices
    address public operator;

    /// @notice Only the operator can call this function
    modifier onlyOperator() {
        require(msg.sender == operator, "OracleHub: not operator");
        _;
    }

    // ==================== Initialization ====================

    /// @notice Called once to set initial config. One-time only (stalenessThreshold guard).
    /// @dev No access control beyond the one-time guard — in production, called during
    ///      genesis via bootloader force-deployment. Post-genesis init uses governor EOA.
    function initialize(
        bytes32[] calldata symbolHashes,
        uint256 _stalenessThreshold,
        uint256 _deviationThreshold,
        uint8 _minSourceCount
    ) external {
        // Guard: only init once
        require(stalenessThreshold == 0, "OracleHub: already initialized");
        require(_stalenessThreshold > 0, "OracleHub: zero staleness");

        stalenessThreshold = _stalenessThreshold;
        deviationThreshold = _deviationThreshold;
        minSourceCount = _minSourceCount;

        for (uint256 i = 0; i < symbolHashes.length; i++) {
            isSymbolSupported[symbolHashes[i]] = true;
            _supportedSymbols.push(symbolHashes[i]);
            emit SymbolAdded(symbolHashes[i]);
        }

        // Set initial operator to the transaction origin (deployer/bootloader)
        operator = tx.origin;
        emit OperatorUpdated(tx.origin);
    }

    // ==================== Price Updates (Operator Only) ====================

    /// @inheritdoc IOracleHub
    /// @dev Called by the operator at the start of each L1 Batch via synthetic L2 transaction.
    function batchUpdatePrices(
        bytes32[] calldata symbolHashes,
        uint128[] calldata prices,
        uint64[] calldata confidences,
        uint8[] calldata sourceCounts
    ) external onlyOperator {
        uint256 len = symbolHashes.length;
        require(
            len == prices.length && len == confidences.length && len == sourceCounts.length,
            "OracleHub: length mismatch"
        );

        for (uint256 i = 0; i < len; i++) {
            _updatePrice(symbolHashes[i], prices[i], confidences[i], sourceCounts[i]);
        }
    }

    // ==================== Price Queries (Free View Calls) ====================

    /// @inheritdoc IOracleHub
    function getLatestPrice(bytes32 symbolHash) external view returns (uint128 price, uint128 timestamp) {
        PriceData storage pd = _prices[symbolHash];
        require(pd.timestamp > 0, "OracleHub: no price");
        return (pd.price, pd.timestamp);
    }

    /// @inheritdoc IOracleHub
    function getPriceData(bytes32 symbolHash) external view returns (PriceData memory) {
        PriceData storage pd = _prices[symbolHash];
        require(pd.timestamp > 0, "OracleHub: no price");
        return pd;
    }

    /// @inheritdoc IOracleHub
    function isPriceFresh(bytes32 symbolHash) external view returns (bool) {
        PriceData storage pd = _prices[symbolHash];
        if (pd.timestamp == 0) return false;
        return (block.timestamp - pd.timestamp) <= stalenessThreshold;
    }

    // ==================== Admin (System Call or Operator) ====================

    /// @inheritdoc IOracleHub
    /// @dev Callable by system call (admin) or operator for runtime symbol registration.
    function addSymbol(bytes32 symbolHash) external {
        require(_isSystemCallOrOperator(), "OracleHub: unauthorized");
        require(!isSymbolSupported[symbolHash], "OracleHub: already supported");
        isSymbolSupported[symbolHash] = true;
        _supportedSymbols.push(symbolHash);
        emit SymbolAdded(symbolHash);
    }

    /// @inheritdoc IOracleHub
    /// @dev Batch version of addSymbol. Skips already-supported symbols (no revert).
    function batchAddSymbols(bytes32[] calldata symbolHashes) external {
        require(_isSystemCallOrOperator(), "OracleHub: unauthorized");
        require(symbolHashes.length > 0, "OracleHub: empty array");
        for (uint256 i = 0; i < symbolHashes.length; i++) {
            bytes32 h = symbolHashes[i];
            if (!isSymbolSupported[h]) {
                isSymbolSupported[h] = true;
                _supportedSymbols.push(h);
                emit SymbolAdded(h);
            }
        }
    }

    // ==================== Admin (System Call Only) ====================

    /// @inheritdoc IOracleHub
    function removeSymbol(bytes32 symbolHash) external onlySystemCall {
        require(isSymbolSupported[symbolHash], "OracleHub: not supported");
        isSymbolSupported[symbolHash] = false;
        // Swap-and-pop removal
        uint256 len = _supportedSymbols.length;
        for (uint256 i = 0; i < len; i++) {
            if (_supportedSymbols[i] == symbolHash) {
                _supportedSymbols[i] = _supportedSymbols[len - 1];
                _supportedSymbols.pop();
                break;
            }
        }
        emit SymbolRemoved(symbolHash);
    }

    /// @inheritdoc IOracleHub
    function setConfig(
        uint256 _stalenessThreshold,
        uint256 _deviationThreshold,
        uint8 _minSourceCount
    ) external onlySystemCall {
        require(_stalenessThreshold > 0 && _stalenessThreshold <= 3600, "OracleHub: invalid staleness");
        require(_deviationThreshold > 0 && _deviationThreshold <= 5000, "OracleHub: invalid deviation");
        require(_minSourceCount > 0 && _minSourceCount <= 10, "OracleHub: invalid source count");

        stalenessThreshold = _stalenessThreshold;
        deviationThreshold = _deviationThreshold;
        minSourceCount = _minSourceCount;

        emit ConfigUpdated(_stalenessThreshold, _deviationThreshold, _minSourceCount);
    }

    /// @notice Set the operator address. Only callable by system call (admin).
    function setOperator(address _operator) external onlySystemCall {
        require(_operator != address(0), "OracleHub: zero operator");
        operator = _operator;
        emit OperatorUpdated(_operator);
    }

    // ==================== View Helpers ====================

    /// @notice Returns all supported symbol hashes.
    function getSupportedSymbols() external view returns (bytes32[] memory) {
        return _supportedSymbols;
    }

    /// @notice Returns the number of supported symbols.
    function getSupportedSymbolCount() external view returns (uint256) {
        return _supportedSymbols.length;
    }

    // ==================== Internal ====================

    /// @notice Returns true if the caller is a system call or the operator.
    function _isSystemCallOrOperator() internal view returns (bool) {
        return SystemContractHelper.isSystemCall()
            || SystemContractHelper.isSystemContract(msg.sender)
            || msg.sender == operator;
    }

    function _updatePrice(
        bytes32 symbolHash,
        uint128 price,
        uint64 confidence,
        uint8 sourceCount
    ) internal {
        require(price > 0, "OracleHub: zero price");
        require(isSymbolSupported[symbolHash], "OracleHub: unsupported symbol");
        require(sourceCount >= minSourceCount, "OracleHub: insufficient sources");

        PriceData storage existing = _prices[symbolHash];

        // Anomaly detection: check deviation against last known price
        if (existing.price > 0 && deviationThreshold > 0) {
            uint256 oldPrice = uint256(existing.price);
            uint256 newPrice = uint256(price);
            uint256 diff = oldPrice > newPrice ? oldPrice - newPrice : newPrice - oldPrice;
            uint256 avg = (oldPrice + newPrice) / 2;
            uint256 deviation = (diff * BPS_DENOMINATOR) / avg;

            if (deviation > deviationThreshold) {
                emit AnomalyDetected(symbolHash, price, existing.price, deviation);
                // In system contract context, we skip the update rather than revert
                // to avoid blocking batch processing
                return;
            }
        }

        existing.price = price;
        existing.timestamp = uint128(block.timestamp);
        existing.confidence = confidence;
        existing.sourceCount = sourceCount;

        emit PriceUpdated(symbolHash, price, uint128(block.timestamp), sourceCount);
    }
}
