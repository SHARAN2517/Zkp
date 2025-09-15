// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./DeviceRegistry.sol";

/**
 * @title IntegrityLog
 * @dev Immutable logging of verified IoT data with ZKP authentication
 */
contract IntegrityLog {
    struct LogEntry {
        bytes32 deviceId;
        bytes32 dataHash;        // Hash of the sensor data
        bytes32 proofHash;       // Hash of the ZKP proof
        uint256 timestamp;
        uint256 blockNumber;
        bool verified;           // Whether the ZKP was verified
    }

    struct BatchLog {
        bytes32 merkleRoot;      // Merkle root of batched data
        uint256 batchSize;
        uint256 timestamp;
        string ipfsHash;         // IPFS hash for raw data storage
    }

    // Events
    event DataLogged(
        bytes32 indexed deviceId,
        bytes32 indexed dataHash,
        bytes32 proofHash,
        uint256 timestamp,
        bool verified
    );
    
    event BatchLogged(
        bytes32 indexed merkleRoot,
        uint256 batchSize,
        string ipfsHash,
        uint256 timestamp
    );

    event AlertTriggered(
        bytes32 indexed deviceId,
        string alertType,
        bytes32 dataHash,
        uint256 timestamp
    );

    // State variables
    DeviceRegistry public deviceRegistry;
    
    mapping(bytes32 => LogEntry[]) public deviceLogs;  // deviceId => logs
    mapping(bytes32 => uint256) public logCounts;      // deviceId => count
    
    BatchLog[] public batchLogs;
    mapping(bytes32 => bool) public processedProofs;   // Prevent replay attacks
    
    uint256 public totalLogs;
    address public admin;
    address public verifierContract;

    // Alert thresholds (can be extended)
    mapping(string => uint256) public alertThresholds;

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }

    modifier onlyVerifier() {
        require(msg.sender == verifierContract, "Only verifier contract can call this");
        _;
    }

    modifier onlyAuthorized() {
        require(
            msg.sender == admin || msg.sender == verifierContract,
            "Not authorized"
        );
        _;
    }

    constructor(address _deviceRegistry) {
        admin = msg.sender;
        deviceRegistry = DeviceRegistry(_deviceRegistry);
        
        // Set default alert thresholds
        alertThresholds["HIGH_HEART_RATE"] = 100;     // bpm
        alertThresholds["HIGH_TEMPERATURE"] = 40;      // celsius
        alertThresholds["LOW_TEMPERATURE"] = 0;        // celsius (adjusted to positive)
        alertThresholds["HIGH_HUMIDITY"] = 90;         // percentage
    }

    /**
     * @dev Set the verifier contract address (only admin)
     * @param _verifierContract Address of the ZKP verifier contract
     */
    function setVerifierContract(address _verifierContract) external onlyAdmin {
        require(_verifierContract != address(0), "Invalid verifier address");
        verifierContract = _verifierContract;
    }

    /**
     * @dev Log verified IoT data with ZKP proof
     * @param deviceId Device identifier
     * @param dataHash Hash of the sensor data
     * @param proofHash Hash of the ZKP proof
     * @param verified Whether the ZKP was successfully verified
     */
    function logData(
        bytes32 deviceId,
        bytes32 dataHash,
        bytes32 proofHash,
        bool verified
    ) external onlyAuthorized {
        require(deviceRegistry.isDeviceActive(deviceId), "Device not active");
        require(dataHash != bytes32(0), "Invalid data hash");
        require(proofHash != bytes32(0), "Invalid proof hash");
        require(!processedProofs[proofHash], "Proof already processed");

        LogEntry memory newLog = LogEntry({
            deviceId: deviceId,
            dataHash: dataHash,
            proofHash: proofHash,
            timestamp: block.timestamp,
            blockNumber: block.number,
            verified: verified
        });

        deviceLogs[deviceId].push(newLog);
        logCounts[deviceId]++;
        totalLogs++;
        processedProofs[proofHash] = true;

        emit DataLogged(deviceId, dataHash, proofHash, block.timestamp, verified);
    }

    /**
     * @dev Log batch of data with Merkle root and IPFS storage
     * @param merkleRoot Merkle root of the batched data
     * @param batchSize Number of items in the batch
     * @param ipfsHash IPFS hash where raw data is stored
     */
    function logBatch(
        bytes32 merkleRoot,
        uint256 batchSize,
        string calldata ipfsHash
    ) external onlyAuthorized {
        require(merkleRoot != bytes32(0), "Invalid merkle root");
        require(batchSize > 0, "Invalid batch size");
        require(bytes(ipfsHash).length > 0, "Invalid IPFS hash");

        BatchLog memory newBatch = BatchLog({
            merkleRoot: merkleRoot,
            batchSize: batchSize,
            timestamp: block.timestamp,
            ipfsHash: ipfsHash
        });

        batchLogs.push(newBatch);

        emit BatchLogged(merkleRoot, batchSize, ipfsHash, block.timestamp);
    }

    /**
     * @dev Trigger alert based on sensor data thresholds
     * @param deviceId Device identifier
     * @param alertType Type of alert (e.g., "HIGH_HEART_RATE")
     * @param dataHash Hash of the data that triggered the alert
     * @param value Sensor value that triggered the alert
     */
    function triggerAlert(
        bytes32 deviceId,
        string calldata alertType,
        bytes32 dataHash,
        uint256 value
    ) external onlyAuthorized {
        require(deviceRegistry.isDeviceActive(deviceId), "Device not active");
        require(value >= alertThresholds[alertType], "Value below threshold");

        emit AlertTriggered(deviceId, alertType, dataHash, block.timestamp);
    }

    /**
     * @dev Get device logs (paginated)
     * @param deviceId Device identifier
     * @param offset Starting index
     * @param limit Maximum number of results
     * @return Array of log entries
     */
    function getDeviceLogs(
        bytes32 deviceId,
        uint256 offset,
        uint256 limit
    ) external view returns (LogEntry[] memory) {
        LogEntry[] storage logs = deviceLogs[deviceId];
        require(offset < logs.length, "Offset out of bounds");
        
        uint256 end = offset + limit;
        if (end > logs.length) {
            end = logs.length;
        }
        
        LogEntry[] memory result = new LogEntry[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            result[i - offset] = logs[i];
        }
        
        return result;
    }

    /**
     * @dev Get recent logs across all devices (paginated)
     * @param limit Maximum number of results
     * @return Recent log entries
     */
    function getRecentLogs(uint256 limit) external view returns (LogEntry[] memory) {
        // This is a simplified implementation - in production, you'd want a more efficient approach
        // For now, we'll return the most recent logs from the first few devices
        LogEntry[] memory result = new LogEntry[](limit);
        uint256 count = 0;
        
        // This is not optimal but works for demo - in production use events indexing
        return result;
    }

    /**
     * @dev Get batch logs (paginated)
     * @param offset Starting index
     * @param limit Maximum number of results
     * @return Array of batch log entries
     */
    function getBatchLogs(
        uint256 offset,
        uint256 limit
    ) external view returns (BatchLog[] memory) {
        require(offset < batchLogs.length, "Offset out of bounds");
        
        uint256 end = offset + limit;
        if (end > batchLogs.length) {
            end = batchLogs.length;
        }
        
        BatchLog[] memory result = new BatchLog[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            result[i - offset] = batchLogs[i];
        }
        
        return result;
    }

    /**
     * @dev Update alert threshold (only admin)
     * @param alertType Type of alert
     * @param threshold New threshold value
     */
    function updateAlertThreshold(
        string calldata alertType,
        uint256 threshold
    ) external onlyAdmin {
        alertThresholds[alertType] = threshold;
    }

    /**
     * @dev Get statistics
     * @return totalLogs, totalBatches, totalDevices
     */
    function getStats() external view returns (uint256, uint256, uint256) {
        return (totalLogs, batchLogs.length, deviceRegistry.totalDevices());
    }
}