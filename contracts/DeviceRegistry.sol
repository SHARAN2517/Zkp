// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title DeviceRegistry
 * @dev Registry for IoT devices with ZKP-based authentication
 */
contract DeviceRegistry {
    struct Device {
        address owner;
        bytes32 deviceId;
        bytes32 firmwareHash;
        bytes32 secretHash; // Hash of the secret used for ZKP
        uint256 registrationTime;
        bool isActive;
    }

    // Events
    event DeviceRegistered(
        bytes32 indexed deviceId,
        address indexed owner,
        bytes32 firmwareHash,
        uint256 timestamp
    );
    
    event DeviceUpdated(
        bytes32 indexed deviceId,
        bytes32 newFirmwareHash,
        uint256 timestamp
    );
    
    event DeviceDeactivated(
        bytes32 indexed deviceId,
        uint256 timestamp
    );

    // State variables
    mapping(bytes32 => Device) public devices;
    mapping(address => bytes32[]) public ownerDevices;
    bytes32[] public allDeviceIds;
    
    uint256 public totalDevices;
    address public admin;

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }

    modifier onlyDeviceOwner(bytes32 deviceId) {
        require(devices[deviceId].owner == msg.sender, "Only device owner can perform this action");
        _;
    }

    modifier deviceExists(bytes32 deviceId) {
        require(devices[deviceId].owner != address(0), "Device does not exist");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /**
     * @dev Register a new IoT device
     * @param deviceId Unique identifier for the device
     * @param firmwareHash Hash of the device firmware
     * @param secretHash Hash of the secret used for ZKP authentication
     */
    function registerDevice(
        bytes32 deviceId,
        bytes32 firmwareHash,
        bytes32 secretHash
    ) external {
        require(devices[deviceId].owner == address(0), "Device already registered");
        require(deviceId != bytes32(0), "Invalid device ID");
        require(firmwareHash != bytes32(0), "Invalid firmware hash");
        require(secretHash != bytes32(0), "Invalid secret hash");

        Device memory newDevice = Device({
            owner: msg.sender,
            deviceId: deviceId,
            firmwareHash: firmwareHash,
            secretHash: secretHash,
            registrationTime: block.timestamp,
            isActive: true
        });

        devices[deviceId] = newDevice;
        ownerDevices[msg.sender].push(deviceId);
        allDeviceIds.push(deviceId);
        totalDevices++;

        emit DeviceRegistered(deviceId, msg.sender, firmwareHash, block.timestamp);
    }

    /**
     * @dev Update device firmware hash (only by owner)
     * @param deviceId Device identifier
     * @param newFirmwareHash New firmware hash
     */
    function updateFirmware(
        bytes32 deviceId,
        bytes32 newFirmwareHash
    ) external deviceExists(deviceId) onlyDeviceOwner(deviceId) {
        require(newFirmwareHash != bytes32(0), "Invalid firmware hash");
        require(devices[deviceId].isActive, "Device is not active");

        devices[deviceId].firmwareHash = newFirmwareHash;
        
        emit DeviceUpdated(deviceId, newFirmwareHash, block.timestamp);
    }

    /**
     * @dev Deactivate a device (only by owner or admin)
     * @param deviceId Device identifier
     */
    function deactivateDevice(bytes32 deviceId) external deviceExists(deviceId) {
        require(
            devices[deviceId].owner == msg.sender || msg.sender == admin,
            "Only device owner or admin can deactivate"
        );
        require(devices[deviceId].isActive, "Device already inactive");

        devices[deviceId].isActive = false;
        
        emit DeviceDeactivated(deviceId, block.timestamp);
    }

    /**
     * @dev Get device information
     * @param deviceId Device identifier
     * @return Device struct
     */
    function getDevice(bytes32 deviceId) external view returns (Device memory) {
        require(devices[deviceId].owner != address(0), "Device does not exist");
        return devices[deviceId];
    }

    /**
     * @dev Get devices owned by an address
     * @param owner Owner address
     * @return Array of device IDs
     */
    function getDevicesByOwner(address owner) external view returns (bytes32[] memory) {
        return ownerDevices[owner];
    }

    /**
     * @dev Get all registered device IDs (paginated)
     * @param offset Starting index
     * @param limit Maximum number of results
     * @return Array of device IDs
     */
    function getAllDevices(uint256 offset, uint256 limit) external view returns (bytes32[] memory) {
        require(offset < allDeviceIds.length, "Offset out of bounds");
        
        uint256 end = offset + limit;
        if (end > allDeviceIds.length) {
            end = allDeviceIds.length;
        }
        
        bytes32[] memory result = new bytes32[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            result[i - offset] = allDeviceIds[i];
        }
        
        return result;
    }

    /**
     * @dev Verify if device is registered and active
     * @param deviceId Device identifier
     * @return bool True if device is registered and active
     */
    function isDeviceActive(bytes32 deviceId) external view returns (bool) {
        return devices[deviceId].owner != address(0) && devices[deviceId].isActive;
    }

    /**
     * @dev Get secret hash for ZKP verification (used by verifier contract)
     * @param deviceId Device identifier
     * @return bytes32 Secret hash
     */
    function getSecretHash(bytes32 deviceId) external view returns (bytes32) {
        require(devices[deviceId].owner != address(0), "Device does not exist");
        require(devices[deviceId].isActive, "Device is not active");
        return devices[deviceId].secretHash;
    }
}