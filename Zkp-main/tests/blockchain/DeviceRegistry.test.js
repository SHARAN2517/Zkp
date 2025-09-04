const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("DeviceRegistry", function () {
  let deviceRegistry;
  let owner, user1, user2;
  let deviceId, firmwareHash, secretHash;

  beforeEach(async function () {
    [owner, user1, user2] = await ethers.getSigners();
    
    const DeviceRegistry = await ethers.getContractFactory("DeviceRegistry");
    deviceRegistry = await DeviceRegistry.deploy();
    await deviceRegistry.waitForDeployment();

    // Generate test data
    deviceId = ethers.encodeBytes32String("device001");
    firmwareHash = ethers.keccak256(ethers.toUtf8Bytes("firmware-v1.0"));
    secretHash = ethers.keccak256(ethers.toUtf8Bytes("secret123"));
  });

  describe("Device Registration", function () {
    it("Should register a device successfully", async function () {
      await expect(
        deviceRegistry.connect(user1).registerDevice(deviceId, firmwareHash, secretHash)
      )
        .to.emit(deviceRegistry, "DeviceRegistered")
        .withArgs(deviceId, user1.address, firmwareHash, (timestamp) => timestamp > 0);

      const device = await deviceRegistry.getDevice(deviceId);
      expect(device.owner).to.equal(user1.address);
      expect(device.deviceId).to.equal(deviceId);
      expect(device.firmwareHash).to.equal(firmwareHash);
      expect(device.secretHash).to.equal(secretHash);
      expect(device.isActive).to.be.true;
    });

    it("Should not allow duplicate device registration", async function () {
      await deviceRegistry.connect(user1).registerDevice(deviceId, firmwareHash, secretHash);
      
      await expect(
        deviceRegistry.connect(user2).registerDevice(deviceId, firmwareHash, secretHash)
      ).to.be.revertedWith("Device already registered");
    });

    it("Should not allow registration with invalid parameters", async function () {
      const zeroBytes = ethers.ZeroHash;
      
      await expect(
        deviceRegistry.connect(user1).registerDevice(zeroBytes, firmwareHash, secretHash)
      ).to.be.revertedWith("Invalid device ID");

      await expect(
        deviceRegistry.connect(user1).registerDevice(deviceId, zeroBytes, secretHash)
      ).to.be.revertedWith("Invalid firmware hash");

      await expect(
        deviceRegistry.connect(user1).registerDevice(deviceId, firmwareHash, zeroBytes)
      ).to.be.revertedWith("Invalid secret hash");
    });
  });

  describe("Device Management", function () {
    beforeEach(async function () {
      await deviceRegistry.connect(user1).registerDevice(deviceId, firmwareHash, secretHash);
    });

    it("Should update firmware hash by owner", async function () {
      const newFirmwareHash = ethers.keccak256(ethers.toUtf8Bytes("firmware-v2.0"));
      
      await expect(
        deviceRegistry.connect(user1).updateFirmware(deviceId, newFirmwareHash)
      )
        .to.emit(deviceRegistry, "DeviceUpdated")
        .withArgs(deviceId, newFirmwareHash, (timestamp) => timestamp > 0);

      const device = await deviceRegistry.getDevice(deviceId);
      expect(device.firmwareHash).to.equal(newFirmwareHash);
    });

    it("Should not allow non-owner to update firmware", async function () {
      const newFirmwareHash = ethers.keccak256(ethers.toUtf8Bytes("firmware-v2.0"));
      
      await expect(
        deviceRegistry.connect(user2).updateFirmware(deviceId, newFirmwareHash)
      ).to.be.revertedWith("Only device owner can perform this action");
    });

    it("Should deactivate device by owner", async function () {
      await expect(
        deviceRegistry.connect(user1).deactivateDevice(deviceId)
      )
        .to.emit(deviceRegistry, "DeviceDeactivated")
        .withArgs(deviceId, (timestamp) => timestamp > 0);

      const device = await deviceRegistry.getDevice(deviceId);
      expect(device.isActive).to.be.false;
      expect(await deviceRegistry.isDeviceActive(deviceId)).to.be.false;
    });

    it("Should allow admin to deactivate any device", async function () {
      await expect(
        deviceRegistry.connect(owner).deactivateDevice(deviceId)
      )
        .to.emit(deviceRegistry, "DeviceDeactivated")
        .withArgs(deviceId, (timestamp) => timestamp > 0);

      const device = await deviceRegistry.getDevice(deviceId);
      expect(device.isActive).to.be.false;
    });
  });

  describe("Device Queries", function () {
    beforeEach(async function () {
      // Register multiple devices
      for (let i = 0; i < 3; i++) {
        const id = ethers.encodeBytes32String(`device00${i}`);
        const fw = ethers.keccak256(ethers.toUtf8Bytes(`firmware-v1.${i}`));
        const secret = ethers.keccak256(ethers.toUtf8Bytes(`secret${i}`));
        await deviceRegistry.connect(user1).registerDevice(id, fw, secret);
      }
    });

    it("Should return devices by owner", async function () {
      const devices = await deviceRegistry.getDevicesByOwner(user1.address);
      expect(devices).to.have.length(3);
    });

    it("Should return all devices with pagination", async function () {
      const devices = await deviceRegistry.getAllDevices(0, 2);
      expect(devices).to.have.length(2);
    });

    it("Should return correct total device count", async function () {
      const totalDevices = await deviceRegistry.totalDevices();
      expect(totalDevices).to.equal(3n);
    });

    it("Should return secret hash for active device", async function () {
      const id = ethers.encodeBytes32String("device000");
      const expectedSecret = ethers.keccak256(ethers.toUtf8Bytes("secret0"));
      const actualSecret = await deviceRegistry.getSecretHash(id);
      expect(actualSecret).to.equal(expectedSecret);
    });
  });
});