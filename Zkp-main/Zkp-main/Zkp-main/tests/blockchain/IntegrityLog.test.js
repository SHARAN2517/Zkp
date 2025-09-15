const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("IntegrityLog", function () {
  let deviceRegistry, integrityLog;
  let owner, verifier, user1;
  let deviceId, dataHash, proofHash;

  beforeEach(async function () {
    [owner, verifier, user1] = await ethers.getSigners();
    
    // Deploy DeviceRegistry
    const DeviceRegistry = await ethers.getContractFactory("DeviceRegistry");
    deviceRegistry = await DeviceRegistry.deploy();
    await deviceRegistry.waitForDeployment();

    // Deploy IntegrityLog
    const IntegrityLog = await ethers.getContractFactory("IntegrityLog");
    integrityLog = await IntegrityLog.deploy(deviceRegistry.target);
    await integrityLog.waitForDeployment();

    // Set verifier
    await integrityLog.setVerifierContract(verifier.address);

    // Register a test device
    deviceId = ethers.encodeBytes32String("device001");
    const firmwareHash = ethers.keccak256(ethers.toUtf8Bytes("firmware-v1.0"));
    const secretHash = ethers.keccak256(ethers.toUtf8Bytes("secret123"));
    await deviceRegistry.connect(user1).registerDevice(deviceId, firmwareHash, secretHash);

    // Generate test hashes
    dataHash = ethers.keccak256(ethers.toUtf8Bytes("sensor-data"));
    proofHash = ethers.keccak256(ethers.toUtf8Bytes("zkp-proof"));
  });

  describe("Data Logging", function () {
    it("Should log data successfully by verifier", async function () {
      await expect(
        integrityLog.connect(verifier).logData(deviceId, dataHash, proofHash, true)
      )
        .to.emit(integrityLog, "DataLogged")
        .withArgs(deviceId, dataHash, proofHash, true);

      const logs = await integrityLog.getDeviceLogs(deviceId, 0, 10);
      expect(logs).to.have.length(1);
      expect(logs[0].deviceId).to.equal(deviceId);
      expect(logs[0].dataHash).to.equal(dataHash);
      expect(logs[0].proofHash).to.equal(proofHash);
      expect(logs[0].verified).to.be.true;
    });

    it("Should not allow unauthorized logging", async function () {
      await expect(
        integrityLog.connect(user1).logData(deviceId, dataHash, proofHash, true)
      ).to.be.revertedWith("Not authorized");
    });

    it("Should not log for inactive device", async function () {
      await deviceRegistry.connect(user1).deactivateDevice(deviceId);
      
      await expect(
        integrityLog.connect(verifier).logData(deviceId, dataHash, proofHash, true)
      ).to.be.revertedWith("Device not active");
    });

    it("Should prevent replay attacks", async function () {
      await integrityLog.connect(verifier).logData(deviceId, dataHash, proofHash, true);
      
      await expect(
        integrityLog.connect(verifier).logData(deviceId, dataHash, proofHash, true)
      ).to.be.revertedWith("Proof already processed");
    });
  });

  describe("Batch Logging", function () {
    it("Should log batch successfully", async function () {
      const merkleRoot = ethers.keccak256(ethers.toUtf8Bytes("merkle-root"));
      const ipfsHash = "QmTest123";
      
      await expect(
        integrityLog.connect(verifier).logBatch(merkleRoot, 5, ipfsHash)
      )
        .to.emit(integrityLog, "BatchLogged")
        .withArgs(merkleRoot, 5, ipfsHash);

      const batches = await integrityLog.getBatchLogs(0, 10);
      expect(batches).to.have.length(1);
      expect(batches[0].merkleRoot).to.equal(merkleRoot);
      expect(batches[0].batchSize).to.equal(5);
      expect(batches[0].ipfsHash).to.equal(ipfsHash);
    });
  });

  describe("Alert System", function () {
    it("Should trigger alert for high values", async function () {
      const alertType = "HIGH_HEART_RATE";
      const highValue = 120; // Above default threshold of 100
      
      await expect(
        integrityLog.connect(verifier).triggerAlert(deviceId, alertType, dataHash, highValue)
      )
        .to.emit(integrityLog, "AlertTriggered")
        .withArgs(deviceId, alertType, dataHash);
    });

    it("Should not trigger alert for values below threshold", async function () {
      const alertType = "HIGH_HEART_RATE";
      const lowValue = 80; // Below default threshold of 100
      
      await expect(
        integrityLog.connect(verifier).triggerAlert(deviceId, alertType, dataHash, lowValue)
      ).to.be.revertedWith("Value below threshold");
    });

    it("Should allow admin to update alert thresholds", async function () {
      const alertType = "HIGH_HEART_RATE";
      const newThreshold = 110;
      
      await integrityLog.connect(owner).updateAlertThreshold(alertType, newThreshold);
      
      const threshold = await integrityLog.alertThresholds(alertType);
      expect(threshold).to.equal(newThreshold);
    });
  });

  describe("Statistics", function () {
    beforeEach(async function () {
      // Log some test data
      await integrityLog.connect(verifier).logData(deviceId, dataHash, proofHash, true);
      
      const merkleRoot = ethers.keccak256(ethers.toUtf8Bytes("merkle-root"));
      await integrityLog.connect(verifier).logBatch(merkleRoot, 3, "QmTest123");
    });

    it("Should return correct statistics", async function () {
      const [totalLogs, totalBatches, totalDevices] = await integrityLog.getStats();
      
      expect(totalLogs).to.equal(1);
      expect(totalBatches).to.equal(1);
      expect(totalDevices).to.equal(1);
    });
  });
});