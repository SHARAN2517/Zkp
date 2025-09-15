const hre = require("hardhat");

async function main() {
  console.log("Starting deployment...");
  
  // Get the contract factories
  const DeviceRegistry = await hre.ethers.getContractFactory("DeviceRegistry");
  const IntegrityLog = await hre.ethers.getContractFactory("IntegrityLog");
  const ZKPVerifier = await hre.ethers.getContractFactory("ZKPVerifier");

  // Deploy DeviceRegistry first
  console.log("Deploying DeviceRegistry...");
  const deviceRegistry = await DeviceRegistry.deploy();
  await deviceRegistry.waitForDeployment();
  console.log("DeviceRegistry deployed to:", deviceRegistry.target);

  // Deploy ZKPVerifier with DeviceRegistry address
  console.log("Deploying ZKPVerifier...");
  const zkpVerifier = await ZKPVerifier.deploy(deviceRegistry.target);
  await zkpVerifier.waitForDeployment();
  console.log("ZKPVerifier deployed to:", zkpVerifier.target);

  // Deploy IntegrityLog with DeviceRegistry address
  console.log("Deploying IntegrityLog...");
  const integrityLog = await IntegrityLog.deploy(deviceRegistry.target);
  await integrityLog.waitForDeployment();
  console.log("IntegrityLog deployed to:", integrityLog.target);

  // Set IntegrityLog address in ZKPVerifier
  console.log("Setting IntegrityLog address in ZKPVerifier...");
  await zkpVerifier.setIntegrityLog(integrityLog.target);
  console.log("IntegrityLog address set in ZKPVerifier");

  // Set ZKPVerifier address in IntegrityLog
  console.log("Setting ZKPVerifier address in IntegrityLog...");
  await integrityLog.setVerifierContract(zkpVerifier.target);
  console.log("ZKPVerifier address set in IntegrityLog");

  // Save deployment addresses
  const network = await hre.ethers.provider.getNetwork();
  const deploymentInfo = {
    network: hre.network.name,
    chainId: Number(network.chainId),
    contracts: {
      DeviceRegistry: deviceRegistry.target,
      ZKPVerifier: zkpVerifier.target,
      IntegrityLog: integrityLog.target
    },
    timestamp: new Date().toISOString()
  };

  const fs = require('fs');
  fs.writeFileSync(
    './deployment-info.json',
    JSON.stringify(deploymentInfo, null, 2)
  );

  console.log("\n=== Deployment Complete ===");
  console.log("DeviceRegistry:", deviceRegistry.target);
  console.log("ZKPVerifier:", zkpVerifier.target);
  console.log("IntegrityLog:", integrityLog.target);
  console.log("Network:", hre.network.name);
  console.log("Deployment info saved to deployment-info.json");

  // Verify contracts on testnet
  if (hre.network.name !== "hardhat" && hre.network.name !== "localhost") {
    console.log("\nWaiting for block confirmations...");
    await deviceRegistry.deployTransaction.wait(5);
    await zkpVerifier.deployTransaction.wait(5);
    await integrityLog.deployTransaction.wait(5);

    console.log("Verifying contracts on Etherscan...");
    
    try {
      await hre.run("verify:verify", {
        address: deviceRegistry.target,
        constructorArguments: [],
      });
      console.log("DeviceRegistry verified");
    } catch (error) {
      console.log("DeviceRegistry verification failed:", error.message);
    }

    try {
      await hre.run("verify:verify", {
        address: zkpVerifier.target,
        constructorArguments: [deviceRegistry.target],
      });
      console.log("ZKPVerifier verified");
    } catch (error) {
      console.log("ZKPVerifier verification failed:", error.message);
    }

    try {
      await hre.run("verify:verify", {
        address: integrityLog.target,
        constructorArguments: [deviceRegistry.target],
      });
      console.log("IntegrityLog verified");
    } catch (error) {
      console.log("IntegrityLog verification failed:", error.message);
    }
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });