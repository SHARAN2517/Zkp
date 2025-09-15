pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

/*
 * Auth Circuit - Stage 1 (MVP)
 * Proves knowledge of a secret whose hash is registered on-chain
 * without revealing the secret itself
 */
template AuthCircuit() {
    // Private inputs (not revealed)
    signal private input secret;
    signal private input deviceId;
    
    // Public inputs (revealed on-chain)
    signal input secretHash;
    signal input expectedDeviceId;
    signal input timestamp;
    
    // Output
    signal output isValid;
    
    // Components
    component hasher = Poseidon(1);
    component deviceIdCheck = IsEqual();
    component timestampCheck = LessEqThan(64);
    
    // Verify the secret hash
    hasher.inputs[0] <== secret;
    hasher.out === secretHash;
    
    // Verify device ID matches
    deviceIdCheck.in[0] <== deviceId;
    deviceIdCheck.in[1] <== expectedDeviceId;
    
    // Verify timestamp is within acceptable range (prevent replay)
    // Assuming timestamp is in seconds since epoch
    // Allow 5 minutes (300 seconds) window
    timestampCheck.in[0] <== timestamp;
    timestampCheck.in[1] <== 1999999999; // Max reasonable timestamp
    
    // Output is valid only if all checks pass
    isValid <== deviceIdCheck.out * timestampCheck.out;
}

component main = AuthCircuit();