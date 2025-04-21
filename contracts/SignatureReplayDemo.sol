// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

// ====== VULNERABLE CONTRACT (NO SALT) ======
contract VulnerableContract is EIP712 {
    bytes32 private constant _MESSAGE_HASH = keccak256("Message(string content)");
    
    constructor(string memory name, string memory version) 
        EIP712(name, version) {}

    function verifyMessage(
        string memory content, 
        bytes memory signature
    ) public view returns (address) {
        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(_MESSAGE_HASH, keccak256(bytes(content))))
        );
        return ECDSA.recover(digest, signature);
    }
}

// ====== SECURE CONTRACT (WITH SALT) ======
contract SecureContract is EIP712 {
    bytes32 private constant _MESSAGE_HASH = keccak256("Message(string content)");
    bytes32 private immutable _salt;
    bytes32 private immutable _hashedName;
    bytes32 private immutable _hashedVersion;
    
    constructor(string memory name, string memory version, bytes32 salt) 
        EIP712(name, version) {
        _salt = salt;
        _hashedName = keccak256(bytes(name));
        _hashedVersion = keccak256(bytes(version));
    }

    function _domainSeparatorWithSalt() internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            _hashedName,
            _hashedVersion,
            block.chainid,
            address(this),
            _salt
        ));
    }

    function verifyMessage(
        string memory content, 
        bytes memory signature
    ) public view returns (address) {
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            _domainSeparatorWithSalt(),
            keccak256(abi.encode(_MESSAGE_HASH, keccak256(bytes(content))))
        ));
        return ECDSA.recover(digest, signature);
    }
}

// ====== DEMO CONTRACT (TEST REPLAY ATTACK) ======
contract SignatureReplayDemo {
    using ECDSA for bytes32;
    
    // Test replay on VulnerableContract
    function testVulnerableReplay(
        address vulnA, 
        address vulnB, 
        string memory message, 
        bytes memory signature
    ) public view returns (bool) {
        address recoveredA = VulnerableContract(vulnA).verifyMessage(message, signature);
        address recoveredB = VulnerableContract(vulnB).verifyMessage(message, signature);
        
        // Condition: Both contracts should recover the same address (replay works)
        return (recoveredA == recoveredB && recoveredA != address(0));
    }
    
    // Test replay on SecureContract
    function testSecureReplay(
        address secureA, 
        address secureB, 
        string memory message, 
        bytes memory signature
    ) public view returns (bool) {
        // Check if signature works on original contract (should succeed)
        address recoveredA = SecureContract(secureA).verifyMessage(message, signature);
        require(recoveredA != address(0), "Signature invalid for ContractA");
        
        // Check if signature works on another contract (should fail)
        try SecureContract(secureB).verifyMessage(message, signature) returns (address recoveredB) {
            return (recoveredB == address(0)); // Returns true if replay fails
        } catch {
            return true; // If call reverts, replay failed (secure)
        }
    }
}