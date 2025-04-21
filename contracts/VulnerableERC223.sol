// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableERC223 {
    mapping(address => uint256) public balanceOf;
    mapping(address => bool) public frozenAccount;
    mapping(address => uint256) public unlockUnixTime;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Transfer(address indexed from, address indexed to, uint256 value, bytes data);

    constructor() {
        balanceOf[msg.sender] = 1000000 * 10**18; // Mint initial supply to deployer
    }

    function isContract(address _addr) private view returns (bool) {
        uint32 size;
        assembly {
            size := extcodesize(_addr)
        }
        return (size > 0);
    }

    function transferToAddress(address _to, uint256 _value, bytes memory _data) private returns (bool) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        emit Transfer(msg.sender, _to, _value, _data);
        return true;
    }


    function transfer(address _to, uint _value, bytes memory _data, string memory _custom_fallback) public returns (bool) {
        require(_value > 0
                    && frozenAccount[msg.sender] == false
                    && frozenAccount[_to] == false
                    && block.timestamp > unlockUnixTime[msg.sender]
                    && block.timestamp > unlockUnixTime[_to]);
    
        if (isContract(_to)) {
            balanceOf[msg.sender] -= _value;
            balanceOf[_to] += _value;
            
            // Critical fix: Add gas and handle failure
            (bool success, ) = _to.call{gas: 200000}(
                abi.encodeWithSelector(
                    bytes4(keccak256(bytes(_custom_fallback))),
                    msg.sender,
                    _value,
                    _data
                )
            );
            require(success, "Callback failed"); // Remove this line if you want to continue even if callback fails
            
            emit Transfer(msg.sender, _to, _value, _data);
            return true;
        }else {
            return transferToAddress(_to, _value, _data);
        }
    }
}