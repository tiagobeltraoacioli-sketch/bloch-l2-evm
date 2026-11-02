// SPDX-License-Identifier: MIT
// Attacker contract of griefsim.py. Private simulations only. It calls real tokens' approve and allowance.
pragma solidity ^0.8.24;

contract Griefer {
    uint256 public next;
    mapping(uint256 => uint256) public raw;

    receive() external payable {}

    function who(uint256 i) public pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encode(i)))));
    }

    /// New allowance slots on a token, for addresses nobody controls. Needs no balance of the token.
    function fillApprove(address token, uint256 n) external {
        uint256 i = next;
        for (uint256 k; k < n; ++k) {
            ++i;
            (bool ok, ) = token.call(abi.encodeWithSelector(0x095ea7b3, who(i), uint256(1)));
            require(ok);
        }
        next = i;
    }

    /// New slots in this contract.
    function fillRaw(uint256 n) external {
        uint256 i = next;
        for (uint256 k; k < n; ++k) {
            ++i;
            raw[i] = 1;
        }
        next = i;
    }

    /// Cold reads of existing allowance slots of a token.
    function readAllowances(address token, address owner, uint256 start, uint256 n) external view returns (uint256 sum) {
        for (uint256 k; k < n; ++k) {
            (bool ok, bytes memory out) = token.staticcall(abi.encodeWithSelector(0xdd62ed3e, owner, who(start + k)));
            require(ok);
            sum += abi.decode(out, (uint256));
        }
    }

    /// Rewrites of existing allowance slots of a token.
    function rewriteApprove(address token, uint256 start, uint256 n, uint256 value) external {
        for (uint256 k; k < n; ++k) {
            (bool ok, ) = token.call(abi.encodeWithSelector(0x095ea7b3, who(start + k), value));
            require(ok);
        }
    }

    /// Cold reads of this contract's raw slots.
    function readRaw(uint256 start, uint256 n) external view returns (uint256 sum) {
        for (uint256 k; k < n; ++k) sum += raw[start + k];
    }

    /// Rewrites of this contract's raw slots.
    function rewriteRaw(uint256 start, uint256 n, uint256 value) external {
        for (uint256 k; k < n; ++k) raw[start + k] = value;
    }

    function disperse(address payable[] calldata to, uint256 value) external payable {
        for (uint256 k; k < to.length; ++k) to[k].transfer(value);
    }
}
