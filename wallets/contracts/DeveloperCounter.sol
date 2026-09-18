// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.30;

/// @notice Public test fixture for the isolated synthetic Bloch developer domain.
contract DeveloperCounter {
    uint256 public constant MAX_VALUE = 1000;
    uint256 public value;

    event ValueChanged(address indexed caller, uint256 previousValue, uint256 newValue);
    error ValueTooLarge(uint256 requested, uint256 maximum);

    constructor(uint256 initialValue) {
        if (initialValue > MAX_VALUE) revert ValueTooLarge(initialValue, MAX_VALUE);
        value = initialValue;
    }

    function setValue(uint256 newValue) external {
        if (newValue > MAX_VALUE) revert ValueTooLarge(newValue, MAX_VALUE);
        uint256 previousValue = value;
        value = newValue;
        emit ValueChanged(msg.sender, previousValue, newValue);
    }
}
