// SPDX-License-Identifier: GPL-3.0
// EXPECT: but has an invalid checksum
// The checksummed literal from ok_address.sol with the case of its first letter flipped.
pragma solidity ^0.8.30;
contract C {
    address constant A = 0x8076f99ED6A2095ddE395300cF2E056F44e3F5CFA66b300c7b84E3972f379E50;
}
