// SPDX-License-Identifier: GPL-3.0
// EXPECT: This looks like a 20-byte Ethereum address literal
// A valid EIP-55 40-digit literal (the EIP-55 example address) is an error on Nodus EVM.
pragma solidity ^0.8.30;
contract C {
    address constant A = 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed;
}
