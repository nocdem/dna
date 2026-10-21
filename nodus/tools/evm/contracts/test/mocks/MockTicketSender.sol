// SPDX-License-Identifier: Apache-2.0
//
// TEST FIXTURE — never shipped. Shows why the library bans transfer / send: their 2 300 gas
// stipend is below the 25 000 gas a ticket takes.
//   pushTransfer: `transfer` to the ticket address (no calldata, 2 300 stipend) — reverts.
//   pushStipend:  the right 64-byte calldata but only the 2 300 stipend (gas: 0 + value) — the
//                 ticket frame halts out of gas, the CALL returns 0 and this reverts.
//   pushFull:     the right calldata forwarding all gas — creates the ticket.
pragma solidity ^0.8.30;

contract MockTicketSender {
    error TicketCallFailed();

    receive() external payable {}

    function pushTransfer(address payable ticket, uint256 amount) external {
        ticket.transfer(amount);
    }

    function pushStipend(address ticket, uint256 amount, bytes calldata fingerprint) external {
        (bool ok,) = ticket.call{value: amount, gas: 0}(fingerprint);
        if (!ok) revert TicketCallFailed();
    }

    function pushFull(address ticket, uint256 amount, bytes calldata fingerprint) external {
        (bool ok,) = ticket.call{value: amount}(fingerprint);
        if (!ok) revert TicketCallFailed();
    }
}
