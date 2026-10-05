// SPDX-License-Identifier: MIT
// Stage F fixture for tests/test_cmt_evm.sh (Nodus EVM). Compiled once with the
// Nodus 32-byte-address solc (see README.md in this directory); the
// scenario deploys Ticketer.hex and never runs a compiler.
//
// openTicket(sys, dest) forwards msg.value to the ticket system address
// `sys` with calldata = `dest` (design §5: a plain CALL, value > 0 and a
// multiple of 10^10 wei, calldata exactly the 64-byte destination
// fingerprint) — the CONTRACT opens a withdrawal ticket, which a later
// `evm redeem` pays out as a native UTXO. The system address is passed in
// (the scenario derives it, SHA3-512("NDS.EVMWITHDRAW.v1")[0..32]) so the
// bytecode carries no chain constant.
pragma solidity 0.8.30;

contract Ticketer {
    event TicketOpened(bytes ticketId);

    function openTicket(address sys, bytes calldata dest)
        external
        payable
        returns (bytes memory)
    {
        (bool ok, bytes memory id) = sys.call{value: msg.value}(dest);
        require(ok, "ticket refused");
        emit TicketOpened(id);
        return id;
    }
}
