# EVM fixtures for `tests/test_cmt_evm.sh`

Solidity sources and their compiled CREATION bytecode, committed so the
scenario never needs a compiler.

| File | What |
|---|---|
| `Counter.sol` / `Counter.hex` | SSTORE + one event (`increment`), a view (`get`), a REVERT with `Error(string)` after an SSTORE (`boom`), the block GASLIMIT (`gasLimitNow`) |
| `Ticketer.sol` / `Ticketer.hex` | a contract that opens a withdrawal TICKET by CALLing the ticket system address with value and the 64-byte destination (design §5) |
| `abi.sigs` | `solc --hashes` output: the function selectors and event topics |

## How they were compiled

Compiler: the Nodus 32-byte-address solc (`nodus/tools/evm/solc`, patch against
upstream v0.8.30), built with that directory's `build.sh`:

```
$ solc --version
solc, the solidity compiler commandline interface
Version: 0.8.30+nodus.addr256.commit.73712a01.Linux.g++
```

Command (run in this directory, default settings: no optimizer, the compiler's
default EVM version `prague`; binary at
`/tmp/claude-1000/-opt-dna/ae144799-5ac0-4755-ac3b-44b1b7347f9a/scratchpad/solc-release/solidity/build/solc/solc`
on the machine that produced these files):

```
solc --bin --hashes Counter.sol Ticketer.sol
```

Each `.hex` file is the hex line under `Binary:` of its contract (no `0x`), one
line. Re-check after a recompile: the line `solc --bin <C>.sol` prints under
`Binary:` must equal `<C>.hex` byte for byte. A stock solc is NOT a substitute:
it masks every address to 20 bytes (`nodus/tools/evm/solc/README.md` "Why").
