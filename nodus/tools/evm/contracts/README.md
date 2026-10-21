# Nodus security contract library — v0.1.0

A small, reviewed set of reusable Solidity contracts for the Nodus EVM (32-byte addresses):
ownership and roles, a reentrancy guard, a pause switch, a timelock, a multisig vault with
on-chain approvals, and a milestone escrow.

Design: `docs/plans/2026-10-21-nodus-contract-library-design.md` rev 3 (local); council record:
`docs/plans/decisions/2026-10-21-kurultay-30-summary.md` (local). Governing records:
`2026-10-04-nodus-evm-domain.md` (32-byte addresses; chain PQ authorization never mixed with
contract crypto) and `2026-10-06-evm-dev-tooling.md` item 1 (the developer pack: compiler + guide +
examples). The library is not yet linked from the Wiki developer page; it joins the developer pack
when it is published.

Nothing here changes the chain: these are ordinary contracts, run by the consensus EVM like any
other. The library contains **no signature-based authorization** (no `ecrecover`, no permits):
every check is `msg.sender`.

## Quick start

A 2-of-3 MultisigVault paying a Nodus account, and a MilestoneEscrow, deployed from the committed
`out/default/` bytecode with `nodus-cli` alone (no compiler). These are the command lines
`nodus/tests/integration/stagef/tests/test_cmt_evm_lib.sh` runs end to end on a 7-node test chain;
the scenario adds `--no-wait` (it reads each receipt from the node's database) and points `-s` /
`-p` / `--submit` at its local nodes. **Run 2026-10-21: PASS** on a fresh 7-node test chain
(epoch 15 / grace 15 — the logic, not production timing): the vault paid a Nodus account through a
ticket that redeemed to a native coin, the timelock paid only after its delay, the escrow paid both
milestones, and every node agreed on the result.

Run the commands in this directory (`nodus/tools/evm/contracts`). Placeholders: `<ip>` / `<port>`
a node's client port, `<keysN>` an identity directory,
`<A1>` … an EVM address as 64 lowercase hex WITHOUT `0x`, `<VAULT>` / `<ESC>` the contract
addresses the deployments print, amounts in wei (1 NODUS = 10^8 raw = 10^18 wei; q = 10^10 wei).
Every transaction below also takes `--keys <keysN> --submit <ip>:<port> --yes` (shown once, in step
1). `--yes` skips the CLI's question when the fee is above 50 NODUS; leave it out to be asked, or
give `--max-fee <raw>`. Without `--no-wait` the CLI waits and prints the receipt.

```
CLI="nodus-cli -s <ip> -p <port>"
```

Arrays are passed to `--args` (and to `evm send` / `evm call` / `evm encode`) as ONE argument
`"[v1,v2,...]"`, `"[]"` for an empty one; only one-dimensional `T[]` of a static type (address,
uintN, intN, bool, bytesN) is supported. `nodus-cli evm encode --ctor "(T…)" v…` prints the
constructor arguments as hex offline (what `--args` appends to the creation code), and
`nodus-cli evm encode "f(T…)" v…` a call's data (selector + arguments).

1. **Your EVM address and EVM balance.** `nodus-cli evm address --keys <keys1>` prints `0x<64 hex>`
   (offline). Then
   `$CLI evm deposit <raw> --keys <keys1> --submit <ip>:<port> --yes`
   — you see the build line (`evm DEPOSIT: sender 0x… nonce=… fee=…`), `accepted: mempool CheckTx
   approved`, then `receipt (…): DEPOSIT SUCCEEDED, included at height …`.
2. **Deploy a 2-of-3 vault.** The constructor is `(address[] owners, uint256 threshold)`:
   ```
   $CLI evm deploy "$(cat out/default/MultisigVault.creation.hex)" \
       --args "(address[],uint256)" "[<A1>,<A2>,<A3>]" 2 --gas 5000000 …
   ```
   — the receipt says `CREATE SUCCEEDED` and `created contract: 0x<VAULT>`. Check it:
   `$CLI evm call <VAULT> "isOwner(address)(bool)" <A2>` prints `ok at height …` and `[0] true`;
   `$CLI evm call <VAULT> "threshold()(uint256)"` prints `[0] 2`.
3. **Fund it.** The vault takes value only in `receive()`; a plain value transfer (an address and
   `--value`, no signature) sends it with empty calldata:
   ```
   $CLI evm send <VAULT> --value <wei> --gas 1000000 …
   ```
   — `CALL SUCCEEDED`; `$CLI evm balance <VAULT>` shows the amount.
4. **Pay a Nodus account through a ticket.** The ticket address
   (`python3 -c 'import hashlib;print(hashlib.sha3_512(b"NDS.EVMWITHDRAW.v1").hexdigest()[:64])'`,
   see "Getting value out of a contract"), a q-multiple amount, and the destination's 128-hex
   fingerprint (its `nodus.fp`) as the 64 bytes of calldata. Owner 1 proposes (the id is
   `proposalCount()` read before, here 0):
   ```
   $CLI evm send <VAULT> "submit(address,uint256,bytes)" <TICKET_ADDR> <wei> <FP128> --gas 1000000 … (keys1)
   $CLI evm send <VAULT> "approve(uint256)" 0 --gas 1000000 …                                     (keys2)
   $CLI evm send <VAULT> "execute(uint256)" 0 --gas 1000000 …                                     (keys3)
   ```
   — `getProposal(uint256)(address,uint256,bytes,uint256,uint256,bool)` shows the proposal and its
   approvals; an `execute` below the threshold is refused by the simulation (`the call FAILS` and
   the revert data; nothing is built unless you pass `--force`, which lands a failed transaction
   that still pays its fee). The executing receipt prints `withdrawal ticket: <ticket_id>`. Anyone
   then pays it out:
   `$CLI evm redeem <ticket_id> …` — `ticket: <raw> raw to <FP128>`, then `REDEEM SUCCEEDED`; the
   destination holds a native coin of exactly that amount.
5. **A milestone escrow.** Constructor `(payer, payee, arbiter, uint256[] amounts, deadline)`,
   the amounts each a multiple of q. The
   deadline is a `block.timestamp` — the committed block's time in seconds; no `nodus-cli` verb
   prints it (the scenario reads it from a Timelock, `getReadyTime(id)` minus the delay):
   ```
   $CLI evm deploy "$(cat out/default/MilestoneEscrow.creation.hex)" \
       --args "(address,address,address,uint256[],uint256)" <A1> <A2> <A3> "[<m0>,<m1>]" <deadline> \
       --gas 5000000 …                                                                 (any key)
   $CLI evm send <ESC> "fund()" --value <m0+m1> --gas 1000000 …                    (payer)
   $CLI evm send <ESC> "release(uint256)" 0 --gas 1000000 …                        (payer)
   $CLI evm send <ESC> "withdraw()" --gas 1000000 …                                (payee)
   $CLI evm send <ESC> "resolve(uint256,bool)" 1 false --gas 1000000 …             (arbiter)
   $CLI evm send <ESC> "withdraw()" --gas 1000000 …                                (payer)
   ```
   — each `CALL SUCCEEDED`; `milestone(uint256)(uint256,uint8)` shows the state (0 Pending,
   1 Released, 2 Refunded), `creditOf(address)(uint256)` what a party may withdraw, and each
   `withdraw()` raises the caller's `evm balance` by exactly its credit. A party then takes EVM
   value back to a native coin with `$CLI evm withdraw <raw> …` (`WITHDRAW SUCCEEDED`).

The scenario also runs a Timelock (minDelay 300 s, deployed with `--args
"(uint256,address[],address[],address[])" 300 "[<A1>]" "[<A1>]" "[]"` and funded with a plain
value transfer; `schedule`, an `execute` refused before the ready time, the `execute` after it)
and the negative controls named in its header. It also checks that `evm encode --ctor` prints
exactly the constructor words it builds by hand, as an independent cross-check.

## Files

| Path | What |
|---|---|
| `src/access/Ownable.sol` | abstract — one owner, two-step transfer, no renounce |
| `src/access/AccessControl.sol` | abstract — `bytes32` roles, per-role admin role |
| `src/security/ReentrancyGuard.sol` | abstract — `nonReentrant` |
| `src/security/Pausable.sol` | abstract — `whenNotPaused` / `whenPaused` |
| `src/governance/Timelock.sol` | delayed calls with proposer / executor / canceller roles |
| `src/vaults/MultisigVault.sol` | M-of-N owners approve a call on-chain before it runs |
| `src/payments/MilestoneEscrow.sol` | payer / payee / arbiter escrow paid out per milestone |
| `test/mocks/*.sol` | TEST FIXTURES, never shipped (concrete versions of the abstract contracts, a re-entering / reverting actor, a `false`-returning target, a `transfer()`-to-ticket sender, a SELFDESTRUCT forcer) |
| `build.sh` | compiles `src/` and `test/mocks/` with the pinned compiler into `out/` |
| `verify.sh` | re-compiles into a temporary directory and diffs against `out/` (drift check) |
| `out/` | COMMITTED bytecode + ABI, two configurations; `out/VERSION.txt` = compiler line, sources, flags. **Every `out/**/Mock*` file (`MockAccessControl`, `MockActor`, `MockFalseTarget`, `MockForcer`, `MockGuarded`, `MockOwnable`, `MockTicketSender`) is a TEST FIXTURE — test-only, NOT for deployment**: they are there only because the tests run `out/`; several are deliberately unsafe (open `pause`, re-entry, `transfer`, SELFDESTRUCT). Deploy only `Timelock`, `MultisigVault`, `MilestoneEscrow`, or your own contract built on the abstract ones. |
| `VERSION` | the library version (`0.1.0`) |

The tests are `shared/evm/tests/test_contract_lib.c` (part of `cd shared/evm && make test`); they
run the committed `out/` in the node's engine profile and need no compiler.

## Build and verify

```
SOLC=/usr/local/bin/solc-nodus ./build.sh     # after any .sol change
SOLC=/usr/local/bin/solc-nodus ./verify.sh    # MANDATORY before committing or publishing
```

Both scripts accept only the exact compiler line
`Version: 0.8.30+nodus.addr256.commit.73712a01.Linux.g++` (the Nodus solc,
`nodus/tools/evm/solc/README.md`), pass `--evm-version prague` explicitly, and refuse any compiler
diagnostic (warning or error). Configurations: `default` (no optimizer — what
`nodus-cli evm deploy --solc` compiles; prague is also the compiler's default, and a no-flag
compile of the same source list gave byte-identical creation code on 2026-10-21; a deployment
through `nodus-cli` passes the path the user typed, so its metadata tail can differ) and
`optimize` (`--optimize`, runs 200). Sources are passed by their paths relative to this directory, so the
metadata hash does not depend on where the tree is checked out. The tests run `out/`, not the
sources: **a `.sol` edit without `build.sh` + `verify.sh` leaves the tests checking old code.**

## Source rules (every file under `src/`)

`pragma solidity ^0.8.30;`, `// SPDX-License-Identifier: Apache-2.0`, relative imports inside
`src/` only, custom errors, `abi.encode` (never `encodePacked`) for ids. Not used anywhere in
`src/`: `uint160` / `bytes20`, external function types off the stack, `ecrecover`, inline
assembly, `selfdestruct`, `delegatecall`, `tx.origin`, `block.prevrandao`, `blockhash`,
`gasleft()`, `transfer` / `send`, immutables, linked (external) library functions. Loops run
over stored owner / milestone lists of at most 32 entries (the Timelock constructor loops over
its argument lists once, at deployment). `test/mocks/` is exempt — the fixtures there
deliberately use `transfer`, re-entry, inline assembly and the SELFDESTRUCT opcode.

## Contracts

### Ownable (abstract)

- `constructor(initialOwner)`: non-zero, else `OwnableInvalidOwner(0)`; emits
  `OwnershipTransferred(0, initialOwner)`.
- `onlyOwner`: `OwnableUnauthorizedAccount(caller)` for anyone else.
- `transferOwnership(newOwner)` (owner only, non-zero) only **nominates**: sets `pendingOwner`
  (overwriting an earlier nomination), emits `OwnershipTransferStarted(owner, newOwner)`.
- `acceptOwnership()` only by `pendingOwner`: moves ownership, clears `pendingOwner`, emits
  `OwnershipTransferred(previous, new)`. Ownership never lands on an account that did not accept.
- **No `renounceOwnership`.** Nominating the current owner is allowed (it changes nothing when
  accepted).
- Storage: `_owner`, `_pendingOwner` — the first two slots of an inheritor that lists Ownable
  first (`MockOwnable`: slots 0, 1).

### AccessControl (abstract)

- `DEFAULT_ADMIN_ROLE = 0x00`; each role's admin role is `DEFAULT_ADMIN_ROLE` until the inheritor
  calls `_setRoleAdmin(role, adminRole)` (emits `RoleAdminChanged`).
- `hasRole(role, account)`, `getRoleAdmin(role)`.
- `grantRole` / `revokeRole`: only a holder of the role's admin role, else
  `AccessControlUnauthorizedAccount(caller, neededRole)`.
- `renounceRole(role, account)`: only `account == msg.sender`, else
  `AccessControlBadConfirmation()`. It is `virtual`: an inheritor may refuse renouncing
  altogether (the Timelock does).
- `_grantRole` / `_revokeRole` are no-ops without an event when nothing changes;
  events `RoleGranted(role, account, sender)` / `RoleRevoked(role, account, sender)`.
- The constructor grants nothing: the inheritor grants the first roles. **If the inheritor grants
  no admin, nobody can ever grant or revoke** (see "Irreversible authority").

### ReentrancyGuard (abstract)

One status word: the constructor writes 1 (NOT_ENTERED); `nonReentrant` reverts `ReentrantCall()`
when it is 2, sets 2 before the body and 1 after. All `nonReentrant` functions of a contract share
the word, so re-entry into a different guarded function is refused too. A revert in the body undoes
the status write; the guard keeps working.

### Pausable (abstract)

Starts unpaused. `paused()`; modifiers `whenNotPaused` (`EnforcedPause()`) and `whenPaused`
(`ExpectedPause()`); internal `_pause()` (reverts when paused) and `_unpause()` (reverts when not
paused); events `Paused(account)` / `Unpaused(account)` (the account in the data, not a topic).
Who may pause is the inheritor's choice. Pause stops **exactly** the functions marked
`whenNotPaused` — nothing else.

### Timelock

- Roles `PROPOSER_ROLE`, `EXECUTOR_ROLE`, `CANCELLER_ROLE` (`keccak256` of the names).
- `MAX_DELAY = 365 days` (public constant): the largest `minDelay` and the largest schedule
  delay (`TimelockDelayTooLong(delay, MAX_DELAY)`).
- `constructor(minDelay, proposers[], executors[], cancellers[])`: at least one proposer and one
  executor (`TimelockNoProposer()` / `TimelockNoExecutor()`), cancellers may be empty;
  `minDelay <= MAX_DELAY`; every account non-zero and not the timelock itself
  (`TimelockInvalidAccount(a)`).
- **The timelock is the only holder of `DEFAULT_ADMIN_ROLE`, from construction on.** There is no
  external admin. Every later role change is `grantRole` / `revokeRole` called by the timelock on
  itself through `schedule` + `execute`, so it waits the delay like everything else. The timelock
  refuses (`TimelockAdminFixed()`) to grant `DEFAULT_ADMIN_ROLE` to any other account and to revoke
  its own — such a delayed operation fails at execute.
- **Role rules** (all enforced in the role functions, so a delayed operation that breaks one fails
  at execute):
  - `renounceRole` **always reverts** (`TimelockRenounceDisabled()`), for every role and every
    caller: a role leaves only through a delayed `revokeRole`, so no holder can drop a role without
    the delay.
  - PROPOSER and EXECUTOR never go to zero holders: a revoke of the last proposer or the last
    executor reverts (`TimelockLastHolder(role)`). Grant the replacement first, then revoke. (A
    revoke of an account that does not hold the role stays a no-op.) CANCELLER may go to zero.
  - No role other than `DEFAULT_ADMIN_ROLE` is ever granted to `address(0)` or to the timelock
    itself (`TimelockInvalidAccount(account)`) — at construction and later.
- Operation id = `keccak256(abi.encode(target, value, data, salt))` (`hashOperation`).
  States `Unset(0) → Pending(1) → Done(2) | Cancelled(3)` (`getOperationState`); `getReadyTime`.
- `schedule(target, value, data, salt, delay)`: PROPOSER only; `delay >= minDelay`
  (`TimelockInsufficientDelay`) and `delay <= MAX_DELAY` (`TimelockDelayTooLong`); the id must
  never have been used, in ANY state
  (`TimelockUnexpectedOperationState`) — a cancelled or executed operation needs a new salt. Ready
  time = `block.timestamp + delay` (checked add).
- `execute(target, value, data, salt)`: EXECUTOR only, `nonReentrant`, op Pending, and
  `block.timestamp >= ready` (`TimelockNotReady`). Marks Done **before** the call. `value` comes
  from the timelock's own balance — `execute` is not payable; send value to the timelock first
  (`receive()` accepts it). A failed call reverts the whole execute with
  `TimelockCallFailed(id, reason)` — `reason` is the target's revert data (see "Why an execute
  failed"): the operation stays Pending and can be retried.
- `cancel(id)`: CANCELLER only, Pending only; cancelled is terminal.
- `updateDelay(newDelay)`: only `msg.sender == address(this)`, i.e. through a delayed operation
  (`TimelockUnauthorizedCaller`). Any value from 0 to `MAX_DELAY` is accepted.
- No predecessors, no batches (cut from v0.1).

### MultisigVault

- `constructor(owners[], threshold)`. Invariant, checked here and after **every** change:
  `1 <= threshold <= ownerCount <= 32`, owners distinct, non-zero and never the vault itself
  (`VaultInvalidOwner`, `VaultInvalidConfig(count, threshold)`).
- `submit(to, value, data)` (owner only) → sequential id from 0; the proposal never changes, is
  tagged with the current `configVersion`, and carries the submitter's approval.
- `approve(id)` / `revokeApproval(id)` (owner only) on an existing, not executed proposal of the
  current `configVersion`; no double approval.
- `execute(id)`: any owner, `nonReentrant`, approvals `>= threshold`; marks Executed **before** the
  call; value from the vault balance; a failed call reverts the whole execute with
  `VaultCallFailed(id, reason)` — `reason` is the target's revert data (see "Why an execute
  failed"); the proposal stays pending (retryable).
- `addOwner`, `removeOwner`, `changeThreshold`: only `msg.sender == address(this)` — i.e. as a
  passed proposal whose `to` is the vault itself (`VaultNotSelf`). Each bumps `configVersion`,
  which **voids every pending proposal of an older version** (they must be resubmitted; approvals
  never survive an owner-set change, so a removed and re-added owner cannot revive old
  approvals). A change that would break the invariant fails, and with it the execute.
- Views: `getOwners`, `isOwner`, `threshold`, `configVersion`, `proposalCount`, `getProposal`,
  `isApproved`. `receive()` accepts value (event `Deposit`).
- `removeOwner` moves the last owner into the removed one's place in `getOwners()` (the order of
  that list is not meaningful).

### MilestoneEscrow

- One escrow per deployment: `constructor(payer, payee, arbiter, amounts[], deadline)` — the three
  parties distinct, non-zero and never the escrow's own address (`EscrowInvalidParty`); 1..32
  milestones; each amount > 0 and a multiple of
  **q = 10^10 wei** (1 raw NODUS unit, see "dust"); the sum must not overflow (Solidity's checked
  add: `Panic(0x11)`); `deadline > block.timestamp`.
- `fund()`: payer only, exactly once, `msg.value == sum`, only while `block.timestamp < deadline`.
- Every milestone moves exactly once, Pending → Released or Refunded, and only after funding
  (`EscrowNotFunded`):
  - `release(i)` — payer → credits the payee;
  - `resolve(i, toPayee)` — arbiter → credits the payee (`true`) or the payer (`false`);
  - `refund(i)` — payer, only when `block.timestamp >= deadline` → credits the payer.
- **The deadline gives the payer refund ELIGIBILITY, not priority.** After it, a `release` or a
  `resolve` that lands first still settles the milestone. There is no dispute window: **the arbiter
  must act before the deadline** if it wants to decide a milestone.
- **If the payer goes silent after funding and the arbiter is gone, the pending milestones cannot
  move**: only the payer (`release`, `refund`) and the arbiter (`resolve`) can settle one, and v0.1
  has no payee-side claim (deferred).
- `withdraw()` (`nonReentrant`): clears the caller's credit, then pays it with a CALL forwarding all
  gas; if the payment fails the whole withdraw reverts and the credit is restored. A payer or payee
  that is a contract must be able to receive value, or its credit can never leave.
- Accounting uses stored sums only, never `address(this).balance`. The escrow has no `receive()`:
  value that arrives anyway (only possible as a SELFDESTRUCT beneficiary) is **never credited and
  stays locked**. Invariant (`accounting()`): `unsettled + credited + withdrawn == funded total`.

## What is different on Nodus

- **Addresses are 32 bytes** (`nodus/tools/evm/solc/README.md`, semantic rules). An address takes
  a whole storage slot; event topics and errors carry all 32 bytes; a 20-byte Ethereum address
  padded with zeros is a different account.
- **Value in the EVM is wei; 1 raw NODUS unit = q = 10^10 wei.**
- **Block time** (`block.timestamp`) is the committed block time in seconds, the same on every
  node, seen only at block boundaries (an idle chain commits a block about every 60 s). "Ready at
  T" means "ready in the first block whose timestamp is ≥ T".
- While the chain-level gas price is zero, CALL / CREATE / DEPOSIT are refused: no contract
  executes and no new ticket opens; existing tickets stay redeemable. The library has no other
  emergency exit.

## Getting value out of a contract

A contract **cannot use WITHDRAW**: the bridge refuses a sender account that carries code
(`nodus/src/witness/nodus_witness_rt_evm.c`, `rtevm_bridge_pre`). There are two ways out:

1. **Pay an EOA** (an ordinary account, e.g. a vault proposal or a timelock operation whose
   `target` is your own Nodus EVM address); that account then uses WITHDRAW itself.
2. **Open a ticket** — the only DIRECT exit from a contract to a Nodus account: a plain CALL to
   the ticket address carrying
   - value > 0 and a multiple of q (10^10 wei),
   - **exactly 64 bytes** of calldata: the destination fingerprint.

   The ticket takes 25 000 gas from the forwarded gas. Any other call into the ticket address
   (other calldata length, a non-q value) halts the called frame: the CALL returns 0 and a vault /
   timelock execute reverts — nothing moves. A later REDEEM pays the ticket out
   (`nodus-cli evm redeem <ticket_id>`).

   The ticket address is `SHA3-512("NDS.EVMWITHDRAW.v1")[0..32]` (the 18 ASCII bytes, no
   terminator; `nodus_witness_rt_evm.c`, `TICKET_ADDR_PREIMAGE`). Computed on 2026-10-21 with
   Python's `hashlib.sha3_512` and with `openssl dgst -sha3-512` (the two agree):
   `0xd51053ece8ce1bc31659bbf1eca305581848eefe1536cb0da42ca65b838c8502`
   — recompute it yourself before sending value
   (`python3 -c 'import hashlib;print(hashlib.sha3_512(b"NDS.EVMWITHDRAW.v1").hexdigest()[:64])'`).
   The library's tests use a different, test-only address; this value has not been exercised
   against a running node by them.

   With the vault: `submit(ticketAddress, amount, fingerprint64)`, approve to the threshold,
   `execute`. With the timelock: `schedule(ticketAddress, amount, fingerprint64, salt, delay)`,
   then `execute` after the delay.

**`transfer` and `send` are banned** in the library: they forward only the 2 300 gas stipend
(`shared/evm/evm_gas.h`, `EVM_G_CALL_STIPEND`), below the 25 000 a ticket needs, and send no
calldata. Every payout is `(bool ok, ) = to.call{value: v}(data)` forwarding all gas and reverting
on `!ok`.

**The dust rule.** Wei below q cannot leave the EVM: neither a ticket nor WITHDRAW moves a
non-multiple of q. The q-multiple part of a balance can always leave; only the remainder below q
stays. The escrow therefore requires q-multiple milestone amounts, so all of it can leave.

## CALL success is execution success

The vault and the timelock are generic executors. They treat a CALL that does not revert as a
successful execution: a target that returns an encoded `false` (for example an ERC-20 `transfer`
that returns `false` instead of reverting) still completes the proposal / operation, and it can not
be executed again. Put application-level checks in the target, or call a target that reverts on
failure. The `receive()` functions are not guarded and not paused, so a target that sends value
back during an execute does not make it fail.

## Why an execute failed

When the target's call fails, the vault reverts `VaultCallFailed(uint256 id, bytes reason)` and the
timelock `TimelockCallFailed(bytes32 id, bytes reason)`. `reason` is the target's revert data
exactly as returned: decode its first 4 bytes as the target's error selector and the rest as that
error's arguments (e.g. a delayed `revokeRole` of the last executor gives
`reason = TimelockLastHolder(EXECUTOR_ROLE)`; a self-call that breaks the vault's invariant gives
`VaultInvalidConfig(count, threshold)`). `reason` is EMPTY when the target gave no data — a call
that ran out of gas, a plain `revert()`, or a refused ticket call (the ticket frame halts without
data). The data is carried as an argument rather than re-thrown as the vault's / timelock's own
revert: re-throwing raw bytes needs inline assembly, which the library's source rules forbid.

## Irreversible authority — read before deploying

- **Ownable:** there is no renounce and no recovery. A typo in `initialOwner` or in an accepted
  nomination is permanent — but a nomination only takes effect when the nominee itself accepts, so
  nominate an address you control and accept from it.
- **AccessControl:** if the inheritor grants nobody `DEFAULT_ADMIN_ROLE` (or the admin role of a
  role), that role can never be granted or revoked. Renouncing the last admin is final.
- **Timelock:** the proposer / executor / canceller sets given at construction are the only way in.
  The contract keeps at least one proposer and one executor (no renounce, no revoke of the last
  one), but it cannot know whether their keys still work: if every proposer loses its key, nothing
  can ever be scheduled again — including the role change that would fix it. If every executor
  loses its key, nothing executes. With no canceller, nothing can be cancelled. A delay of up to
  `MAX_DELAY` (365 days) is accepted, and a `minDelay` near it makes every change, including a
  role fix, wait that long. Choose several holders, and consider giving the role to a
  MultisigVault.
- **MultisigVault:** if more than `ownerCount - threshold` owners lose their keys, the vault and its
  balance are frozen for good. A configuration change voids every pending proposal.
- **MilestoneEscrow:** the parties are fixed at construction. If the payer never funds, nothing
  happens; if the arbiter disappears, disputes end at the deadline with the payer's refund
  eligibility; if the payer goes silent after funding and the arbiter is gone, pending milestones
  cannot move (no payee-side claim in v0.1); credits of a party that cannot receive value stay in
  the escrow.

## Tests and what they do NOT cover

`shared/evm/tests/test_contract_lib.c` deploys every contract and mock from `out/` in both
configurations and runs the positive path of every rule above plus the negative controls of the
design's test plan (§5), with accounts whose high 12 bytes are non-zero and their "twins" (same
low 20 bytes): refusals name the full 32-byte account, raw mapping slots of twins show no net
write (the engine's change set reports only slots whose final value differs from the pre-state, so
a write later undone would not show), event address topics hold all 32 bytes, and the deployed code
equals the committed runtime. A failed vault / timelock execute is checked byte for byte, including
the inner `reason`.

On a chain: `nodus/tests/integration/stagef/tests/test_cmt_evm_lib.sh` (PASS 2026-10-21, epoch 15 /
grace 15) deploys MultisigVault, Timelock and MilestoneEscrow from the committed bytes through
`nodus-cli` and the node's envelope / fee / receipt path, pays a Nodus account from the vault
through the PRODUCTION ticket address and redeems it to a native coin, and checks the result on all
7 nodes (its README row lists what it does not cover).

Not covered:
- A chain-level gas price of zero; owner / threshold changes, cancel, `updateDelay`, refund and
  re-entry on a chain (the engine tests cover them).
- Contracts you write on top of the abstract ones: the tests exercise them only through the mocks
  in `test/mocks/`.
- Compilers other than the pinned one, other optimizer settings, EVM versions other than prague.
- The engine is the project's own (`shared/evm`): an engine defect that mirrors a compiler defect
  would not show; `test_addr32.c` and `test_nodus_profile.c` pin the engine's own rules.
- No external audit. v0.1 has had the design council (Kurultay #30) and this test suite.

## Deliberately not in v0.1

ERC-20 / ERC-721 tokens (see `nodus/tools/evm/examples/`), upgradeable proxies, signature / permit
approvals (they need an ML-DSA-87 verification precompile, a separate hard-fork design),
`renounceOwnership`, timelock predecessors and batches, emergency "rescue" functions, token
escrow, ERC-165, an arbiter-side `refund` (use `resolve(i, false)`), an escrow dispute window, a
payee-side claim on an escrow whose payer and arbiter are both gone, a timelock external setup
admin.
