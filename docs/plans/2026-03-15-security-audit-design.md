# Multi-Agent Security Audit v2 — Design

**Date:** 2026-03-15
**Scope:** DNA Nodus + DNA Connect (full stack)
**Method:** 6 parallel domain agents + 1 cross-domain consolidation agent
**Prior Audit:** 2026-03-14 (88 findings, 7 attack chains)
**Output:** `docs/security/2026-03-15-security-audit.md`

---

## Architecture

```
┌──────────┬──────────┬──────────┬──────────┬──────────┬──────────┐
│ Agent 1  │ Agent 2  │ Agent 3  │ Agent 4  │ Agent 5  │ Agent 6  │
│ Network  │ Crypto   │ DHT      │ Messenger│ DNAC/BFT │ MemSafety│
│ Transport│          │ Kademlia │ Connect  │ Witness  │ Input Val│
├──────────┴──────────┴──────────┴──────────┴──────────┴──────────┤
│              All run in parallel (isolated worktrees)           │
│              Each writes findings to /tmp/*.md                  │
├─────────────────────────────────────────────────────────────────┤
│                     Agent 7: Consolidator                       │
│  - Merge, deduplicate, attack chains                            │
│  - Cross-reference 2026-03-14 audit                             │
│  - Final report: docs/security/2026-03-15-security-audit.md     │
└─────────────────────────────────────────────────────────────────┘
```

## Agent Scopes

| Agent | Source Files | Focus |
|-------|-------------|-------|
| 1: Network/Transport | `nodus/src/transport/`, `nodus/src/server/nodus_server.c`, `nodus/src/protocol/` | TCP/UDP, connection limits, auth, wire protocol, DoS |
| 2: Cryptography | `shared/crypto/`, `nodus/src/crypto/`, `messenger/src/crypto/` | Key mgmt, RNG, wiping, file perms, side channels |
| 3: DHT/Kademlia | `nodus/src/core/`, `nodus/src/channel/`, `nodus/src/consensus/`, `messenger/dht/` | Routing, value verification, replication, Sybil/Eclipse |
| 4: Messenger | `messenger/src/` (api/, messenger/, database/, transport/, blockchain/) | Engine API, contacts, groups, GEK, messages, DB, threads |
| 5: DNAC/Witness BFT | `dnac/src/`, `nodus/src/witness/` | Consensus, TX verification, ledger, witness auth, double-spend |
| 6: Memory Safety | All C source across nodus/, messenger/, dnac/, shared/ | Buffers, integers, malloc, format strings, UAF, CBOR |

## Methodology

Each agent:
1. Read all source files in scope
2. Apply STRIDE threat model
3. Classify: CRITICAL/HIGH/MEDIUM/LOW + confidence
4. Cite exact file:line for every finding
5. Write to `/tmp/audit_agent_N.md`

## Consolidation

Agent 7:
1. Read all 6 outputs
2. Deduplicate overlapping findings
3. Identify cross-domain attack chains
4. Cross-reference 2026-03-14 audit (NEW/KNOWN/FIXED/REGRESSION)
5. Final report to `docs/security/2026-03-15-security-audit.md`

## Output Format

```markdown
# DNA Security Audit v2 — 2026-03-15
## Executive Summary
## Attack Chains
## All Findings by Severity
## Comparison with Prior Audit
## Remediation Priority
```
