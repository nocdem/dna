# DNAC Staking, Delegation & Smart Contract Design

**Date:** 2026-04-10 | **Status:** APPROVED | **Version:** TBD

---

## Overview

DNAC'a Delegated Proof of Stake (DPoS) mekanizmasi, atomic swap (HTLC) ve predefined smart contract templates eklenmesi. Mevcut chain resetlenecek.

---

## 1. Witness Self-Stake

| Parameter | Value |
|-----------|-------|
| Minimum stake | 10,000,000 DNAC |
| Lock type | Self-lock (ownership degismez) |
| Unlock | Witness gorevinden ayrilirsa, 7 gun unbonding |
| Enforcement | Bootstrap period sonrasi zorunlu |

**Witness olmak icin:**
1. 10M DNAC'a sahip ol
2. `STAKE_LOCK` TX ile coin'leri kilitle (witness kendi adresine)
3. Witness olarak aktif ol

**Witness olmaktan cikmak icin:**
1. `STAKE_UNLOCK` TX gonder
2. 7 gun unbonding period baslar
3. Unbonding bitince UTXO serbest kalir
4. Witness statusu hemen duser (unbonding basladiginda)

---

## 2. User Delegation

| Parameter | Value |
|-----------|-------|
| Minimum delegation | Yok (herhangi miktar) |
| Lock type | Delegate-lock (ownership degismez, voting power devredilir) |
| Unbonding | 7 gun |
| Reward | Epoch sonunda, oransal |

**Delegation akisi:**
1. User `DELEGATE` TX gonderir (miktar + hedef witness fingerprint)
2. UTXO kilitlenir, witness'in toplam stake'ine eklenir
3. Her epoch sonunda fee reward oransal dagitilir
4. `UNDELEGATE` TX ile 7 gun unbonding baslar

**Witness Commission:**
- Her witness kendi commission oranini belirler (orn. %10)
- Commission orani on-chain kayitlidir
- Degisiklik bir sonraki epoch'tan itibaren gecerli

---

## 3. Fee Model

| Parameter | Value |
|-----------|-------|
| Fee rate | %0.1 (transfer miktarinin) |
| Fee currency | Transfer edilen token cinsinden |
| Fee destination | Burn DEGIL — delegator/witness'lara dagitilir |

**Ornek:**
```
Alice -> Bob: 1000 MEME token
Fee: 1 MEME (%0.1)
Bob alir: 999 MEME
1 MEME -> epoch fee pool'a gider
```

**Fee dagitimi (epoch batch, her 1 saat):**
```
epoch_fee_pool = sum(tum TX fee'leri, token bazinda)

Her token icin:
  witness_share = fee * witness_commission_rate
  delegator_pool = fee - witness_share
  
  her_delegator_reward = delegator_pool * (delegator_stake / total_stake)
```

**Not:** Delegator'lar DNAC stake eder ama reward olarak cesitli token'lar alir. DNAC stake orani reward dagitim oranini belirler.

---

## 4. Reward Kaynagi

| Source | Description |
|--------|-------------|
| Fee redistribution | Ana kaynak — tum TX fee'leri staker'lara |
| Inflation | YOK (su an icin) |

Ileride governance ile dusuk inflation eklenebilir (erken donem tesvik).

---

## 5. Slashing: Jail-Only Model

| Durum | Ceza |
|-------|------|
| Double-sign | Jail (stake yanmaz) |
| Uzun sure offline | Jail (stake yanmaz) |
| Normal offline | Reward almaz |

**Jail mekanizmasi:**
- Kotu davranan witness jail'e girer
- Jail suresi: configurable (orn. 168 epoch = 7 gun)
- Jail'deyken: reward yok, witness gorevleri yok
- Jail bitince: otomatik aktif (stake hala kilitli)
- Delegator'lar jail'deki witness'tan etkilenmez (stake guvenli, sadece reward durur)

---

## 6. Bootstrap Period

| Parameter | Value |
|-----------|-------|
| Duration | 720 epoch (30 gun) |
| Stake required | HAYIR (bootstrap surecinde) |
| Genesis stake | YOK — normal supply dagitimi |

**Akis:**
```
Genesis Block:
  -> Normal supply dagitimi (lock yok, stake yok)

Bootstrap Period (30 gun):
  -> Witness olmak icin stake gerekmez
  -> Witness'lar DNAC edinir
  -> Witness'lar istege bagli 10M lock yapabilir
  
Bootstrap Biter (block height veya epoch):
  -> 10M self-lock olmayan witness duser
  -> Delegation aktif olur
  -> Fee redistribution baslar
```

---

## 7. Atomic Swap (HTLC)

Hash Time-Locked Contract — iki taraf birbirine guvenmeden token takas eder.

**TX Tipleri:**
- `HTLC_CREATE` — hash lock + time lock ile UTXO olustur
- `HTLC_CLAIM` — preimage ile UTXO'yu claim et
- `HTLC_REFUND` — timeout sonrasi geri al

**Akis (Alice: DNAC, Bob: MEME):**
```
1. Alice secret uretir, hash = SHA3-512(secret)
2. Alice HTLC_CREATE: 100 DNAC -> Bob, hashlock=hash, timelock=24h
3. Bob HTLC_CREATE: 500 MEME -> Alice, hashlock=hash, timelock=12h
4. Alice HTLC_CLAIM: secret ile 500 MEME'yi alir (secret on-chain aciga cikar)
5. Bob HTLC_CLAIM: aciga cikan secret ile 100 DNAC'yi alir
6. Timeout: taraf claim yapmazsa HTLC_REFUND ile geri alir
```

**Guvenlik:**
- Bob'un timelock'u Alice'inkinden kisa olmali (Alice once claim yapmak zorunda)
- Secret aciga cikmadan Bob claim yapamaz
- Timeout sonrasi refund garantili

---

## 8. Predefined Smart Contract Templates

Full VM yok. Sabit contract tipleri TX olarak implement edilir:

| Template | TX Type | Kullanim |
|----------|---------|----------|
| Stake Lock | `STAKE_LOCK` | Witness self-stake |
| Stake Unlock | `STAKE_UNLOCK` | Witness cikisi (unbonding baslatir) |
| Delegate | `DELEGATE` | User delegation |
| Undelegate | `UNDELEGATE` | Delegation geri cekme (unbonding) |
| HTLC Create | `HTLC_CREATE` | Atomic swap baslat |
| HTLC Claim | `HTLC_CLAIM` | Atomic swap claim |
| HTLC Refund | `HTLC_REFUND` | Atomic swap timeout refund |

Ileride eklenebilir: MULTISIG, TIMELOCK, ESCROW.

---

## 9. Yeni TX Tipleri (Ozet)

Mevcut:
- `GENESIS` (0)
- `SPEND` (1)  
- `BURN` (2)
- `TOKEN_CREATE` (3)

Yeni:
- `STAKE_LOCK` (4)
- `STAKE_UNLOCK` (5)
- `DELEGATE` (6)
- `UNDELEGATE` (7)
- `HTLC_CREATE` (8)
- `HTLC_CLAIM` (9)
- `HTLC_REFUND` (10)
- `REWARD_DISTRIBUTE` (11) — epoch sonunda witness tarafindan olusturulur

---

## 10. Chain Reset

- Mevcut chain (9 block) silinecek
- Yeni genesis ile temiz baslangic
- Tum yeni TX tipleri genesis'ten itibaren desteklenir
- Bootstrap period genesis'ten baslar

---

## 11. Witness Veri Yapilari (Yeni)

**Stake Registry (witness tarafinda):**
```
stake_entry {
    fingerprint     // witness FP
    amount          // locked DNAC miktari
    lock_height     // kilitlenme block height
    status          // ACTIVE | UNBONDING | UNLOCKED
    unbond_epoch    // unbonding baslangic epoch (0 = aktif)
}
```

**Delegation Registry:**
```
delegation_entry {
    delegator_fp    // delegator fingerprint
    witness_fp      // hedef witness fingerprint
    amount          // delegate edilen DNAC
    delegate_height // delegation block height
    status          // ACTIVE | UNBONDING
    unbond_epoch    // unbonding baslangic epoch
}
```

**Fee Pool (epoch bazinda):**
```
epoch_fee_pool {
    epoch_number
    token_id        // hangi token
    total_fee       // toplanan fee miktari
    distributed     // dagitildi mi
}
```

**Witness Config:**
```
witness_config {
    fingerprint
    commission_rate // 0-100 (%)
    min_self_stake  // 10,000,000 DNAC
    jail_until      // jail bitis epoch (0 = aktif)
}
```

---

## Karar Ozeti

| # | Karar | Secim |
|---|-------|-------|
| 1 | Smart contract model | Predefined templates (full VM yok) |
| 2 | Witness requirement | 10M DNAC self-lock (bootstrap sonrasi) |
| 3 | Bootstrap period | 720 epoch (30 gun), stake zorunlu degil |
| 4 | Genesis stake | Yok — normal dagitim |
| 5 | User delegation | DNAC delegate to witness |
| 6 | Fee rate | %0.1, transfer edilen token cinsinden |
| 7 | Fee destination | Delegator/witness'lara dagitilir (burn degil) |
| 8 | Fee dagitim zamani | Epoch batch (1 saat) |
| 9 | Witness commission | Witness belirler, on-chain |
| 10 | Slashing | Jail-only (stake yanmaz) |
| 11 | Unbonding period | 7 gun (168 epoch) |
| 12 | Atomic swap | HTLC (create/claim/refund) |
| 13 | Chain | Reset |
