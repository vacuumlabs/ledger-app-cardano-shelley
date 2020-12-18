# Sign Transaction

**Description**

Given transaction inputs and transaction outputs (addresses + amounts), fee, ttl, staking certificates, reward withdrawals, and metadata hash, construct and sign a transaction.

Due to Ledger constraints and potential security implications (parsing errors), Cardano Ledger app uses a custom format for streaming the transaction to be signed. The main rationale behind not streaming directly the (CBOR-encoded) cardano raw transaction to Ledger is the following:
1) The app needs to support BIP44 change address outputs (Ledger should not display user's own change addresses to the user as this degrades UX).
2) Serializing is easier than parsing. This is true especially if transaction chunks would not be aligned with processing (e.g., inputs/outputs arbitrarily split between multiple APDUs). This also allows a potentially smaller memory footprint on the device.
3) SignTx communication protocol is more extensible in the future.
4) Potential security improvement --- because SignTx does not output the serialized transaction, only the witnesses, the host app is responsible for serializing the transaction itself. Any serialization mismatch between host and Ledger would result in a transaction which is rejected by nodes.

**SignTx Limitations**

- Output address size is limited to ~200 bytes (single APDU). (Note: IOHK is fine with address size limit of 100 bytes)
- Addresses that are not shown to the user are base addresses with spending path `m/1852'/1815'/account'/{0,1}/changeIndex` and the standard staking key `m/1852'/1815'/account'/2/0`, where values of `account` and `changeIndex` are limited (for now, `0 <= account < 20` and `0 <= changeIndex <= 1 000 000`). This makes it feasible to brute-force all change addresses in case an attacker manages to modify change address(es). (As the user does not confirm change addresses, it is relatively easy to perform MITM attack).
- Only transactions with at least one input and at least one output will be signed (these provide protection against certificate replays and transaction replays on different networks).

**Communication protocol non-goals:**

The communication protocol is designed to *ease* the Ledger App implementation (and simplify potential edge conditions). As such, the protocol might need more APDU exchanges than strictly necessary. We deem this as a good tradeoff between implementation and performance (after all, the bottleneck are user UI confirmations).

Given these requirements in mind, here is how transaction signing works:

## Signing

Transaction signing consists of an exchange of several APDUs. During this exchange, Ledger keeps track of its current internal state, so APDU messages have to be sent in the order of increasing P1 values, and the entities in the transaction body are serialized in the same order as the messages are received (this applies for inputs, outputs, certificates and withdrawals).

By BIP44, we refer here both to the original BIP44 scheme and its Cardano Shelley analogue using 1852' in place of 44'.

**General command**

|Field|Value|
|-----|-----|
| CLA | `0xD7` |
| INS | `0x21` |
|  P1 | signing phase |
|  P2 | (specific for each subcall) |

### 1 - Initialize signing

Initializes signing request.

**Command**

|Field|Value|
|-----|-----|
|  P1 | `0x01` |
|  P2 | unused |

**Data**

|Field| Length | Comments|
|------|-----|-----|
| network id                | 1 | |
| protocol magic            | 4 | Big endian |
| include metadata          | 1 | `SIGN_TX_METADATA_NO=0x01` / `SIGN_TX_METADATA_YES=0x02` |
| number of tx inputs       | 4 | Big endian |
| number of tx outputs      | 4 | Big endian |
| number of tx certificates | 4 | Big endian |
| number of tx withdrawals  | 4 | Big endian |
| number of tx witnesses    | 4 | Big endian |

### 2 - Set UTxO inputs

**Command**

|Field|Value|
|-----|-----|
|  P1 | `0x02` |
|  P2 | unused |
| data | see below |

**Data**

|Field| Length | Comments|
|-----|--------|--------|
|tx id (hash) | 32 | |
|output index |  4 | Big endian |


### 3 - Set outputs & amounts

**Command**

|Field|Value|
|-----|-----|
|  P1 | `0x03` |
|  P2 | unused |
| data | Tx output, data depending on type |

**Data for SIGN_TX_OUTPUT_TYPE_ADDRESS**

This output type is used for regular destination addresses.

|Field| Length | Comments|
|-----|--------|--------|
|Amount| 8| Big endian. Amount in Lovelace|
|Output type| 1 | `SIGN_TX_OUTPUT_TYPE_ADDRESS=0x01`|
|Address| variable | raw address (before bech32/base58-encoding)|

**Data for SIGN_TX_OUTPUT_TYPE_ADDRESS_PARAMS**

This output type is used for change addresses. Depending (mostly) on staking info, these might or might not be shown to the user. 
(See [src/securityPolicy.c](../src/securityPolicy.c) for details.)

|Field| Length | Comments|
|-----|--------|--------|
|Amount| 8| Big endian. Amount in Lovelace|
|Output type| 1 | `SIGN_TX_OUTPUT_TYPE_ADDRESS_PARAMS=0x02`|
|Address params | variable | see `parseAddressParams` in [src/addressUtilsShelley.c](../src/addressUtilsShelley.c)|

 
### 4 - Fee

User needs to confirm the given fee.

|Field|Value|
|-----|-----|
|  P1 | `0x04` |
|  P2 | (unused) |

**Data**

|Field| Length | Comments|
|-----|--------|--------|
|Amount| 8| Big endian. Amount in Lovelace|

### 5 - TTL


|Field|Value|
|-----|-----|
|  P1 | `0x05` |
|  P2 | (unused) |

**Data**

|Field| Length | Comments|
|-----|--------|--------|
|TTL| 8| Big endian. Absolute slot number (not relative to epoch)|

### 6 - Certificate

We support three types of certificates: stake key registration, stake key deregistration, stake delegation.

|Field|Value|
|-----|-----|
|  P1 | `0x06` |
|  P2 | (unused) |

**Data for CERTIFICATE_TYPE_STAKE_REGISTRATION**

|Field| Length | Comments|
|-----|--------|--------|
|Output type| 1 | `CERTIFICATE_TYPE_STAKE_REGISTRATION=0x00`|
|Staking key path| variable | BIP44 path. See [GetExtPubKey call](ins_get_extended_public_key.md) for a format example |

**Data for CERTIFICATE_TYPE_STAKE_DEREGISTRATION**

|Field| Length | Comments|
|-----|--------|--------|
|Output type| 1 | `CERTIFICATE_TYPE_STAKE_DEREGISTRATION=0x01`|
|Staking key path| variable | BIP44 path. See [GetExtPubKey call](ins_get_extended_public_key.md) for a format example |

**Data for CERTIFICATE_TYPE_STAKE_DELEGATION**

|Field| Length | Comments|
|-----|--------|--------|
|Output type| 1 | `CERTIFICATE_TYPE_STAKE_DELEGATION=0x02`|
|Staking key path| variable | BIP44 path. See [GetExtPubKey call](ins_get_extended_public_key.md) for a format example |
|Pool key hash| 28 | Hash of staking pool public key|


### 7 - Reward withdrawal

Withdrawals from reward accounts.

|Field|Value|
|-----|-----|
|  P1 | `0x07` |
|  P2 | (unused) |

**Data**

|Field| Length | Comments|
|-----|--------|--------|
| Amount | 8 | Big endian |
| Staking key path| variable | BIP44 path. See [GetExtPubKey call](ins_get_extended_public_key.md) for a format example |

### 8 - Metadata

Ledger cannot parse and display metadata in full because their structure is too loose and their memory footprint potentially too big.
So only the hash is transferred and displayed and the user has to use other means of verification that the hash is correct.

|Field|Value|
|-----|-----|
|  P1 | `0x08` |
|  P2 | (unused) |

**Data**

|Field| Length | Comments|
|-----|--------|--------|
| Metadata hash | 32 | |

### 9 - Final confirmation

Depending on `policyForSignTxConfirm` in [src/securityPolicy.c](../src/securityPolicy.c), the user is asked to confirm the transaction after seeing all its components.

|Field|Value|
|-----|-----|
|  P1 | `0x09` |
|  P2 | (unused) |
| data | (none) |

### 10 - Compute witnesses

Given a valid BIP44 path (or its Shelley analogue), sign TxHash by Ledger. Return the signature.

The caller is responsible for assembling the actual witness (the format is different for Shelley and legacy Byron witnesses).

**Command**

|Field|Value|
|-----|-----|
|  P1 | `0x0a` |
|  P2 | (unused) |
| data | BIP44 path. See [GetExtPubKey call](ins_get_extended_public_key.md) for a format example |

**Response**

|Field|Length| Comments|
|-----|-----|-----|
|Signature|32| Witness signature.|
