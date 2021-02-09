# Sign Transaction

**Description**

Given transaction inputs and transaction outputs, fee, ttl, staking certificates, reward withdrawals, metadata hash, and validity interval start, construct and sign a transaction.

Due to Ledger constraints and potential security implications (parsing errors), Cardano Ledger app uses a custom format for streaming the transaction to be signed. The main rationale behind not streaming directly the (CBOR-encoded) cardano raw transaction to Ledger is the following:
1) The app needs to support BIP44 change address outputs (Ledger should not display user's own change addresses to the user as this degrades UX).
2) Serializing is easier than parsing. This is true especially if transaction chunks would not be aligned with processing (e.g., inputs/outputs arbitrarily split between multiple APDUs). This also allows a potentially smaller memory footprint on the device.
3) SignTx communication protocol is more extensible in the future.
4) Potential security improvement --- because SignTx does not output the serialized transaction, only the witnesses, the host app is responsible for serializing the transaction itself. Any serialization mismatch between host and Ledger would result in a transaction which is rejected by nodes.

**SignTx Limitations**

- Output address size is limited to ~200 bytes (single APDU). (Note: IOHK is fine with address size limit of 100 bytes)
- Addresses that are not shown to the user are base addresses with spending path `m/1852'/1815'/account'/{0,1}/changeIndex` and the standard staking key `m/1852'/1815'/account'/2/0`, where values of `account` and `changeIndex` are limited (for now, `0 <= account <= 100` and `0 <= changeIndex <= 1 000 000`). This makes it feasible to brute-force all change addresses in case an attacker manages to modify change address(es). (As the user does not confirm change addresses, it is relatively easy to perform MITM attack).
- Only transactions with at least one input will be signed (this provides protection against certificate replays and transaction replays on different networks).

**Communication protocol non-goals:**

The communication protocol is designed to *ease* the Ledger App implementation (and simplify potential edge conditions). As such, the protocol might need more APDU exchanges than strictly necessary. We deem this as a good tradeoff between implementation and performance (after all, the bottleneck are user UI confirmations).

Given these requirements in mind, here is how transaction signing works:

## Signing

Transaction signing consists of an exchange of several APDUs. During this exchange, Ledger keeps track of its current internal state, so APDU messages have to be sent in the order of increasing P1 values, and the entities in the transaction body are serialized in the same order as the messages are received. The Ledger maintains an internal state and refuses to accept APDU messages that are out of place by aborting the transaction being signed. (This also applies to outputs and pool registration certificates which are serialized in multiple steps.)

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

*Data*

|Field| Length | Comments|
|------|-----|-----|
| network id                                | 1 | |
| protocol magic                            | 4 | Big endian |
| include ttl                               | 1 | `SIGN_TX_INCLUDED_NO=0x01` / `SIGN_TX_INCLUDED_YES=0x02` |
| include metadata                          | 1 | `SIGN_TX_INCLUDED_NO=0x01` / `SIGN_TX_INCLUDED_YES=0x02` |
| include validity interval start           | 1 | `SIGN_TX_INCLUDED_NO=0x01` / `SIGN_TX_INCLUDED_YES=0x02` |
| is signing as pool registration owner     | 1 | `SIGN_TX_POOL_REGISTRATION_NO=0x03` / `SIGN_TX_POOL_REGISTRATION_YES=0x04` |
| number of tx inputs                       | 4 | Big endian |
| number of tx outputs                      | 4 | Big endian |
| number of tx certificates                 | 4 | Big endian |
| number of tx withdrawals                  | 4 | Big endian |
| number of tx witnesses                    | 4 | Big endian |

### 2 - Set UTxO inputs

**Command**

|Field|Value|
|-----|-----|
|  P1 | `0x02` |
|  P2 | unused |
| data | see below |

*Data*

|Field| Length | Comments|
|-----|--------|--------|
|tx id (hash) | 32 | |
|output index |  4 | Big endian |


### 3 - Set outputs

For each output, at least two messages are required: the first one with top-level data and the last one for confirmation. The messages in between them describe multiasset tokens if such are included in the output (one message for each asset group, followed by messages for tokens included in the group). The asset groups and tokens are serialized into their respective CBOR maps in the same order as they are received.

**Command (top-level output data)**

|Field|Value|
|-----|-----|
|  P1 | `0x03` |
|  P2 | `0x30` |
| data | depends on output type |

*Data for SIGN_TX_OUTPUT_TYPE_ADDRESS_BYTES*

This output type is used for regular destination addresses.

|Field| Length | Comments|
|-----|--------|--------|
|Output type| 1 | `SIGN_TX_OUTPUT_TYPE_ADDRESS_BYTES=0x01`|
|Address size| 4 | Big endian|
|Address| variable | raw address (before bech32/base58-encoding)|
|Amount| 8| Big endian. Amount in Lovelace|
|Number of asset groups| 4 | Big endian|

*Data for SIGN_TX_OUTPUT_TYPE_ADDRESS_PARAMS*

This output type is used for change addresses. Depending (mostly) on staking info, these might or might not be shown to the user. 
(See [src/securityPolicy.c](../src/securityPolicy.c) for details.)

|Field| Length | Comments|
|-----|--------|--------|
|Output type| 1 | `SIGN_TX_OUTPUT_TYPE_ADDRESS_PARAMS=0x02`|
|Address params | variable | see `view_parseAddressParams` in [src/addressUtilsShelley.c](../src/addressUtilsShelley.c)|
|Amount| 8| Big endian. Amount in Lovelace|
|Number of asset groups| 4 | Big endian|

**Command (asset group)**

|Field|Value|
|-----|-----|
|  P1 | `0x03` |
|  P2 | `0x31` |
| data | see below |

*Data*

|Field| Length | Comments|
|-----|--------|--------|
|minting policy id | 28 | |
|number of tokens |  4 | Big endian |

**Command (token)**

|Field|Value|
|-----|-----|
|  P1 | `0x03` |
|  P2 | `0x32` |
| data | see below |

*Data*

|Field| Length | Comments|
|-----|--------|--------|
|asset name size | 4 | Big endian |
|asset name |  variable | |
|amount |  8 | Big endian |

**Command (confirmation)**

|Field|Value|
|-----|-----|
|  P1 | `0x03` |
|  P2 | `0x33` |
| data | (none) |


 
### 4 - Fee

User needs to confirm the given fee.

|Field|Value|
|-----|-----|
|  P1 | `0x04` |
|  P2 | (unused) |

*Data*

|Field| Length | Comments|
|-----|--------|--------|
|Amount| 8| Big endian. Amount in Lovelace|

### 5 - TTL

Optional.

|Field|Value|
|-----|-----|
|  P1 | `0x05` |
|  P2 | (unused) |

*Data*

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

*Data*

|Field| Length | Comments|
|-----|--------|--------|
| Amount | 8 | Big endian |
| Staking key path| variable | BIP44 path. See [GetExtPubKey call](ins_get_extended_public_key.md) for a format example |

### 8 - Metadata

Optional.

Ledger cannot parse and display metadata in full because their structure is too loose and their memory footprint potentially too big.
So only the hash is transferred and displayed and the user has to use other means of verification that the hash is correct.

|Field|Value|
|-----|-----|
|  P1 | `0x08` |
|  P2 | (unused) |

*Data*

|Field| Length | Comments|
|-----|--------|--------|
| Metadata hash | 32 | |

### 9 - Validity interval start

Optional.

|Field|Value|
|-----|-----|
|  P1 | `0x09` |
|  P2 | (unused) |

*Data*

|Field| Length | Comments|
|-----|--------|--------|
|Validity interval start| 8| Big endian. Absolute slot number (not relative to epoch)|

### 9 - Final confirmation

Depending on `policyForSignTxConfirm` in [src/securityPolicy.c](../src/securityPolicy.c), the user is asked to confirm the transaction after seeing all its components.

|Field|Value|
|-----|-----|
|  P1 | `0x0a` |
|  P2 | (unused) |
| data | (none) |

### 10 - Compute witnesses

Given a valid BIP44 path (or its Shelley analogue), sign TxHash by Ledger. Return the signature.

The caller is responsible for assembling the actual witness (the format is different for Shelley and legacy Byron witnesses).

**Command**

|Field|Value|
|-----|-----|
|  P1 | `0x0f` |
|  P2 | (unused) |
| data | BIP44 path. See [GetExtPubKey call](ins_get_extended_public_key.md) for a format example |

**Response**

|Field|Length| Comments|
|-----|-----|-----|
|Signature|32| Witness signature.|
