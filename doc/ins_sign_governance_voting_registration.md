# Governance Voting Key Registration

## Description

Cardano uses a sidechain for its governance voting. One needs to "register" to participate on this sidechain by submitting a registration transaction on the Cardano blockchain. This is done by submitting a transaction with specific auxiliary data attached to the transaction body. These auxiliary data contain a signature by user's staking key, hence serialization of the it by Ledger is required which after confirming by the user returns that signature for the client software to be able to assemble the full serialized transaction.

For more details about governance voting registration see [CIP-0036](https://cips.cardano.org/cips/cip36/).

---

In the following list of APDU messages (which are to be sent in the listed order), we only give the value of P2 and the format of message data. The general format of the message is

|Field|Value|
|-----|-----|
| CLA | `0xD7` |
| INS | `0x21` |
|  P1 | `0x08` |
|  P2 | (specific for each subcall) |

All but the last response are empty. The last response contains the overall auxiliary data hash and the signature needed for the client to assemble the governance voting registration auxiliary data.

---

**Init**

P2 = `0x36`

*Data*

|Field| Length | Comments|
|-----|--------|---------|
|Governance voting registration format |  1 | 0x01 or 0x02 for CIP15 and CIP36, respectively|
|Number of delegations                 |  4 | big endian |

---

**Voting key**

A single APDU with voting key is sent if the number of delegations specified in the init APDU is 0 (otherwise no such APDU is allowed).

P2 = `0x30`

*Data*

|Field| Length | Comments|
|-----|--------|---------|
|Key type                                               |   1 | 0x01 or 0x02 if a 32-byte key or its derivation path follows |
|Voting public key: bytestring or BIP44 derivation path |     | (depends on previous line) |


**Delegation**

The number of delegation APDUs must be equal to the number of delegations specified in the init APDU.

P2 = `0x37`

*Data*

|Field| Length | Comments|
|-----|--------|---------|
|Key type                                               |   1 | 0x01 or 0x02 if a 32-byte key or its derivation path follows |
|Voting public key: bytestring or BIP44 derivation path |     | (depends on previous line) |
|Weight                                                 |   4 | big endian |

---

**Staking key**

P2 = `0x31`

*Data*

|Field| Length | Comments|
|-----|--------|---------|
|staking key path      | variable | BIP44 path. See [GetExtPubKey call](ins_get_extended_public_key.md) for a format example |

---

**Voting rewards address**

P2 = `0x32`

*Data*

|Field| Length | Comments|
|-----|--------|--------|
|Address params | variable | see `view_parseAddressParams` in [src/addressUtilsShelley.c](../src/addressUtilsShelley.c)|

Note: Only Shelley-era address parameters are accepted.

---

**Nonce**

P2 = `0x33`

*Data*

|Field| Length | Comments|
|-----|--------|--------|
|Nonce| 8| Big endian|

---

**Voting purpose**

For CIP36, this is optional; if not sent, voting purpose is set to the default 0.

For CIP15, this is not allowed (and no voting purpose is serialized).

P2 = `0x35`

*Data*

|Field         | Length | Comments  |
|--------------|--------|-----------|
|Voting purpose|       8| Big endian|

---

**Confirmation**

P2 = `0x34`

Data must be empty.

**Response**

|Field|Length| Comments|
|-----|-----|-----|
| Auxiliary data hash | 32 | Hash of the governance voting registration auxiliary data|
| Signature |64| Governance voting registration signature by the staking key that has been supplied|

Note: governance voting registration auxiliary data is serialized in the [Mary-era format](https://github.com/input-output-hk/cardano-ledger-specs/blob/dcdbc38eb9caea16485827bd095d5adcdcca0aba/shelley-ma/shelley-ma-test/cddl-files/shelley-ma.cddl#L214), where the array of auxiliary scripts is fixed to an empty array.
