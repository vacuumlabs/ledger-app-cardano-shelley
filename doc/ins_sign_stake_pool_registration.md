# Stake Pool Registration

## Description

Stake pool registration certificates differ from other types of certificates in three respects:

1. The certificate data does not fit a single APDU message.
2. Transactions containing them are severely restricted due to security concerns about intermingling of witnesses
  (for instance, the same keys are used for witnessing a pool owner and a withdrawal).
3. Transactions containing them potentially need to be signed by several unrelated sets of keys,
  often managed by separate entities.

We therefore split the process into two separate workflows according to the so-called signing modes describing who is signing
the transaction (operator of the pool or one of its owners). The chosen signing mode is given in the initial message for
transaction signing (see [Stake Pool Registration](ins_sign_stake_pool_registration.md)). Note that the serialized transaction
must be the same for both flows, only the required witnesses and some user interactions differ.

The key derivation scheme for pool cold keys used by a pool operator is described in [CIP 1853 - HD Stake Pool Cold Keys for Cardano](https://cips.cardano.org/cips/cip1853/).

## Signing mode for pool operator

- Set by using `SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR=0x05` in the initial sign transaction APDU message
  (see [SignTx call](ins_sign_tx.md)).
- The pool registration transaction is paid for by the operator which is thus supposed to provide witnesses for inputs.
  An additional witness corresponds to pool id (signed by pool cold key).
- Pool id must be given by cold key derivation path.
- Pool owners must be given by hash (of the stake key).

## Signing mode for pool owner

- Set by using `SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER=0x04` in the initial sign transaction APDU message
  (see [SignTx call](ins_sign_tx.md)).
- Transaction outputs must be given by addresses (not address params) and are not shown to the user
  (because he is not funding the transaction). The fee is not shown either.
- Only a single witness is allowed (the key derivation path is the standard stake key path of the owner).
- It is necessary to include exactly one pool owner given by path in the certificate;
  all the other owners must be given by their respective key hashes.
- Pool id must be given by key hash.
- Some details (VRF key, pool relays) are not shown to the user.

---

In the following list of APDU messages (which are to be sent in the listed order), we only give the value of P2
and the format of message data. The general format of the message is

|Field|Value|
|-----|-----|
| CLA | `0xD7` |
| INS | `0x21` |
|  P1 | `0x06` |
|  P2 | (specific for each subcall) |

All the responses are empty.

---

**Init**

P2 = `0x30`

*Data*

|Field| Length | Comments|
|-----|--------|---------|
|number of owners |  4 | Big endian |
|number of relays |  4 | Big endian |

---

**Pool id**

P2 = `0x31`

*Data*

|Field| Length | Comments|
|-----|--------|---------|
|key reference type      |  1       | `KEY_REFERENCE_PATH=0x01` |
|pool cold key path      | variable | BIP44 path. See [GetExtColdKey call](ins_get_cold_key.md) for a format example |

|Field| Length | Comments|
|-----|--------|---------|
|key reference type      |  1  | `KEY_REFERENCE_HASH=0x02` |
|pool id (cold key hash) |  28 | |

---

**VRF key**

P2 = `0x32`

*Data*

|Field| Length | Comments|
|-----|--------|--------|
|VRF key hash  | 32 | |

---

**Pool financials**

P2 = `0x33`

|Field| Length | Comments|
|-----|--------|---------|
|pledge             |  8 | Big endian |
|cost               |  8 | Big endian |
|margin numerator   |  8 | Big endian |
|margin denominator |  8 | Big endian |

---

**Reward account**

P2 = `0x34`

|Field| Length | Comments|
|-----|--------|---------|
|key reference type    |  1       | `KEY_REFERENCE_PATH=0x01` |
|stake key path      | variable | BIP44 path. See [GetExtPubKey call](ins_get_public_keys.md) for a format example |

|Field| Length | Comments|
|-----|--------|---------|
|key reference type |  1 | `KEY_REFERENCE_HASH=0x02` |
|reward account     | 29 | (includes address header) |

---

**Owner**

P2 = `0x35`

|Field| Length | Comments|
|-----|--------|---------|
|key reference type    |  1       | `KEY_REFERENCE_PATH=0x01` |
|stake key path      | variable | BIP44 path. See [GetExtPubKey call](ins_get_public_keys.md) for a format example |

|Field| Length | Comments|
|-----|--------|---------|
|key reference type |   1 | `KEY_REFERENCE_HASH=0x02` |
|stake key hash   |  28 | |

---

**Relay**

P2 = `0x36`

|Field| Length | Comments|
|-----|--------|---------|
|relay format       |  1 | `RELAY_SINGLE_HOST_IP=0x00` |
|isPortGiven        |  1 | `ITEM_INCLUDED_NO=0x01` or `ITEM_INCLUDED_YES=0x02` |
|port               |  2 | Big endian; included if and only if isPortGiven is `ITEM_INCLUDED_YES` |
|isIpv4Given        |  1 | `ITEM_INCLUDED_NO=0x01` or `ITEM_INCLUDED_YES=0x02` |
|IP address v4      |  4 | byte buffer; included if and only if isIpv4Given is `ITEM_INCLUDED_YES` |
|isIpv6Given        |  1 | `ITEM_INCLUDED_NO=0x01` or `ITEM_INCLUDED_YES=0x02` |
|IP address v6      | 16 | byte buffer; included if and only if isIpv6Given is `ITEM_INCLUDED_YES` |

|Field| Length | Comments|
|-----|--------|---------|
|relay format       |  1 | `RELAY_SINGLE_HOST_NAME=0x01` |
|isPortGiven        |  1 | `ITEM_INCLUDED_NO=0x01` or `ITEM_INCLUDED_YES=0x02` |
|port               |  2 | Big endian; included if and only if isPortGiven is `ITEM_INCLUDED_YES` |
|dns name           | variable | byte buffer, max size 128 |

|Field| Length | Comments|
|-----|--------|---------|
|relay format       |  1 | `RELAY_MULTIPLE_HOST_NAME=0x02` |
|dns name           | variable | byte buffer, max size 128 |

---

**Pool metadata**

P2 = `0x37`

|Field| Length | Comments|
|-----|--------|---------|
|includeMetadata    |  1 | `ITEM_INCLUDED_NO=0x01` or `ITEM_INCLUDED_YES=0x02` |
|metadata hash      | 32 | byte buffer; only if includeMetadata is `ITEM_INCLUDED_YES` |
|metadata url       | variable | byte buffer, max size 128; only if includeMetadata is `ITEM_INCLUDED_YES` |

---

**Confirmation**

P2 = `0x38`

Data must be empty.
