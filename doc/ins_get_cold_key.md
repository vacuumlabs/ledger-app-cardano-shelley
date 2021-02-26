# Get Public Cold Key

**Description**

Get an extended public cold key (i.e., public key + chain code) for a given BIP32 path.

These keys are used for operations with stake pools (registration and retirement).
The key derivation scheme for pool cold keys is described in [CIP 1853 - HD Stake Pool Cold Keys for Cardano](https://cips.cardano.org/cips/cip1853/).

**Command**

| Field | Value    |
| ----- | -------- |
| CLA   | `0xD7`   |
| INS   | `0x12`   |
| P1    | `0x00`   |
| P2    | `0x00`   |

*Data*

| Field                             | Length | Comments                           |
| --------------------------------- | ------ | ---------------------------------- |
| BIP32 path len                    | 1      | min 2, max 10                      |
| First derivation index            | 4      | Big endian. Must be 1853'          |
| Second derivation index           | 4      | Big endian. Must be 1815'          |
| Third derivation index            | 4      | Big endian.                        |
| ...                               | ...    | ...                                |
| (optional) Last derivation index  | 4      | Big endian                         |

There are additional restrictions on the path; see `policyForGetPoolColdPublicKey` in [src/securityPolicy.c](../src/securityPolicy.c) for the details.

**Response**

This format applies to both the initial APDU message and each of the following messages.

| Field      | Length |
| ---------- | ------ |
| pub_key    | 32     |
| chain_code | 32     |

Concatenation of `pub_key` and `chain_code` representing the extended public key.

**Errors (SW codes)**

- `0x9000` OK
- `0x6E10` Request rejected by app policy
- `0x6E09` Request rejected by user
- for more errors, see [src/errors.h](../src/errors.h)

