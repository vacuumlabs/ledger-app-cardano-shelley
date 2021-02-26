# Get Public Keys

**Description**

Get an extended public key (i.e., public key + chain code) for a given BIP32 path. 

It is also possible to ask for a confirmation for exporting several keys (if the paths describing the keys are not suspicious, they won't be shown to the user and no further confirmation is required).

Note: Unlike BTC app, this call does not return nor display addresses. See [](ins_derive_address.md) for details.


**Command**

For the initial APDU message, use

| Field | Value    |
| ----- | -------- |
| CLA   | `0xD7`   |
| INS   | `0x10`   |
| P1    | `0x00`   |
| P2    | unused   |
| Lc    | variable |

For each of the following messages (one for each of the remaining keys), use `0x01` for P1.

*Data*

For the initial APDU message, use

| Field                             | Length | Comments                           |
| --------------------------------- | ------ | ---------------------------------- |
| BIP32 path len                    | 1      | min 2, max 10                      |
| First derivation index            | 4      | Big endian. Must be 44' or 1852'   |
| Second derivation index           | 4      | Big endian. Must be 1815'          |
| (optional) Third derivation index | 4      | Big endian                         |
| ...                               | ...    | ...                                |
| (optional) Last derivation index  | 4      | Big endian                         |
| (optional) No. of remaining keys  | 4      | Big endian                         |

For each of the following messages (one for each of the remaining keys), the last field (No. of remaining keys) must not be included.

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

**Ledger responsibilities**

- Check:
  - check P1 is valid
    - `P1 == 0`
  - check P2 is valid
    - `P2 == 0`
  - check data is valid:
    - `Lc >= 1` (we have path_len)
    - `1 + path_len * 4 == Lc`
  - check derivation path is valid and within Cardano BIP32 space
    - `path_len >= 3`
    - `path_len <= 10`
    - `path[0] == 44'` or `path[0] == 1852'` (' means hardened)
    - `path[1] == 1815'`
    - `path[2] is hardened` (`path[2]` is account number)
    - Ledger might impose more restrictions, see implementation of `policyForGetExtendedPublicKey` in [src/securityPolicy.c](../src/securityPolicy.c) for details
- calculate public key
- respond with public key
 
**TODOs**
- ❓(IOHK): Should we also support BTC app like token validation? (Note: Token validation is to prevent concurrent access to the Ledger by two different host apps which could confuse user into performing wrong actions)
- ❓(IOHK): Should we support permanent app setting where Ledger forces user to acknowledge public key retrieval before sending it to host? (Note: probably not in the first version of the app)
- ❓(IOHK): Should there be an option to show the public key on display? Is it useful in any way? (Note: probably not)
