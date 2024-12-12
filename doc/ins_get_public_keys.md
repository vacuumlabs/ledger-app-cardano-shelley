# Get Public Keys

**Description**

Get an extended public key (i.e., public key + chain code) for a given BIP32 path.

It is also possible to ask for a confirmation for exporting several keys (if the paths describing the keys are not suspicious,
they won't be shown to the user and no further confirmation is required).

The allowed derivation paths correspond to wallet keys (accounts, payment paths, staking paths) and pool cold keys, as described:

- [CIP 1852 - HD Wallets for Cardano](https://cips.cardano.org/cips/cip1852/);
- [CIP 1853 - HD Stake Pool Cold Keys for Cardano](https://cips.cardano.org/cips/cip1853/).

Note: Unlike BTC app, this call does not return nor display addresses. See [](ins_derive_address.md) for details.

**Command**

For the initial APDU message, use

| Field | Value    |
| ----- | -------- |
| CLA   | `0xD7`   |
| INS   | `0x10`   |
| P1    | `0x00`   |
| P2    | `0x00`   |
| Lc    | variable |

For each of the following messages (one for each of the remaining keys), use `0x01` for P1.

*Data*

For the initial APDU message, use

| Field                             | Length | Comments                                  |
| --------------------------------- | ------ | ----------------------------------------- |
| BIP32 path len                    | 1      | min 2, max 5                              |
| First derivation index            | 4      | Big endian. Must be 44', 1852' or 1853'   |
| Second derivation index           | 4      | Big endian. Must be 1815'                 |
| (optional) Third derivation index | 4      | Big endian                                |
| ...                               | ...    | ...                                       |
| (optional) Last derivation index  | 4      | Big endian                                |
| (optional) No. of remaining keys  | 4      | Big endian                                |

For each of the following messages (one for each of the remaining keys), the last field (No. of remaining keys)
must not be included.

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
- for more errors, see [errors](../src/common.h)

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
    - `path_len <= 5`
    - `path[0] == 44'` or `path[0] == 1852'` or `path[0] == 1853'` (' means hardened)
    - `path[1] == 1815'`
    - Ledger might impose more restrictions; for details, see implementation of `policyForGetExtendedPublicKey` in [src/securityPolicy.c](../src/securityPolicy.c)
- calculate extended public key
- respond with extended public key

**TODOs**

- ❓(IOHK): Should we also support BTC app like token validation?
  (Note: Token validation is to prevent concurrent access to the Ledger by two different host apps
  which could confuse user into performing wrong actions)
