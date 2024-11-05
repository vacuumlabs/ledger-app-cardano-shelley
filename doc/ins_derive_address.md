# Derive Address

Derive a Shelley address (including legacy Byron addresses) and either return it, or show it to the user for confirmation.

The supported address types are given in the definition of `address_type_t` in [src/addressUtilsShelley.c](../src/addressUtilsShelley.c).

The derivation scheme is BIP44 for Byron `v2` addresses and an analogous scheme
(using `1852'` instead of `44'` in the derivation path) for the new Shelley addresses.
Most Shelley addresses also contain staking info. See `parseAddressParams` in [src/addressUtilsShelley.c](../src/addressUtilsShelley.c)
for the description of additional address parameters.

We expect this call to be used for the address verification purposes (i.e., matching address on Ledger with the one on the screen).

> Note: Unlike BTC Ledger app which returns both public key and the corresponding address in the same instruction call,
> we split these two functionalities as they serve different purposes. Notably:
>
> - `DeriveAddress` is weaker than `GetPublicKeys` (an extended public key allows deriving non-hardened child keys;
  an address does not, since it only contains hashes of public keys).
  As such, (in the future) the app might apply more restrictions/user confirmations to get the public key.
> - `GetAddress` is typically called only for the purpose of address verification.
  As such, it should belong to a valid address BIP32 path.
> - Note that implementations would typically call `GetAddress` with `P1_DISPLAY` to display the address to the user
  and `P1_RETURN` is usually not needed because the wallet anyway requested account's extended public key
  which enables it to derive all addresses. `P1_RETURN` can be used by paranoid users that do not want to expose
  account public key to the host yet they still want to be able to export individual addresses.

**Command**

| Field | Value                   |
| ----- | ----------------------- |
| CLA   | `0xD7`                  |
| INS   | `0x11`                  |
| P1    | request type: `P1_RETURN=0x01` for returning address to host, `P1_DISPLAY=0x02` for displaying address on the screen |
| P2    | unused                  |
| Lc    | variable                |

**Response**

| Field   | Length   |
| ------- | -------- |
| address | variable |

Where `address` is encoded in raw bytes (i.e. no base58 or bech32 encoding).

**Ledger responsibilities**

- The input gives address parameters which fully determine the address, including the staking information
  needed for most Shelley address types. See `parseAddressParams` in [src/addressUtilsShelley.c](../src/addressUtilsShelley.c)
  for the description of this variable-length entity.
- Restrictions on these parameters are given in `policyForReturnDeriveAddress`/`policyForShowDeriveAddress`
  in [src/securityPolicy.c](../src/securityPolicy.c) for details.
- If the request is to show the address, Ledger should wait before sending response.
  Note that until user confirms the address, Ledger should not process any subsequent instruction call.
