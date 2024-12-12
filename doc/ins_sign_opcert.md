# Sign Operational Certificate

**Description**

Get a signature for a given operational certificate and a cold key path.

The signing algorithm is the same as for transaction witnesses.

The key derivation scheme for pool cold keys is described in [CIP 1853 - HD Stake Pool Cold Keys for Cardano](https://cips.cardano.org/cips/cip1853/).

**Command**

| Field | Value    |
| ----- | -------- |
| CLA   | `0xD7`   |
| INS   | `0x22`   |
| P1    | `0x00`   |
| P2    | `0x00`   |

*Data*

| Field                             | Length | Comments                           |
| --------------------------------- | ------ | ---------------------------------- |
| KES public key           | 32       | |
| KES period               |  8       | Big endian. |
| Issue counter            |  8       | Big endian. |
| Pool cold key path       | variable | BIP44 path. See [GetExtColdKey call](ins_get_cold_key.md) for a format example. |

There are restrictions on the path; see `policyForSignOpCert` in [src/securityPolicy.c](../src/securityPolicy.c) for the details.

**Response**

|Field|Length| Comments|
|-----|-----|-----|
|Signature|64| Operational certificate signature.|
