# Derive Native Script Hash

**Description**

Given a native script, defined in the [Cardano CDDL](https://github.com/input-output-hk/cardano-ledger-specs/blob/master/shelley-ma/shelley-ma-test/cddl-files/shelley-ma.cddl#L228),
compute it's hash.

**Derive Native Script Hash Limitations**

The native script structure is recursive (with unlimited depth for nested scripts). Ledger, however, limits the depth to 10,
due to the limited memory available on Ledger.

## Derivation

A native script can be complex and contain nested native scripts. Therefore, the exchange can consist of multiple APDUs.
Ledger keeps track of the internal state and controls the correctness of the APDUs received.
If an unexpected or out of place APDU is received Ledger will abort the transaction.

Ledger internally distinguishes between two native script groups:

1. Complex native scripts - those which contain nested scripts (types: `ALL`, `ANY`, `N_OF_K`)
2. Simple native scripts - those which don't contain scripts (types: `PUBKEY`, `INVALID_BEFORE`, `INVALID_HEREAFTER`)

For those two script groups Ledger recognizes two different calls that can be combined to represent native scripts of arbitrary complexity:

1. [Start complex script](#start-complex-script)
2. [Add simple script](#add-simple-script)

After the whole native script is received, Ledger expects a finish call, which returns the computed native script hash:

* [Finish native script](#finish-native-script)

**General command**

| Field | Value        |
|-------|--------------|
| CLA   | `0xD7`       |
| INS   | `0x12`       |
| P1    | script phase (`0x01` to `0x03`, see below) |
| P2    | unused       |

### Start complex script

Marks the beginning of a complex native script.

**Command**

| Field | Value  |
|-------|--------|
| P1    | `0x01` |

*Data*

| Field | Length | Comments |
|-------|--------|----------|
| script type | 1 | Script type according to the [CDDL](https://github.com/input-output-hk/cardano-ledger-specs/blob/master/shelley-ma/shelley-ma-test/cddl-files/shelley-ma.cddl#L241) |
| number of nested scripts | 4 | |
| number of required nested scripts | 4 | Only when script type is `N_OF_K` |

The *number of required nested scripts* must be omitted for script types `ALL` and `ANY`.

### Add simple script

Adds a simple script.

**Command**

| Field | Value  |
|-------|--------|
| P1    | `0x02` |

*data*

#### `PUBKEY`

| Field | Length | Comments |
|-------|--------|----------|
| script type | 1 | Script type according to the [CDDL](https://github.com/input-output-hk/cardano-ledger-specs/blob/master/shelley-ma/shelley-ma-test/cddl-files/shelley-ma.cddl#L241) |
| pubkey type | 1 | See below for more info |
| pubkey path | variable | Only when *pubkey type* is `KEY_REFERENCE_PATH`, BIP44 path. See [Get Public Keys call](./ins_get_public_keys.md) for format example |
| pubkey hash | 28 | Only when *pubkey type* is `KEY_REFERENCE_HASH` |

This native script can be either specified by a key path if the public key is owned by the device (`KEY_REFERENCE_PATH = 1`)
and can be derived, or by a specifying the pubkey hash (`KEY_REFERENCE_HASH = 2`). This is encoded in the *pubkey type* field.

#### `INVALID_BEFORE`/`INVALID_HEREAFTER`

| Field | Length | Comments |
|-------|--------|----------|
| script type | 1 | Script type according to the [cddl](https://github.com/input-output-hk/cardano-ledger-specs/blob/master/shelley-ma/shelley-ma-test/cddl-files/shelley-ma.cddl#L241) |
| timelock | 8 | |

### Finish native script

Explicitly state the end of the whole native script and specify in what format should the native script hash be shown on Ledger.

**Command**

| Field | Value  |
|-------|--------|
| P1    | `0x03` |

*data*

| Field | Length | Comments |
|-------|--------|----------|
| display format | 1 | See below for possible values |

Display format can be:

* `0x01` for bech32 encoded hash
* `0x02` for hash shown as a policy id

*response*

| Field | Length | Comments |
|-------|--------|----------|
| Hash  | 28     | The native script hash |
