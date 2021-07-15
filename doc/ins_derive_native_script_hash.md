# Derive Native Script Hash

**Description**

Given a native script compute it's hash.

**Derive Native Script Hash Limitations**

- The native script structure is recursive and could theoretically grow to infinite depth (depth as in the level of the nested script), Ledger enforces a limit on the depth to 10.

## Derivation

Native script can be complex and contains nested native scripts. Therefore, the exchange can consist of multiple APDUs. Ledger keeps track of the internal state and controls the correctness of the APDUs received. If an unexpected or out of place APDU is received ledger will abort the transaction.

Ledger internally distinguishes between two native script groups:
1. Complex native scripts - those which contain nested scripts (types: `ALL`, `ANY`, `N_OF_K`)
2. Simple native scripts - those which don't contain scripts (types: `PUBKEY`, `INVALID_BEFORE`, `INVALID_HEREAFTER`)

For those two script groups Ledger recognizes three different calls that can be combined to represent native script of arbitrary complexity:
1. [Start complex script](#start-complex-script)
2. [Add simple script](#add-simple-script)
3. [Finish complex script](#finish-complex-script)

A return value, the native script hash, is returned after Ledger receives the last APDU request. Whether the request is the last one is determined by Ledger's internal state and is not explicitly specified in the APDU request. The last APDU call might be:
* *Add simple script* call if the whole native script consist only of a single simple script
* *Finish complex script* call if it finishes the first started complex script
The response format for the last request is:

| Field | Length | Comments |
|-------|--------|----------|
| Hash  | 28     | The native script hash |

**General command**
| Field | Value        |
|-------|--------------|
| CLA   | `0xD7`       |
| INS   | `0x12`       |
| P1    | script phase |
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
| script type | 1 | Script type according to the [cddl](https://github.com/input-output-hk/cardano-ledger-specs/blob/master/shelley-ma/shelley-ma-test/cddl-files/shelley-ma.cddl#L241) |
| number of required scripts | 4 | Only when script type is `N_OF_K` |
| number of scripts | 4 | |

The *number_of_required_scripts* must be omitted for script types `ALL` and `ANY`.

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
| script type | 1 | Script type according to the [cddl](https://github.com/input-output-hk/cardano-ledger-specs/blob/master/shelley-ma/shelley-ma-test/cddl-files/shelley-ma.cddl#L241) |
| pubkey type | 1 | See below for more info |
| pubkey path | variable | Only when *pubkey type* is `DEVICE_OWNED`, BIP44 path. See [Get Public Keys call](./ins_get_public_keys.md) for format example |
| pubkey hash | 28 | Only when *pubkey type* is `THIRD PARTY` |

This native script can be either specified by a key path if the public key is owned by the device (`DEVICE_OWNED = 0`) and can be derived, or by a specifying the pubkey hash (`THIRD_PARTY = 1`). This is encoded in the *pubkey type* field.

#### `INVALID_BEFORE`/`INVALID_HEREAFTER`
| Field | Length | Comments |
|-------|--------|----------|
| script type | 1 | Script type according to the [cddl](https://github.com/input-output-hk/cardano-ledger-specs/blob/master/shelley-ma/shelley-ma-test/cddl-files/shelley-ma.cddl#L241) |
| timelock | 8 | |

### Finish complex script

Explicitly state the end of a complex script

**Command**
| Field | Value  |
|-------|--------|
| P1    | `0x03` |

*data*

No data

