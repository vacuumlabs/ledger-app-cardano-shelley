# Get Device Serial Number

**Description**

Gets the serial number of the Ledger device.
Could be called at any time.

**Command**

|Field|Value|
|-----|-----|
| INS | `0x01` |
| P1 | unused |
| P2 | unused |
| Lc | 0 |

**Response**

|Field|Length|
|------|-----|
|serial| 7 |

The returned value is bytes exactly as written by the system call `os_serial()`.

**Ledger responsibilities**

- Check:
  - Check `P1 == 0`
  - Check `P2 == 0`
  - Check `Lc == 0`
- Respond with serial number
