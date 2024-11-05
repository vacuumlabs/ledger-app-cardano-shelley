# Cardano Ledger App

Cardano Ledger App for Ledger devices (Nano S, Nano S Plus, Nano X, Stax, Flex)

## Building

### Dependencies

We recommend using the containerized build. See [Getting started](doc/build.md) for details.

### Loading the app

We recommend using the [Ledger VS Code plugin](https://marketplace.visualstudio.com/items?itemName=LedgerHQ.ledger-dev-tools)
to load the app on a device.

### Debug version

In `Makefile`, uncomment

```Makefile
#DEVEL = 1
#DEFINES += HEADLESS
```

also comment out

```Makefile
DEFINES += RESET_ON_CRASH
```

The debug version is too big to fit on Nano S, but works on Speculos.

### Setup

Make sure you have:

- SDK >= 2.0.0
- MCU >= 1.11

Environment setup and developer documentation is sufficiently provided in Ledger’s [Read the Docs](https://developers.ledger.com/docs/device-app/getting-started).

You want a debug version of the MCU firmware (but it blocks SDK firmware updates, so for the purpose of upgrading SDK,
replace it temporarily with a non-debug one). Instructions for swapping MCU versions: [Debugging](https://github.com/LedgerHQ/ledger-dev-doc/blob/master/source/userspace/debugging.rst)

## Development

To learn more about development process and individual commands, [check the design doc](doc/design_doc.md).

## Deploying

The build process is managed with [Make](https://www.gnu.org/software/make/).

### Make Commands

- `load`: Load signed app onto the Ledger device
- `clean`: Clean the build and output directories
- `delete`: Remove the application from the device
- `build`: Build obj and bin api artefacts without loading
- `format`: Format source code.
- `analyze`: Run clang static analyzer (requires clang-tools)
- `size`: Prints the app size.

See `Makefile` for list of included functions.

`make load` results in an exception in the following cases (there might be others):

- the Ledger device is not connected
- the device is locked
- the device is in some intermediary state (e.g. processing an APDU message)
- the app is too big to fit on the device (try `make size`)

### Before merging a pull request

_Before merging a PR, one should make sure that:_

- `make format` does not change anything (except possibly some glyph* files)
- `make clean load` runs without errors and warnings (except those reported for nanos-secure-sdk repo) for production build
- `make clean load` runs without errors and warnings (except those reported for nanos-secure-sdk repo) for development build
  (see Debug version above)
- `make analyze` does not report errors or warnings

## Running tests

All the tests are initiated from the accompanying [ledgerjs package](https://github.com/vacuumlabs/ledgerjs-cardano-shelley)
(see what [commands to run](https://github.com/vacuumlabs/ledgerjs-cardano-shelley?tab=readme-ov-file#tests)).
You have to make sure that the version of ledgerjs correspond to the app version, otherwise some tests with fail
(possibly resulting in odd errors) or test coverage will be incomplete.

## How to get a transaction body computed by Ledger

Ledger computes a rolling hash of the serialized transaction body, but the body itself is ordinarily not available.
It is possible to acquire it from the development build by going through the following steps:

1. [Install debug MCU](https://developers.ledger.com/docs/nano-app/debug/#introduction) on your Ledger Nano S device.
2. Install the debug version of Cardano app (see above).
3. Install `usbtool` and turn on [console printing](https://developers.ledger.com/docs/nano-app/debug/#console-printing).
4. Send a single `signTx` call to Ledger (e.g. by running `yarn test-integration --grep "<some-signTx-test>"`).
5. After the call is processed, the terminal running console printing now contains all log messages resulting
  from that `signTx` call. (See the `TRACE*` macros.) Extract the transaction body logs (dumped by the function computing
  the rolling tx hash; you can identify them by function names following the pattern `blake2b_256_append*tx_body`)
  and merge them into a single hexstring. You can use the following javascript to achieve it:

    ```javascript
        const logfile = `<content of the log file>`
        console.log(logfile.split('\n').filter((x) => x.includes('blake2b_256_append'))
            .map((x) => x.split(' ')[3]).join(''))
    ```

    Replace `x.split(' ')[3]` with `x.split(' ')[1]` if you are running the tests on the physical device instead of Speculos.

    > WARNING: the output of tracing sometimes (although very rarely) gets slightly mangled on the physical device
    > (for instance, the output contains `blake2b_s56_append` instead of `blake2b_256_append`) and then the script
    > above produces an incorrect result.

6. Analyze the obtained output via [CBOR](https://cbor.me). The result of the decoding is close to valid json and can be
  pretty-printed by [JSON formatter](https://jsonformatter.curiousconcept.com) (replacing `h'` with `'` removes the errors).
