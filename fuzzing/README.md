# Fuzzing tests

## Compilation

In `fuzzing` folder

```shell
cmake -DBOLOS_SDK=/path/to/sdk -DCMAKE_C_COMPILER=/usr/bin/clang -Bbuild -H.
```

then

```shell
make -C build
```

Harnesses built:

```shell
all_harness
deriveAddress_harness
deriveNativeScriptHash_harness
getPublicKeys_harness
signCVote_harness
signMsg_harness
signOpCert_harness
signTx_harness
```

## Run

To start fuzzing simply do `./build/<harness>` where `<harness>` is one of the files above. For instance

```shell
./build/deriveAddress_harness
```

Since there is an already existing corpus, to start fuzzing with it simply do `./build/<harness> ./corpus`

## Notes

For more context regarding fuzzing check out the app-boilerplate fuzzing [README.md](https://github.com/LedgerHQ/app-boilerplate/blob/master/fuzzing/README.md)
