#!/bin/bash -eu

# build fuzzers

pushd fuzzing
cmake -DBOLOS_SDK=../BOLOS_SDK -Bbuild -H.
make -C build VERBOSE=1
mv build/*_harness $OUT
popd