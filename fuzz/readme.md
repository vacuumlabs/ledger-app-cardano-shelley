# Cardano Fuzzer

## Building and fuzzing

### Linux

```shell
BOLOS_SDK=/path/to/sdk/ cmake -Bbuild -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DFUZZ=1
cd build
make
```

```shell
mkdir ../corpus
cp ../ref_corpus/* ../corpus/
./fuzzer ../corpus/
```

### Windows

```shell
$env:BOLOS_SDK = 'C:/path/to/sdk'       # (PowerShell)
cmake -Bbuild -GNinja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DFUZZ=1
cd build
ninja
```

```shell
mkdir ../corpus
copy ../ref_corpus/valid_tx ../corpus/valid_tx
./fuzzer.exe ../corpus/
```

## Coverage information

Generating coverage:

```
python3 coverage.py
```

Will output an HTML report in `./coverage/index.html`.