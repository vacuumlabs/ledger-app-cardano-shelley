# Getting started

## Dependencies

- Install Docker
- Update [Dockerfile](../Dockerfile) if needed: check https://github.com/LedgerHQ/ledger-app-builder/blob/master/Dockerfile.
- Create Docker image

  `docker build -t ledger-app-builder-cardano:latest .`


## Compiling the app

### With CLI

Based on https://developers.ledger.com/docs/nano-app/build/.

### For Nano S

- Create container with the image

  `docker run --rm -ti -v "$(realpath .):/app" ledger-app-builder-cardano:latest`

- Run make commands

  `make clean`

  `make all`

  More make commands are listed in [README.md](../README.md#Make Commands)

#### For Nano S Plus or Nano X

Just set `BOLOS_SDK` before running `make`.

  `BOLOS_SDK=$NANOSP_SDK make`

  `BOLOS_SDK=$NANOX_SDK make`

Don't forget to run `make clean` when switching the SDK.

### With CLion

If you choose to use CLion as IDE, you can setup the Docker as toolchain
- Go to **Settings** -> **Build, Execution, Deployment** -> **Toolchains**

- Add new Toolchain by clicking **+** sign (or Alt+Insert)

- Choose Docker, and set `ledger-app-builder-cardano:latest` as image

- Make sure you set Docker as default toolchain by clicking `^` button, if there are no other toolchains set, skip this
step

- Save the changes, reload makefile. After project loads make commands will be listed on up right corner, near the build (hammer) icon
