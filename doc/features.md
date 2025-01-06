# Features (not) available on specific Ledger devices

Nano S has a very limited space for storing applications. It is not enough to fit all Cardano features there,
so some of them are only available on Nano S+ and other more spacious Ledger devices (e.g. Nano X and Stax).

The features not supported on Nano S, Cardano app version 7 and above:

* pool registration and retirement
* signing of operational certificates
* computation of native script hashes
* details in Byron change outputs (only the address is shown)

Details can be found in [Makefile](../Makefile) and in the code (search for compilation flags beginning with `APP_FEATURE_`).
