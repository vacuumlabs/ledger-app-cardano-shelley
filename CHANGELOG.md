# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).


## [6.0.2](TBD) - [TBD]

Support for CIP-36 voting

### Added

- export of vote keys (1694'/1815'/...)
- support for CIP-36 voting (signing of vote-cast fragments with 1694 keys)
- support for CIP-36 registrations (in transaction auxiliary data)

### Changed

- API for Catalyst voting registration (it is still possible to use CIP-15 in auxiliary data)
- updated list of native tokens recognized by the app with correct decimal places


## [5.0.0](https://github.com/LedgerHQ/app-cardano/compare/4.1.2...LedgerHQ:nanos_2.1.0_5.0.0) - [October 11th 2022]

Support for Babbage era

### Added

- support for all new Babbage era transaction elements

### Changed

- updated tickers for native tokens
- minor UI changes (e.g. Cardano logo added to the initial screen)


## [4.1.2](https://github.com/LedgerHQ/app-cardano/compare/v4.0.0...LedgerHQ:4.1.2) - [July 4th 2022]

Expert mode and token decimal places

### Added

- a menu option to enable/disable expert mode (until now, we displayed all the transaction details affecting security; from now on, most of those will only be displayed in expert mode; without expert mode turned on, only most important items are shown)
- displaying tickers and decimal places for a fixed list of popular native tokens (100 at the moment)

### Changed

- required signers are now allowed in ordinary and multisig transactions
- certain messages displayed to users have been changed to better fit on the screen


## [4.0.0](https://github.com/LedgerHQ/app-cardano/compare/3.0.0...LedgerHQ:v4.0.0) - [April 25th 2022]

Support for Alonzo era (Plutus scripts)

### Added

- support for all new Alonzo transaction elements
- support for stake credentials given by key hash
- a new transaction signing mode for Plutus transactions

### Changed

- the account on HD derivation path must be the same across the transaction elements (incl. witnesses)
- bech32 instead of hex in certain places in the UI as described in [CIP 5](https://cips.cardano.org/cips/cip5/)

### Fixed

- pool registration transaction witness must be consistent with the path of the owner (for `SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER`)
- wrong pool retirement epoch UI text


## [3.0.0](https://github.com/LedgerHQ/app-cardano/compare/2.4.1...LedgerHQ:3.0.0) - [October 8th 2021]

Script elements in transactions and support for native scripts

### Added

- support for multisig key derivation as described in [CIP 1854 - Multi-signatures HD Wallets](https://cips.cardano.org/cips/cip1854/)
- native script hash derivation call
- support for mint field in transaction body and corresponding key derivation paths from [CIP 1855 - Forging policy keys for HD Wallets](https://cips.cardano.org/cips/cip1855/)
- support for address types with script hashes (all Shelley address types are now supported)
- support for script elements in transactions (certficates etc.) within a new transaction signing mode
- validation of canonical ordering of cbor map keys (withdrawals, token policy ids in outputs and mint, asset names within an asset group)

### Changed

- serialization of certain APDU messages breaks backwards compatibility (mostly because paths were replaced with stake credentials)
- the limit on number of witnesses based on transaction body elements has been dropped


### Fixed

- public keys are now displayed in bech32 instead of hex strings
- certain assertions have been turned into proper validations


## [2.4.1](https://github.com/LedgerHQ/app-cardano/compare/2.3.2...LedgerHQ:2.4.1) - [June 29th 2021]

Support for signing pool registrations by operators.

### Added

- operational certificate signing
- new signing mode for transactions containing pool registration certificate: operators can sign such a transaction with the pool cold key
- in the new signing mode, pool relays and the VRF key are displayed to the user
- support for pool retirement certificates in ordinary transactions

### Changed

- public key derivation extended with pool cold key derivation, as described in [CIP 1853 - HD Stake Pool Cold Keys for Cardano](https://cips.cardano.org/cips/cip1853/)
- pool registration transactions have reworked APDU flow (not compatible with older version of the js library), but ordinary transactions are backwards-compatible

### Fixed

- Fixed pool id still being displayed as hex for stake delegations instead of bech32: https://github.com/vacuumlabs/ledger-app-cardano-shelley/pull/53#issuecomment-821971545


## [2.3.2](https://github.com/LedgerHQ/app-cardano/compare/2.2.1...LedgerHQ:2.3.2) - [May 10th 2021]

Add Catalyst voting registration metadata support

### Added

- Renamed metadata to auxiliary data (as per Mary-era [https://github.com/input-output-hk/cardano-ledger-specs/blob/e8f19bcc9c8f405131cb95ca6ada26b2b4eac638/shelley-ma/shelley-ma-test/cddl-files/shelley-ma.cddl#L16](CDDL)) and introduced a new type of auxiliary data, the Catalyst voting registration: https://github.com/LedgerHQ/app-cardano/pull/8

### Changed

### Fixed



## [2.2.1](https://github.com/LedgerHQ/app-cardano/compare/2.2.0...LedgerHQ:2.2.1) - [March 30th 2021]

Minor release updating the way of showing multiasset identifiers. No API changes.

### Added
 
### Changed

- In multiasset outputs, show bech32 asset fingerprints instead of their raw representation, complying with [https://github.com/cardano-foundation/CIPs/blob/master/CIP-0014/CIP-0014.md](CIP-0014): https://github.com/LedgerHQ/app-cardano/pull/7

### Fixed



## [2.2.0](https://github.com/LedgerHQ/app-cardano/compare/2.1.0...LedgerHQ:2.2.0) - [February 15th 2021]

Mary and Allegra hardfork-related changes. `signTransaction` call APDU changes are breaking, therefore it won't work properly with [https://www.npmjs.com/package/@cardano-foundation/ledgerjs-hw-app-cardano](ledgerjs-hw-app-cardano) version 2.1.0 and older.

### Added

- Support for Allegra-era transaction validity interval start property and transaction outputs containing native assets (Mary-era): https://github.com/vacuumlabs/ledger-app-cardano-shelley/pull/54

 
### Changed

- Transaction TTL is now optional, complying with Allegra hard-fork changes: https://github.com/LedgerHQ/app-cardano/pull/6/files
- Stake pool ID displayed as bech32 instead of hex, complying with [CIP0005](https://github.com/cardano-foundation/CIPs/blob/master/CIP-0005/CIP-0005.md): https://github.com/LedgerHQ/app-cardano/pull/6/files
- Accounts are numbered in the UI from 1, instead of from 0, to align with the way Ledger Live and Trezor displays account numbers: https://github.com/LedgerHQ/app-cardano/pull/6/files
- Updated docs: https://github.com/LedgerHQ/app-cardano/pull/6/files

### Fixed



## [2.1.0](https://github.com/LedgerHQ/app-cardano/compare/2.0.5...LedgerHQ:2.1.0) - [January 7th 2021]

Introduced support for stake pool registration certificates for stake pool owners. `signTransaction` call APDU changes are breaking, therefore it won't work properly with [https://www.npmjs.com/package/@cardano-foundation/ledgerjs-hw-app-cardano](ledgerjs-hw-app-cardano) 2.0.1 and older.

### Added

- Support for stake pool registration certificate as a pool owner: https://github.com/LedgerHQ/app-cardano/pull/4
d- Support bulk public key export: https://github.com/LedgerHQ/app-cardano/pull/4
 
### Changed

- Allow transactions without outputs: https://github.com/LedgerHQ/app-cardano/pull/5
- Show account number alongside the BIP32 derivation path in prompts to export account public key: https://github.com/LedgerHQ/app-cardano/pull/3

### Fixed




## [2.0.5](https://github.com/LedgerHQ/app-cardano/compare/2.0.4...LedgerHQ:2.0.5) - [November 6th 2020]
### Added
 
### Changed

### Fixed

- Compilation fixes related to Ledger Nano X




## [2.0.4](https://github.com/LedgerHQ/app-cardano/compare/2.0.3...LedgerHQ:2.0.4) - [August 21st 2020]

### Added
 
### Changed

### Fixed

- Serialize reward address instead of staking key into the withdrawals within the transaction body: https://github.com/LedgerHQ/app-cardano/pull/2




## [2.0.3](https://github.com/LedgerHQ/app-cardano/compare/2.0.2...LedgerHQ:2.0.3) - [July 31st 2020]

### Added

### Changed

### Fixed

- Fix ttl block/epoch calculation to reflect network parameter changes: https://github.com/LedgerHQ/app-cardano/pull/1




## [2.0.2](https://github.com/LedgerHQ/app-cardano/releases/tag/2.0.2) - [July 29th 2020]

First public release with Shelley-era support. Older, 1.x.x releases of this app are meant for the Byron-era Cardano blockchain and no longer work in the Shelley-era (and newer ones) of the Cardano blockchain.

### Added

### Changed

### Fixed
