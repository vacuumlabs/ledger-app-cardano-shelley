# Change Log
All notable changes to this project will be documented in this file.
 
The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [2.2.0](https://github.com/LedgerHQ/app-cardano/compare/2.1.0...LedgerHQ:2.2.0) - [TBD]

Mary and Allegra hardfork-related changes. `signTransaction` call APDU changes are breaking, therefore it won't work properly with [https://www.npmjs.com/package/@cardano-foundation/ledgerjs-hw-app-cardano](ledgerjs-hw-app-cardano) version 2.1.0 and older.

### Added

- Support for Allegra-era transaction validity interval start property and transaction outputs containing native assets (Mary-era): https://github.com/vacuumlabs/ledger-app-cardano-shelley/pull/54

 
### Changed

- Transaction TTL is now optional, complying with Allegra hard-fork changes: https://github.com/LedgerHQ/app-cardano/pull/6/files
- Stake pool ID displayed as bech32 instead of hex, complying with [CIP0005](https://github.com/cardano-foundation/CIPs/blob/master/CIP-0005/CIP-0005.md): https://github.com/LedgerHQ/app-cardano/pull/6/files
- Accounts are numbered in the UI from 1, instead of from 0, to align with the way Ledger Live and Trezor displays account numbers: https://github.com/LedgerHQ/app-cardano/pull/6/files
- Updated docs: https://github.com/LedgerHQ/app-cardano/pull/6/files

### Fixed

## [2.1.0](https://github.com/LedgerHQ/app-cardano/compare/2.0.5...LedgerHQ:2.1.0) - [January 7th 2020]

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
