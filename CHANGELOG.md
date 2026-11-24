# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0](https://github.com/aicers/attrievent/compare/0.7.0...0.8.0) - 2026-11-24

### Other

- *(deps)* [**breaking**] raise review-protocol to 0.31.0 ([#76](https://github.com/aicers/attrievent/pull/76))

## [0.7.0](https://github.com/aicers/attrievent/compare/0.6.0...0.7.0) - 2026-11-23

### Other

- *(deps)* [**breaking**] raise review-protocol to 0.30.0 ([#73](https://github.com/aicers/attrievent/pull/73))

## [0.6.0](https://github.com/aicers/attrievent/compare/0.5.0...0.6.0) - 2026-11-23

### Other

- *(deps)* [**breaking**] raise review-protocol to 0.29.0 ([#69](https://github.com/aicers/attrievent/pull/69))

## [0.5.0](https://github.com/aicers/attrievent/compare/0.4.0...0.5.0) - 2026-11-22

### Added

- [**breaking**] use review-protocol's raw event kinds for attributes ([#65](https://github.com/aicers/attrievent/pull/65))

### Other

- update shared instruction blocks to 0.6.4 ([#64](https://github.com/aicers/attrievent/pull/64))
- update shared instruction blocks to 0.6.3 ([#61](https://github.com/aicers/attrievent/pull/61))
- automate releases with release-plz ([#58](https://github.com/aicers/attrievent/pull/58))
- Run CI on pull requests into any branch ([#54](https://github.com/aicers/attrievent/pull/54))
- Standardize the CI workflow ([#52](https://github.com/aicers/attrievent/pull/52))

## [0.4.0] - 2026-10-01

### Added

- Added `OptionCode` and `OptionData` variants to `DhcpAttr` for DHCP option
  TLV components.
- Added `DceRpcAttr` enum and `DceRpc` variant to `RawEventKind` and
  `RawEventAttrKind` for DCE/RPC protocol support.

## [0.3.0] - 2026-02-20

### Added

- Added `RadiusAttr` enum and `Radius` variant to `RawEventKind` and
  `RawEventAttrKind` for RADIUS protocol support.
- Added `Duration`, `OrigPkts`, `RespPkts`, `OrigL2Bytes`, and `RespL2Bytes`
  variants to all protocol attribute enums (except `ConnAttr`).

### Changed

- Modified `HttpAttr` to merge `OrigMimeTypes` and `RespMimeTypes` into
  `MimeTypes`, merge `OrigFilenames` and `RespFilenames` into `Filenames`,
  and rename `PostBody` to `Body`.

### Fixed

- Fixed typo in `DhcpAttr::MgsType` enum variant, renamed to
  `DhcpAttr::MsgType` for clarity and consistency with "Message Type".

## [0.2.1] - 2025-06-05

### Added

- Implemented the `Copy` trait for `RawEventKind`.

## [0.2.0] - 2025-05-19

### Added

- Renamed `referrer` to `referer` for consistency with the HTTP header field
  name.

## [0.1.0] - 2024-12-20

### Added

- Added a new enum type `RawEventAttrKind`. This type is created using the raw event
  type and raw event's attribute name, which is later used by the triage to
  perform a comparison of values.

[0.4.0]: https://github.com/aicers/attrievent/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/aicers/attrievent/compare/0.2.1...0.3.0
[0.2.1]: https://github.com/aicers/attrievent/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/aicers/attrievent/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/aicers/attrievent/tree/0.1.0
