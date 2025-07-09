# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.25] - 2025-01-14

### Added
- **DLC Splicing functionality** - Enable using existing DLC funding outputs as inputs to new DLCs
  - `DlcInputInfo` struct to represent existing DLC funding outputs for reuse
  - Enhanced `PartyParams` with `dlc_inputs_info` field for DLC inputs
  - `CreateSplicedDlcTransactions` function for creating DLCs with spliced inputs
  - Complete signing workflow for multisig DLC inputs (`SignDlcFundingInput`, `GetRawDlcFundingInputSignature`, `VerifyDlcFundingInputSignature`)
  - Support for three splicing scenarios:
    - **Splice-in**: Add additional funds to create larger DLC
    - **Splice-out**: Remove funds to create smaller DLC  
    - **DLC transition**: Change oracle, terms, or participants while reusing funds
- **Comprehensive input validation** for DLC splicing
  - Zero amount validation for DLC inputs
  - Public key uniqueness validation (local != remote)
  - Dust limit enforcement (546 satoshi minimum)
  - Party-specific error messaging for better debugging
- **Extensive test coverage** with 11 new test cases covering:
  - Basic splicing functionality
  - DLC input signature creation and verification
  - All splicing scenarios (splice-in, splice-out, DLC transition)
  - Input validation edge cases
  - Mixed regular and DLC input scenarios
- **Single-funded DLC transactions** - Support for DLCs where one party provides all funding
  - Automatic filtering of dust change outputs from funding transactions
  - Proper fee distribution between funding and non-funding parties
  - Support for no-change single-funded DLCs for enhanced privacy
  - Comprehensive test coverage for single and batch single-funded DLCs

### Changed
- **Fee calculation** updated to account for DLC input weights (~220 bytes per P2WSH multisig)
- **Input sorting** maintains compatibility with existing serial ID ordering system
- **Error handling** improved with party-specific validation messages
- **CI/CD improvements** - Modernized GitHub Actions workflow
  - Updated Windows runner from windows-2019 to windows-latest
  - Upgraded Visual Studio generator from VS 16 2019 to VS 17 2022
  - Updated all actions/checkout from v2 to v4

### Fixed
- Fee computation for single-funded DLCs with proper distribution
- Windows build compatibility issues

### Technical Details
- DLC inputs are converted to regular transaction inputs with proper serial ID ordering
- Signature ordering based on public key lexicographic order for deterministic multisig
- Maintains full backward compatibility with existing DLC transaction creation
- Proper weight calculation for P2WSH multisig inputs

## [0.0.24] - 2025-05-29

### Changed
- Updated libwally-core to cfd-0.3.9 for ARM64 building support

## [0.0.23] - 2025-05-26

### Added
- GitHub Actions CI/CD pipeline with comprehensive workflows
- Automated testing and linting in CI
- Documentation generation automation

### Changed
- Updated CFD dependency to v0.3.27
- Improved cpplint configuration and error handling
- Enhanced code formatting and linting rules

## [0.0.22] - 2025-05-25

### Changed
- Reverted CFD dependency back to v0.3.26 for compatibility

## [0.0.21] - 2025-05-25

### Changed
- Updated CFD dependency to v0.4.3

## [0.0.20] - 2025-05-25

### Changed
- Bumped CMake minimum version requirement to 3.15
- Fixed iOS CMake toolchain configuration

## [0.0.19] - 2024-04-11

### Fixed
- Batch CET fee rounding calculation for more accurate fee distribution

## [0.0.18] - 2024-04-10

### Fixed
- Batch fee computation error logic for improved accuracy

## [0.0.17] - 2024-01-19

### Added
- Support for refund locktime lists in batch DLC transactions
- Justfile for simplified development workflow

## [0.0.16] - 2024-01-19

### Added
- Batch DLC transaction functionality
- Support for creating multiple DLC contracts in a single transaction
- Batch funding transaction creation
- Batch CET and refund transaction generation

### Changed
- Enhanced transaction creation API to support batch operations

## [0.0.15] - 2024-01-15

### Added
- Clang-format configuration for improved code readability
- Standardized code formatting across the project
- Updated indent width to 2 spaces for consistency

## Previous Versions

For changes prior to v0.0.15, please refer to the Git commit history.

---

## Release Notes

### v0.0.25 - DLC Splicing Release

This release introduces a major new feature: **DLC Splicing**. This allows existing DLC funding outputs to be used as inputs for new DLCs, enabling dynamic fund management without requiring on-chain settlements.

**Key Benefits:**
- **Capital Efficiency**: Reuse locked funds without closing existing DLCs
- **Seamless Transitions**: Change oracle, terms, or participants while maintaining funding
- **Flexible Scenarios**: Support for adding funds (splice-in), removing funds (splice-out), or pure transitions

**Protocol Integration:**
- Compatible with existing DLC offer/accept/sign flow
- DLC inputs require both parties' signatures (2-of-2 multisig)
- Maintains backward compatibility with regular DLC transactions

**Security:**
- Comprehensive input validation prevents invalid transactions
- Proper signature ordering ensures deterministic multisig behavior  
- Dust limit enforcement prevents uneconomical transactions

This release significantly enhances the DLC protocol's flexibility and usability for dynamic contract management scenarios.
