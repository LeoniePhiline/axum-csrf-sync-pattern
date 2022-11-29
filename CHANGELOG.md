# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Tested code coverage and added tests covering the error path.
- Added `Cargo.toml` snippet for quick-installation to `README.md`.
- Added `CsrfSynchronizerTokenMiddleware::layer()` for the sake of convention.
- Added `CsrfSynchronizerTokenLayer::new()` for the sake of convention.
- Now depending on the more stable `axum-core` where possible.
- Now indicating project state with badges.
- Added a `CHANGELOG.md`.

### Changed

- Rewrote example / demo projects to never panic, but use appropriate error handling instead.
- Removed direct dependency on `async-session`, using the re-export from `axum-sessions` instead.

### Fixed

## [0.1.3] - 2022-11-24

### Fixed

- Properly linked demo URL to help users find the frontend address after `cargo run`.

## [0.1.2] - 2022-11-23

### Changed

- Fixed code style.

## [0.1.1] - 2022-11-23

### Changed

- Simplified example code.

## [0.1.0] - 2022-11-23

### Added

- Implemented CSRF Synchronizer Token Middleware and Layer.
- Example / demo projects for same-site and cross-site usage.
- Added full crate documentation.

[unreleased]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/compare/0.1.3...HEAD
[0.1.3]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/compare/0.1.2...0.1.3
[0.1.2]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/compare/0.1.1...0.1.2
[0.1.1]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/releases/tag/0.1.0
