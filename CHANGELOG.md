# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Nothing yet.

## [0.2.2] - 2022-12-01

### Fixed

- Re-release - forgot to update version in `Cargo.toml` for [0.2.1].
- Fixed punctuation in `CHANGELOG.md`. ([68df15d](https://github.com/LeoniePhiline/axum-csrf-sync-pattern/commit/68df15d63a9b3b9e4ccde84e34239bcba156629c))

## [0.2.1] - 2022-12-01

### Changed

- Updated to [`axum 0.6.1`](https://github.com/tokio-rs/axum/releases/tag/axum-v0.6.1).
- Updated to [`axum-sessions 0.4.1`](https://github.com/maxcountryman/axum-sessions/releases/tag/v0.4.1).
- Added links to dependency versions to ease dependents' work. ([57dbd72](https://github.com/LeoniePhiline/axum-csrf-sync-pattern/commit/57dbd72ba0cbd8ff29074d86f1480703d1cba9b1))

### Fixed

- Removed a duplicated word from `README.md`. ([09ead55](https://github.com/LeoniePhiline/axum-csrf-sync-pattern/commit/09ead55fef5d89f95d4ea444a206028a3539f5bb))

## [0.2.0] - 2022-11-29

### Added

- Added support for [`axum` 0.6](https://tokio.rs/blog/2022-11-25-announcing-axum-0-6-0),
  [`axum-core` 0.3](https://github.com/tokio-rs/axum/releases/tag/axum-core-v0.3.0)
  and [`axum-sessions` 0.4](https://github.com/maxcountryman/axum-sessions/releases/tag/v0.4.0).

### Changed

- Shortened middleware and layer names to `CsrfMiddleware` and `CsrfLayer`
  for improved DX and more elegant code.

  **Migration:** If you prefer to keep on using the old name(s) in your code base,
  the import them with an alias:

  ```rust
  use axum_csrf_sync_pattern::CsrfLayer as CsrfSynchronizerTokenLayer;

  // If you import the middleware:
  use axum_csrf_sync_pattern::CsrfMiddleware as CsrfSynchronizerTokenMiddleware;
  ```

- Re-licensed the project under Mozilla Public License 2.0,
  allowing for commercial use, while inciting contributions.
- Updated `tokio` from 1.21 to [1.22](https://github.com/tokio-rs/tokio/releases/tag/tokio-1.22.0).

### Removed

- Removed support for `axum` 0.5, `axum-core` 0.2 and `axum-sessions` 0.3.

## [0.1.4] - 2022-11-29

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

[unreleased]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/compare/0.2.2...HEAD
[0.2.2]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/compare/0.2.1...0.2.2
[0.2.1]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/compare/0.1.4...0.2.0
[0.1.4]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/compare/0.1.3...0.1.4
[0.1.3]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/compare/0.1.2...0.1.3
[0.1.2]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/compare/0.1.1...0.1.2
[0.1.1]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/releases/tag/0.1.0
