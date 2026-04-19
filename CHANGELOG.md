# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->

## [Unreleased] <!-- release-date -->

### Changed

- Migrate to Rust Edition 2024. Minimum supported Rust version is now 1.85.
- Update `rand` to 0.10.

## [0.3.2] - 2024-04-05

### Added

- Configure `cargo nextest` and `cargo llvm-cov` to run in CI.
- Configure `cargo release`.

### Fixed

- Update dependencies.

## [0.3.1] - 2023-04-21

### Changed

- Update `README.md` to reflect semver-breaking `axum-sessions 0.5` update.
- Update crate version in `README.md`.

## [0.3.0] - 2023-04-21

### Breaking

- BREAKING: Update to [`axum-sessions 0.5`](https://github.com/maxcountryman/axum-sessions/releases/tag/v0.5.0).

### Added

- Create CI workflow, with `cargo check`, `cargo clippy`, `cargo fmt --check`, `cargo doc`, `cargo test` and `cargo sort --check`.
- Add dependencies status badge (https://deps.rs).

### Changed

- Remove `tower::util::ServiceExt::oneshot` from `README.md`, hinting instead merely at serving the app with `hyper::Server`. (#17, #20)
- Update library dependencies.
- Update `same-site` and `cross-site` example dependencies.

## [0.2.2] - 2022-12-01

### Fixed

- Re-release - fix missing version update in `Cargo.toml` for [0.2.1].
- Fix punctuation in `CHANGELOG.md`. ([68df15d](https://github.com/LeoniePhiline/axum-csrf-sync-pattern/commit/68df15d63a9b3b9e4ccde84e34239bcba156629c))

## [0.2.1] - 2022-12-01

### Changed

- Update to [`axum 0.6.1`](https://github.com/tokio-rs/axum/releases/tag/axum-v0.6.1).
- Update to [`axum-sessions 0.4.1`](https://github.com/maxcountryman/axum-sessions/releases/tag/v0.4.1).
- Add links to dependency versions to ease dependents' work. ([57dbd72](https://github.com/LeoniePhiline/axum-csrf-sync-pattern/commit/57dbd72ba0cbd8ff29074d86f1480703d1cba9b1))

### Fixed

- Remove a duplicated word from `README.md`. ([09ead55](https://github.com/LeoniePhiline/axum-csrf-sync-pattern/commit/09ead55fef5d89f95d4ea444a206028a3539f5bb))

## [0.2.0] - 2022-11-29

### Added

- Add support for [`axum 0.6`](https://tokio.rs/blog/2022-11-25-announcing-axum-0-6-0),
  [`axum-core 0.3`](https://github.com/tokio-rs/axum/releases/tag/axum-core-v0.3.0)
  and [`axum-sessions 0.4`](https://github.com/maxcountryman/axum-sessions/releases/tag/v0.4.0).

### Changed

- Shorten middleware and layer names to `CsrfMiddleware` and `CsrfLayer`
  for improved DX and more elegant code.

  **Migration:** If you prefer to keep on using the old name(s) in your code base,
  the import them with an alias:

  ```rust
  use axum_csrf_sync_pattern::CsrfLayer as CsrfSynchronizerTokenLayer;

  // If you import the middleware:
  use axum_csrf_sync_pattern::CsrfMiddleware as CsrfSynchronizerTokenMiddleware;
  ```

- Re-license the project under Mozilla Public License 2.0,
  allowing for commercial use, while inciting contributions.
- Update `tokio` from 1.21 to [1.22](https://github.com/tokio-rs/tokio/releases/tag/tokio-1.22.0).

### Removed

- Remove support for `axum` 0.5, `axum-core` 0.2 and `axum-sessions` 0.3.

## [0.1.4] - 2022-11-29

### Added

- Test code coverage and add tests covering the error path.
- Add `Cargo.toml` snippet for quick-installation to `README.md`.
- Add `CsrfSynchronizerTokenMiddleware::layer()` for the sake of convention.
- Add `CsrfSynchronizerTokenLayer::new()` for the sake of convention.
- Depend on the more stable `axum-core` where possible.
- Indicate project state with badges.
- Add a `CHANGELOG.md`.

### Changed

- Rewrite example / demo projects to never panic, but use appropriate error handling instead.
- Remove direct dependency on `async-session`, using the re-export from `axum-sessions` instead.

## [0.1.3] - 2022-11-24

### Fixed

- Properly link demo URL to help users find the frontend address after `cargo run`.

## [0.1.2] - 2022-11-23

### Changed

- Fix code style.

## [0.1.1] - 2022-11-23

### Changed

- Simplify example code.

## [0.1.0] - 2022-11-23

### Added

- Implement CSRF Synchronizer Token Middleware and Layer.
- Example / demo projects for same-site and cross-site usage.
- Add full crate documentation.

<!-- next-url -->
[Unreleased]: https://github.com/LeoniePhiline/basispoort-sync-client/compare/v0.3.2...HEAD
[0.3.2]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/compare/0.3.1...v0.3.2
[0.3.1]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/compare/0.3.0...0.3.1
[0.3.0]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/compare/0.2.2...0.3.0
[0.2.2]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/compare/0.2.1...0.2.2
[0.2.1]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/compare/0.1.4...0.2.0
[0.1.4]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/compare/0.1.3...0.1.4
[0.1.3]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/compare/0.1.2...0.1.3
[0.1.2]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/compare/0.1.1...0.1.2
[0.1.1]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/LeoniePhiline/axum-csrf-sync-pattern/releases/tag/0.1.0
