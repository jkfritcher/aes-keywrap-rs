# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Changed

- Refactored instances of magic numbers into const variables for clarity.

## 0.1.2 (2024-05-18)

### Changed

- Replaced multiple vec!+copy_from_slice instance with Vec::with_capacity+extend_from_slice to avoid prefilling the buffer when its going to be immediately overwritten.
- Refactored several constant buffers to be const.

## 0.1.1 (2023-12-06)

### Changed

- Simplified calculations within the wrap and unwrap functions to improve readability
- Refactored aes function selection to remove duplication and simplify error handling
- Updated to Rust 2021

## 0.1.0 (2021-10-02)
Initial release of aes keywrap crate with padded and unpadded wrapping schemes
