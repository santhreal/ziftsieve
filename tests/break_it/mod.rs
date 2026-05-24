//! Adversarial break-it tests for `ziftsieve` (many are expected red until hardening).
//!
//! Run the full matrix (gzip / snappy / zstd cases require optional parsers):
//! `cargo test -p ziftsieve --test break_it --all-features`

mod adversarial;
