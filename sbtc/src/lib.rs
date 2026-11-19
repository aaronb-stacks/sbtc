// Copyright (c) 2026 Stacks Open Internet Foundation
// SPDX-License-Identifier: GPL-3.0-only

//! # SBTC Common Library
//!
//! This library provides common functionality for the sBTC project, including logging setup
pub mod deposits;
pub mod error;
pub mod events;
pub mod idpack;
pub mod leb128;
pub mod signer_keys;

pub use signer_keys::KeySetId;
pub use signer_keys::SignerKeySet;
pub use signer_keys::derive_signing_public_key;
pub use signer_keys::derive_signing_secret_key;

#[cfg(any(test, feature = "webhooks"))]
pub mod webhooks;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use sbtc_primitives::{
    MAX_RECLAIM_SCRIPT_LENGTH, MAX_SIGNERS, NUMS_X_COORDINATE, UNSPENDABLE_TAPROOT_KEY,
    V2_NUMS_X_COORDINATE, V2_UNSPENDABLE_TAPROOT_KEY, WITHDRAWAL_MIN_CONFIRMATIONS,
};
