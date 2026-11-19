// Copyright (c) 2026 Stacks Open Internet Foundation
// SPDX-License-Identifier: GPL-3.0-only

//! Errors from Bitcoin script construction and parsing.

use bitcoin::ScriptBuf;

/// Bitcoin primitive errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A v2 deposit script did not start with the expected canonical prefix.
    #[error("invalid v2 deposit prefix: expected {expected}, got {actual}")]
    InvalidDepositPrefix {
        /// The prefix supplied by the deposit script.
        actual: ScriptBuf,
        /// The canonical prefix implied by the recipient and maximum fee.
        expected: ScriptBuf,
    },
    /// The v2 signing threshold is invalid for the number of signers.
    #[error("invalid v2 deposit threshold {signatures_required} for {signer_count} signers")]
    InvalidDepositThreshold {
        /// The requested signing threshold.
        signatures_required: u16,
        /// The number of distinct signing keys.
        signer_count: usize,
    },
    /// A v2 signer key set contains more keys than the protocol supports.
    #[error("v2 signer key set contains {signer_count} keys; the maximum is {max_signers}")]
    TooManySignerKeys {
        /// The number of distinct signing keys supplied.
        signer_count: usize,
        /// The maximum supported number of signing keys.
        max_signers: usize,
    },
    /// A v2 signer UTXO script did not have the canonical `multi_a` form.
    #[error("invalid v2 signer script")]
    InvalidSignerScript,
    /// This happens when we realize that the lock-time in the reclaim
    /// script disables the OP_CSV check.
    #[error("invalid lock-time: {0}")]
    DisabledLockTime(#[source] bitcoin::locktime::relative::DisabledLockTimeError),
    /// The end of the deposit script has a fixed format that is very
    /// similar to a P2PK check_sig script, the script violated that format
    #[error("script is CHECKSIG part of script")]
    InvalidDepositCheckSigPart,
    /// The deposit script was invalid
    #[error("invalid deposit script")]
    InvalidDepositScript,
    /// Length of the deposit script is necessarily too short.
    #[error("script is invalid, it is too short")]
    InvalidDepositScriptLength,
    /// The reclaim script was invalid because it was too long.
    #[error("the reclaim script was too long: {0} bytes")]
    InvalidReclaimScriptLength(usize),
    /// The lock time included in the reclaim script was invalid. This
    /// could be because the number is out of range for an acceptable lock
    /// time, or because the 32nd bit has been set.
    #[error("the lock time included in the reclaim script was invalid: {0}")]
    InvalidReclaimScriptLockTime(i64),
    /// The reclaim script was invalid.
    #[error("the reclaim script format was invalid")]
    InvalidReclaimScript,
    /// The reclaim script lock time was invalid
    #[error("reclaim script lock time was either too large or non-minimal: {0}")]
    ScriptNum(#[source] bitcoin::script::Error),
    /// The X-only public key was invalid
    #[error("the x-only public key in the script was invalid: {0}")]
    InvalidXOnlyPublicKey(#[source] secp256k1::Error),
    /// The deposit script was non-standard because it did not follow the
    /// minimal push rule.
    #[error("deposit script did not follow the minimal push rule")]
    NonMinimalPushDepositScript,
    /// This happens when the lock-time is given in time units instead of
    /// block units.
    #[error("lock-time given in time units, but only block units are supported: {0}")]
    UnsupportedLockTimeUnits(u32),
    /// The reclaim script contained an OP_SUCCESSx opcode.
    #[error("the reclaim script contained an OP_SUCCESSx opcode: {0}")]
    ReclaimScriptWithSuccessOp(bitcoin::ScriptBuf),
}
