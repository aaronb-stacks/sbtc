// Copyright (c) 2026 Stacks Open Internet Foundation
// SPDX-License-Identifier: GPL-3.0-only

//! This is the transaction analysis module
//!

use std::collections::BTreeSet;

use bitcoin::Address;
use bitcoin::Network;
use bitcoin::Script;
use bitcoin::ScriptBuf;
use bitcoin::XOnlyPublicKey;
use bitcoin::hashes::Hash as _;
use bitcoin::hashes::sha256;
use bitcoin::locktime::relative::LockTime;
use bitcoin::opcodes::Class;
use bitcoin::opcodes::ClassifyContext;
use bitcoin::opcodes::all as opcodes;
use bitcoin::script::Instruction;
use bitcoin::script::PushBytesBuf;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::NodeInfo;
use bitcoin::taproot::TaprootSpendInfo;
use secp256k1::SECP256K1;

use crate::MAX_RECLAIM_SCRIPT_LENGTH;
use crate::SignerKeySet;
use crate::error::Error;

/// This flag, from bitcoin-core, determines the following:
/// * If the input to OP_CSV has this bit set, then OP_CSV is treated as a
///   NOP, effectively disabling the opcode when executing the script [^1].
/// * It fails OP_CSV/CheckSequence() for any input that has it set (BIP
///   112) [^2]. Note: Transaction inputs have an nSequence field that is
///   different from the one referenced in the above bullet point.
/// * If this flag is set, CTxIn::nSequence is NOT interpreted as a
///   relative locktime.
/// * It skips SequenceLocks() for any input that has it set (BIP 68).
///
/// The last two bullets were taken from [^3].
///
/// [^1]: <https://github.com/bitcoin/bitcoin/blob/v27.1/src/script/interpreter.cpp#L560-L592>
/// [^2]: <https://github.com/bitcoin/bitcoin/blob/v27.1/src/script/interpreter.cpp#L1737-L1782>
/// [^3]: <https://github.com/bitcoin/bitcoin/blob/v27.1/src/primitives/transaction.h#L89-L98>
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;

/// The OP_CHECKSEQUENCEVERIFY opcode described in
/// https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki
const OP_CSV: u8 = opcodes::OP_CSV.to_u8();
/// Represents the number 1.
const OP_PUSHNUM_1: u8 = opcodes::OP_PUSHNUM_1.to_u8();
/// Represents the number 16.
const OP_PUSHNUM_16: u8 = opcodes::OP_PUSHNUM_16.to_u8();
/// Represents the number -1.
const OP_PUSHNUM_NEG1: u8 = opcodes::OP_PUSHNUM_NEG1.to_u8();

/// Construct the expected taproot info for a v1 deposit UTXO from its
/// deposit and reclaim scripts.
pub fn to_taproot(deposit_script: ScriptBuf, reclaim_script: ScriptBuf) -> TaprootSpendInfo {
    let internal_key = *crate::UNSPENDABLE_TAPROOT_KEY;
    taproot_with_internal_key(deposit_script, reclaim_script, internal_key)
}

/// Construct the expected taproot info for a v2 deposit UTXO.
pub fn to_v2_taproot(deposit_script: ScriptBuf, reclaim_script: ScriptBuf) -> TaprootSpendInfo {
    let internal_key = *crate::V2_UNSPENDABLE_TAPROOT_KEY;
    taproot_with_internal_key(deposit_script, reclaim_script, internal_key)
}

/// Construct deposit spend information using the supplied internal key.
fn taproot_with_internal_key(
    deposit_script: ScriptBuf,
    reclaim_script: ScriptBuf,
    internal_key: XOnlyPublicKey,
) -> TaprootSpendInfo {
    let ver = LeafVersion::TapScript;
    // For such a simple tree, we construct it by hand.
    let leaf1 = NodeInfo::new_leaf_with_ver(deposit_script, ver);
    let leaf2 = NodeInfo::new_leaf_with_ver(reclaim_script, ver);
    // A Result::Err is returned by NodeInfo::combine if the depth of
    // our taproot tree exceeds the maximum depth of taproot trees,
    // which is 128. We have two nodes so the depth is 1 so this will
    // never panic.
    let node = NodeInfo::combine(leaf1, leaf2).expect("Tree depth is greater than the max of 128");

    TaprootSpendInfo::from_node_info(SECP256K1, internal_key, node)
}

/// Create the expected ScriptPubKey for v1 deposit and reclaim scripts.
pub fn to_script_pubkey(deposit_script: ScriptBuf, reclaim_script: ScriptBuf) -> ScriptBuf {
    let merkle_root = to_taproot(deposit_script, reclaim_script).merkle_root();
    // Deposit transactions use a NUMS (nothing up my sleeve) public
    // key for the key-spend path of taproot scripts.
    let internal_key = *crate::UNSPENDABLE_TAPROOT_KEY;
    ScriptBuf::new_p2tr(SECP256K1, internal_key, merkle_root)
}
/// Construct a bitcoin address for a v1 deposit UTXO on the given
/// network.
pub fn p2tr_address(
    deposit_script: ScriptBuf,
    reclaim_script: ScriptBuf,
    network: Network,
) -> Address {
    let internal_key = *crate::UNSPENDABLE_TAPROOT_KEY;
    let merkle_root = to_taproot(deposit_script, reclaim_script).merkle_root();
    Address::p2tr(SECP256K1, internal_key, merkle_root, network)
}

/// Create the expected ScriptPubKey for a v2 deposit output.
pub fn to_v2_script_pubkey(deposit_script: ScriptBuf, reclaim_script: ScriptBuf) -> ScriptBuf {
    let merkle_root = to_v2_taproot(deposit_script, reclaim_script).merkle_root();
    // Deposit transactions use a NUMS (nothing up my sleeve) public
    // key for the key-spend path of taproot scripts.
    let internal_key = *crate::V2_UNSPENDABLE_TAPROOT_KEY;
    ScriptBuf::new_p2tr(SECP256K1, internal_key, merkle_root)
}

/// This struct contains the key variable inputs when constructing a
/// deposit script address.
///
/// The caller must supply the consensus serialization of a valid `PrincipalData`,
/// which already bounds its size. External callers enforce this at the integration
/// boundary using their own Clarity types; these builders do not validate bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositScriptInputs {
    /// The last known public key of the signers.
    pub signers_public_key: XOnlyPublicKey,
    /// The consensus-encoded standard or contract principal receiving the deposit.
    pub recipient: Vec<u8>,
    /// The max fee amount to use for the BTC deposit transaction.
    pub max_fee: u64,
}

impl DepositScriptInputs {
    /// Construct a bitcoin address for a deposit UTXO on the given
    /// network and reclaim script.
    pub fn to_address(&self, reclaim_script: ScriptBuf, network: Network) -> Address {
        let deposit_script = self.deposit_script();
        p2tr_address(deposit_script, reclaim_script, network)
    }

    /// Construct a deposit script from the inputs
    pub fn deposit_script(&self) -> ScriptBuf {
        // The format of the OP_DROP data, as shown in
        // https://github.com/stacks-network/sbtc/issues/30, is 8 bytes for
        // the max fee followed by up to 151 bytes for the stacks address.
        let recipient_bytes = self.recipient.as_slice();
        let mut op_drop_data = PushBytesBuf::with_capacity(recipient_bytes.len() + 8);
        // These should never fail. The PushBytesBuf type only
        // errors if the total length of the buffer is greater than
        // u32::MAX. We're pushing a max of 159 bytes.
        op_drop_data
            .extend_from_slice(&self.max_fee.to_be_bytes())
            .expect("8 is greater than u32::MAX?");
        op_drop_data
            .extend_from_slice(recipient_bytes)
            .expect("159 is greater than u32::MAX?");
        // When using the bitcoin::script::Builder, push_slice
        // automatically inserts the appropriate opcodes based on the data
        // size to be pushed onto the stack. Here, OP_PUSHBYTES_32 is
        // pushed before the public key. Also, OP_PUSHBYTES_N is used if
        // the OP_DROP data length is between 1 and 75 otherwise
        // OP_PUSHDATA1 is used since the data length is less than 255.
        ScriptBuf::builder()
            .push_slice(op_drop_data)
            .push_opcode(opcodes::OP_DROP)
            .push_slice(self.signers_public_key.serialize())
            .push_opcode(opcodes::OP_CHECKSIG)
            .into_script()
    }
}

/// This struct contains the key variable inputs when constructing a v2
/// deposit script.
///
/// The recipient must be a valid consensus-serialized principal, as in
/// [`DepositScriptInputs`].
///
/// # Accepted deposit script
///
/// An acceptable script has exactly the following form:
///
/// ```text
/// OP_SIZE 32 OP_EQUALVERIFY
/// OP_SHA256 <32-byte commitment> OP_EQUALVERIFY
/// <key 1> OP_CHECKSIG
/// <key 2> OP_CHECKSIGADD
/// ...
/// <key n> OP_CHECKSIGADD
/// <signatures required> OP_NUMEQUAL
/// ```
///
/// All values use their minimal Bitcoin Script encodings. The keys are
/// distinct 32-byte x-only public keys in sorted order, n is between 1 and
/// [`crate::MAX_SIGNERS`], and `signatures required` is between 1 and n.
///
/// # Deposit-data commitment
///
/// The recipient and maximum fee are supplied off chain. The script
/// commits to them as follows, where `||` denotes concatenation and the
/// recipient uses its Stacks consensus serialization:
///
/// ```text
/// deposit data = max_fee.to_be_bytes() || recipient.consensus_serialize()
/// preimage     = SHA256(deposit data)
/// commitment   = SHA256(preimage)
/// ```
///
/// So the deposit script embeds the commitment. When spending the deposit,
/// the signers reveal the 32-byte preimage. Parsing a deposit script
/// recomputes the commitment from the supplied recipient and maximum fee,
/// so a script is rejected if either value does not match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositScriptInputsV2 {
    /// The validated signer key set encoded by the deposit script.
    pub signer_key_set: SignerKeySet,
    /// The consensus-encoded Stacks principal committed to by the script.
    pub recipient: Vec<u8>,
    /// The maximum fee committed to by the script.
    pub max_fee: u64,
}

impl DepositScriptInputsV2 {
    /// Create validated v2 deposit inputs.
    pub fn new(
        signer_public_keys: BTreeSet<XOnlyPublicKey>,
        signatures_required: u16,
        recipient: Vec<u8>,
        max_fee: u64,
    ) -> Result<Self, Error> {
        let signer_key_set = SignerKeySet::new(signer_public_keys, signatures_required)?;

        Ok(Self {
            signer_key_set,
            recipient,
            max_fee,
        })
    }

    /// Return the hash embedded in the v2 deposit script.
    #[cfg(any(test, feature = "testing"))]
    pub fn commitment(&self) -> [u8; 32] {
        deposit_data_commitment(self.max_fee, &self.recipient)
    }

    /// Construct the v2 deposit leaf.
    ///
    /// The leaf is the fixed-length hash-lock prefix followed by the
    /// signers' `multi_a` script, which is exactly
    /// [`SignerKeySet::signing_script`].
    pub fn deposit_script(&self) -> ScriptBuf {
        let commitment = deposit_data_commitment(self.max_fee, &self.recipient);
        let mut bytes = v2_deposit_prefix(commitment).into_bytes();
        bytes.extend_from_slice(self.signer_key_set.signing_script().as_bytes());
        ScriptBuf::from_bytes(bytes)
    }

    /// Parse and validate the v2 deposit script against recipient and
    /// max-fee.
    pub fn parse(
        deposit_script: &ScriptBuf,
        recipient: Vec<u8>,
        max_fee: u64,
    ) -> Result<Self, Error> {
        let expected_prefix = v2_deposit_prefix(deposit_data_commitment(max_fee, &recipient));
        let (actual_prefix, signing_script) = deposit_script
            .as_bytes()
            .split_at_checked(expected_prefix.len())
            .ok_or(Error::InvalidDepositScriptLength)?;

        let actual_prefix = ScriptBuf::from_bytes(actual_prefix.to_vec());
        if actual_prefix != expected_prefix {
            return Err(Error::InvalidDepositPrefix {
                actual: actual_prefix,
                expected: expected_prefix,
            });
        }

        let signing_script = Script::from_bytes(signing_script);
        let signer_key_set = SignerKeySet::parse(signing_script).map_err(|error| match error {
            Error::InvalidSignerScript => Error::InvalidDepositScript,
            error => error,
        })?;

        Ok(Self {
            signer_key_set,
            recipient,
            max_fee,
        })
    }
}

/// Return the 32-byte preimage that a v2 deposit script commits to, and that
/// the signers reveal when spending the deposit.
///
/// The recipient must be a valid consensus-serialized principal, as in
/// [`DepositScriptInputs`].
pub fn deposit_data_preimage(max_fee: u64, recipient: &[u8]) -> [u8; 32] {
    let mut data = max_fee.to_be_bytes().to_vec();
    data.extend_from_slice(recipient);
    sha256::Hash::hash(&data).to_byte_array()
}

/// Return the hash committed to by a v2 deposit script.
///
/// The recipient must be a valid consensus-serialized principal, as in
/// [`DepositScriptInputs`].
pub fn deposit_data_commitment(max_fee: u64, recipient: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(&deposit_data_preimage(max_fee, recipient)).to_byte_array()
}

/// Return the hash-lock prefix of a v2 deposit script, which is
///
/// ```text
/// OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <commitment> OP_EQUALVERIFY
/// ```
pub fn v2_deposit_prefix(commitment: [u8; 32]) -> ScriptBuf {
    ScriptBuf::builder()
        .push_opcode(opcodes::OP_SIZE)
        .push_int(32)
        .push_opcode(opcodes::OP_EQUALVERIFY)
        .push_opcode(opcodes::OP_SHA256)
        .push_slice(commitment)
        .push_opcode(opcodes::OP_EQUALVERIFY)
        .into_script()
}

/// This struct contains the key variable inputs when constructing a
/// deposit script address.
///
/// This struct upholds the invariant that the `lock_time` is a valid and
/// standard locktime in bitcoin-core. We do not verify whether the
/// user-supplied script is correct and standard.
///
/// Currently, we only accept locktimes denominated in Bitcoin blocks. This
/// implies that bit (1 << 22) in the locktime, must be zero.
///
/// Note that locktimes used as `OP_CSV` inputs in the reclaim script only
/// use the 16 least significant bits for the value of the locktime. All
/// other bits in the 32-bit locktime must be zero or the deposit
/// transaction will fail validation. When we support time-based locktimes,
/// a user may set bit (1 << 22) to indicate that the locktime value is
/// time based, as described in BIP-68.
///
/// <https://github.com/bitcoin/bips/blob/17c04f9fa1ecae173d6864b65717e13dfc1880af/bip-0068.mediawiki#specification>
/// <https://github.com/bitcoin/bips/blob/812907c2b00b92ee31e2b638622a4fe14a428aee/bip-0112.mediawiki#summary>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimScriptInputs {
    /// This is the locktime used for the `OP_CSV` opcode in the reclaim
    /// script. It is not allowed to exceed the bounds expected for a
    /// 4-byte locktime in bitcoin-core. It is also not allowed to have
    /// the [`SEQUENCE_LOCKTIME_DISABLE_FLAG`] bit set.
    lock_time: LockTime,
    /// The reclaim script after the `<locked-time> OP_CSV` part of the
    /// script.
    script: ScriptBuf,
}

impl ReclaimScriptInputs {
    /// Create a new one, validating that:
    ///
    /// * the lock time is a non-disabled block-based time,
    /// * the user-supplied script is within the maximum length allowed
    ///   for a reclaim script,
    /// * the user-supplied script does not contain any OP_SUCCESSx
    ///   opcodes, see [BIP-342].
    ///
    /// [BIP-342]: https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki
    pub fn try_new(lock_time: u32, script: ScriptBuf) -> Result<Self, Error> {
        let lock_time = Self::validate_lock_time(lock_time)?;
        Self::validate_script(&script)?;

        Ok(Self { lock_time, script })
    }

    /// Create a new one, but without validating the user-supplied script.
    ///
    /// The lock time is still validated; only the script-content checks
    /// performed by [`Self::validate_script`] are skipped. This is used
    /// to construct otherwise-rejected reclaim scripts in tests that
    /// exercise the validation logic itself.
    #[cfg(any(test, feature = "testing"))]
    pub fn try_new_unvalidated(lock_time: u32, script: ScriptBuf) -> Result<Self, Error> {
        let lock_time = Self::validate_lock_time(lock_time)?;

        Ok(Self { lock_time, script })
    }

    /// Validate the lock time used in the `<lock-time> OP_CSV` prefix of
    /// the reclaim script.
    ///
    /// OP_CSV checks can be disabled if the lock time has the disabled
    /// lock-time bit set, so we reject any such lock time to ensure that
    /// the OP_CSV check is always enforced. We also reject time-based
    /// (as opposed to block-height-based) lock times since we do not yet
    /// support them.
    ///
    /// <https://github.com/bitcoin/bitcoin/blob/v27.1/src/script/interpreter.cpp#L560-L592>
    fn validate_lock_time(lock_time: u32) -> Result<LockTime, Error> {
        let lock_time = LockTime::from_consensus(lock_time).map_err(Error::DisabledLockTime)?;

        // For now, we only accept locktimes denominated in bitcoin block
        // units.
        if matches!(lock_time, LockTime::Time(_)) {
            return Err(Error::UnsupportedLockTimeUnits(
                lock_time.to_consensus_u32(),
            ));
        }

        Ok(lock_time)
    }

    /// Validate the user-supplied portion of a reclaim script.
    ///
    /// This is the script that follows the `<lock-time> OP_CSV` prefix. We
    /// require:
    ///
    /// * its length is at most [`MAX_RECLAIM_SCRIPT_LENGTH`] bytes, and
    /// * it does not contain any OP_SUCCESSx opcodes.
    ///
    /// We reject OP_SUCCESSx in order for the OP_CSV lock to be
    /// meaningful. BIP-342[1] states that any tapscript containing such an
    /// opcode is unconditionally valid, which would let a depositor spend
    /// the reclaim path without satisfying the lock-time.
    ///
    /// [1]: <https://github.com/bitcoin/bips/blob/554be702d7d28e3cd1cbf2e84c153f041fdde898/bip-0342.mediawiki>
    fn validate_script(script: &ScriptBuf) -> Result<(), Error> {
        if script.len() > MAX_RECLAIM_SCRIPT_LENGTH {
            return Err(Error::InvalidReclaimScriptLength(script.len()));
        }

        // We mirror bitcoin-core's pre-execution scan for OP_SUCCESSx
        // opcodes in tapscript.
        //
        // For the corresponding bitcoin-core logic, see the following:
        // <https://github.com/bitcoin/bitcoin/blob/v27.1/src/script/interpreter.cpp#L1784-L1807>
        // <https://github.com/bitcoin/bitcoin/blob/v27.1/src/script/script.cpp#L341-L347>
        let has_op_success_ops = script.instructions().any(|op| match op {
            Ok(Instruction::Op(opcode)) => {
                opcode.classify(ClassifyContext::TapScript) == Class::SuccessOp
            }
            _ => false,
        });

        if has_op_success_ops {
            return Err(Error::ReclaimScriptWithSuccessOp(script.clone()));
        }

        Ok(())
    }

    /// Get the lock time in the reclaim script.
    pub fn lock_time(&self) -> u32 {
        self.lock_time.to_consensus_u32()
    }

    /// Return the user supplied part of the script.
    ///
    /// The full reclaim script has the form:
    ///```text
    ///  <locked-time> OP_CHECKSEQUENCEVERIFY <rest-of-reclaim-script>
    /// ```
    /// where the user supplies `<rest-of-reclaim-script>`. This function
    /// returns `<rest-of-reclaim-script>`.
    pub fn user_script(&self) -> &Script {
        self.script.as_script()
    }

    /// Create the reclaim script from the inputs
    pub fn reclaim_script(&self) -> ScriptBuf {
        let mut lock_script = ScriptBuf::builder()
            .push_int(self.lock_time().into())
            .push_opcode(opcodes::OP_CSV)
            .into_script()
            .into_bytes();

        lock_script.extend(self.script.as_bytes());
        ScriptBuf::from_bytes(lock_script)
    }

    /// Parse the reclaim script for the lock time.
    ///
    /// The goal of this function is to make sure that there are no
    /// surprises in the reclaim script. These scripts are conceptually
    /// very simple and are their format is
    /// ```text
    ///  <locked-time> OP_CHECKSEQUENCEVERIFY <rest-of-reclaim-script>
    /// ```
    /// This function extracts the <locked-time> from the script. If the
    /// script does not start with <locked-time> OP_CHECKSEQUENCEVERIFY
    /// then we return an error.
    ///
    /// See https://github.com/stacks-network/sbtc/issues/30 for the
    /// expected format of the reclaim script. And see BIP-0112 for
    /// the details and input conditions of OP_CHECKSEQUENCEVERIFY:
    /// https://github.com/bitcoin/bips/blob/812907c2b00b92ee31e2b638622a4fe14a428aee/bip-0112.mediawiki#summary
    pub fn parse(reclaim_script: &ScriptBuf) -> Result<Self, Error> {
        let (lock_time, script) = match reclaim_script.as_bytes() {
            // These first two branches check for the case when the script
            // is written with as few bytes as possible (called minimal
            // CScriptNum format or something like that).
            [0, OP_CSV, script @ ..] => (0, script),
            // This catches numbers 1-16 and -1. Negative numbers are
            // invalid for OP_CHECKSEQUENCEVERIFY, but we filter them out
            // later in `ReclaimScriptInputs::try_new`.
            [n, OP_CSV, script @ ..]
                if OP_PUSHNUM_NEG1 == *n || (OP_PUSHNUM_1..=OP_PUSHNUM_16).contains(n) =>
            {
                (*n as i64 - OP_PUSHNUM_1 as i64 + 1, script)
            }
            // Numbers in bitcoin script are typically only 4 bytes (with a
            // range from -2**31+1 to 2**31-1), unless we are working with
            // OP_CSV or OP_CLTV, where 5-byte numbers are acceptable (with
            // a range of 0 to 2**39-1). See the following for how the code
            // works in bitcoin-core:
            // https://github.com/bitcoin/bitcoin/blob/v27.1/src/script/interpreter.cpp#L531-L573
            // That said, we only accepts 4-byte unsigned integers, and we
            // check that below.
            [n, rest @ ..] if *n <= 5 && rest.get(*n as usize) == Some(&OP_CSV) => {
                // We know the error and panic paths cannot happen because
                // of the above `if` check.
                let (script_num, [OP_CSV, script @ ..]) = rest.split_at(*n as usize) else {
                    return Err(Error::InvalidReclaimScript);
                };
                (read_scriptint(script_num, 5)?, script)
            }
            _ => return Err(Error::InvalidReclaimScript),
        };

        let lock_time =
            u32::try_from(lock_time).map_err(|_| Error::InvalidReclaimScriptLockTime(lock_time))?;

        let script = ScriptBuf::from_bytes(script.to_vec());
        ReclaimScriptInputs::try_new(lock_time, script)
    }
}

/// Decodes an integer in script(minimal CScriptNum) format.
///
/// # Notes
///
/// This code is a slightly modified version of the code in rust-bitcoin:
/// https://github.com/rust-bitcoin/rust-bitcoin/blob/bitcoin-0.32.2/bitcoin/src/blockdata/script/mod.rs#L158-L200.
///
/// The logic here and in rust-bitcoin are both based on the `CScriptNum`
/// constructor in Bitcoin Core:
/// https://github.com/bitcoin/bitcoin/blob/v27.1/src/script/script.h#L244C1-L269C6
fn read_scriptint(v: &[u8], max_size: usize) -> Result<i64, Error> {
    let last = match v.last() {
        Some(last) => last,
        None => return Ok(0),
    };
    // In rust-bitcoin, max_size is hardcoded to 4, while in bitcoin-core
    // it is a variable, and sometimes they set it to 5. This is the only
    // modification to this function body from rust-bitcoin's code.
    if v.len() > max_size {
        return Err(Error::ScriptNum(bitcoin::script::Error::NumericOverflow));
    }
    // Comment and code copied from Bitcoin Core:
    // https://github.com/bitcoin/bitcoin/blob/447f50e4aed9a8b1d80e1891cda85801aeb80b4e/src/script/script.h#L247-L262
    // If the most-significant-byte - excluding the sign bit - is zero
    // then we're not minimal. Note how this test also rejects the
    // negative-zero encoding, 0x80.
    if (*last & 0x7f) == 0 {
        // One exception: if there's more than one byte and the most
        // significant bit of the second-most-significant-byte is set
        // it would conflict with the sign bit. An example of this case
        // is +-255, which encode to 0xff00 and 0xff80 respectively.
        // (big-endian).
        if v.len() <= 1 || (v[v.len() - 2] & 0x80) == 0 {
            return Err(Error::ScriptNum(bitcoin::script::Error::NonMinimalPush));
        }
    }

    Ok(scriptint_parse(v))
}

/// Caller to guarantee that `v` is not empty.
///
/// # Notes
///
/// This code was lifted from rust-bitcoin without modification:
/// https://github.com/rust-bitcoin/rust-bitcoin/blob/bitcoin-0.32.2/bitcoin/src/blockdata/script/mod.rs#L218-L226C2.
///
/// The logic there follows the logic in bitcoin-core:
/// https://github.com/bitcoin/bitcoin/blob/v27.1/src/script/script.h#L382C1-L400C3
fn scriptint_parse(v: &[u8]) -> i64 {
    let (mut ret, sh) = v
        .iter()
        .fold((0, 0), |(acc, sh), n| (acc + ((*n as i64) << sh), sh + 8));
    if v[v.len() - 1] & 0x80 != 0 {
        ret &= (1 << (sh - 1)) - 1;
        ret = -ret;
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hex::DisplayHex as _;
    use test_case::test_case;

    /// SIP-005 encodings of the zero-hash mainnet principal and its contract.
    fn recipient(address: &str) -> Vec<u8> {
        let mut bytes = vec![5, 22];
        bytes.extend([0; 20]);
        if address.ends_with(".my-contract") {
            bytes[0] = 6;
            bytes.push(11);
            bytes.extend(b"my-contract");
        }
        bytes
    }

    #[test_case("SP000000000000000000002Q6VF78", "1e000000000001e24005160000000000000000000000000000000000000000"; "standard")]
    #[test_case("SP000000000000000000002Q6VF78.my-contract", "2a000000000001e240061600000000000000000000000000000000000000000b6d792d636f6e7472616374"; "contract")]
    fn v1_script_bytes_are_stable(address: &str, prefix: &str) {
        let key: XOnlyPublicKey =
            "374bfe83198f423d763ddcad92837229b219117750cf8eee106f59f09ebac157"
                .parse()
                .unwrap();
        let deposit = DepositScriptInputs {
            signers_public_key: key,
            recipient: recipient(address),
            max_fee: 123_456,
        };
        assert_eq!(
            deposit.deposit_script().to_hex_string(),
            format!(
                "{prefix}7520374bfe83198f423d763ddcad92837229b219117750cf8eee106f59f09ebac157ac"
            )
        );
    }

    #[test]
    fn reclaim_round_trip_and_key_set_validation() {
        let reclaim = ReclaimScriptInputs::try_new(
            950,
            ScriptBuf::builder()
                .push_opcode(opcodes::OP_DROP)
                .into_script(),
        )
        .unwrap();
        assert_eq!(reclaim.reclaim_script().to_hex_string(), "02b603b275");
        assert_eq!(
            ReclaimScriptInputs::parse(&reclaim.reclaim_script()).unwrap(),
            reclaim
        );
        let key: XOnlyPublicKey =
            "374bfe83198f423d763ddcad92837229b219117750cf8eee106f59f09ebac157"
                .parse()
                .unwrap();
        assert!(SignerKeySet::new([key, key], 2).is_err());
        assert_eq!(
            SignerKeySet::new([key, key], 1).unwrap(),
            SignerKeySet::new([key], 1).unwrap()
        );
        assert!(SignerKeySet::new([key], 0).is_err());
    }
    /// The inputs and expected outputs of the v2 deposit commitment for one
    /// recipient and max fee.
    struct CommitmentTestCase {
        /// The Stacks principal that receives the deposit, as a string.
        recipient: &'static str,
        /// The maximum fee, in sats, that the depositor will pay.
        max_fee: u64,
        /// The expected hex encoding of the preimage, which is the SHA-256
        /// hash of the deposit data.
        expected_preimage: &'static str,
        /// The expected hex encoding of the commitment, which is the
        /// SHA-256 hash of the preimage.
        expected_commitment: &'static str,
    }

    /// The signers reveal the preimage when they spend a v2 deposit, and
    /// Emily and the signers recompute the commitment from the recipient
    /// and max fee when they parse a deposit script. So the mapping
    /// between preimage and commitment for deposit data must never change,
    /// or existing deposits could no longer be parsed or swept.
    ///
    /// The expected values match a direct SHA-256 computation over the
    /// serialized deposit data.
    #[test_case(CommitmentTestCase {
        recipient: "SP000000000000000000002Q6VF78",
        max_fee: 80_000,
        expected_preimage: "7b7fe3bbc53fcb13556d204e0b69371e3db6e0993ad80e3a08d17a9f0347664a",
        expected_commitment: "bc94e3d783ea495b3e32378c650a0d3ebcf1db9289b9457d8fdd49e069e35392",
    } ; "standard principal")]
    #[test_case(CommitmentTestCase {
        recipient: "SP000000000000000000002Q6VF78.my-contract",
        max_fee: 123_456,
        expected_preimage: "46d23f398c2c553eb97e7c8a3cfdacae20ff64585aaf41348c47b08896997c22",
        expected_commitment: "605806257b04557450ba77a3c9b09ea07dd3f20dd54f357851e3894fc7a1809f",
    } ; "contract principal")]
    fn v2_deposit_commitment_is_stable(case: CommitmentTestCase) {
        let recipient = recipient(case.recipient);

        let preimage = deposit_data_preimage(case.max_fee, &recipient);
        let commitment = deposit_data_commitment(case.max_fee, &recipient);

        assert_eq!(preimage.to_lower_hex_string(), case.expected_preimage);
        assert_eq!(commitment.to_lower_hex_string(), case.expected_commitment);
    }

    /// Deposit UTXOs must stay spendable by the signers, so the
    /// scriptPubKey of a v2 deposit, with its deposit and reclaim leaves
    /// under the v2 NUMS internal key, must never change.
    ///
    /// The signing keys are fixed x-only keys, so this does not depend on
    /// signer key derivation, which `key_set_script_pubkey_is_stable` in
    /// the signer_keys module pins.
    #[test_case("SP000000000000000000002Q6VF78", "5120f6fc56e5f5c723ada251594e680c01e7a94fca80a18b9b429522350c46a2fc26", "51209dd0004976783c946f2746c34be6035962bd4e9f9a217ceab9c8faa493010763"; "standard")]
    #[test_case("SP000000000000000000002Q6VF78.my-contract", "51209f613f9438995dfa82ca3ea3b635d936bcda6d4d2ae860cc9ba24e7bc4b5a2a0", "51201c7da221d03a975094a5b500a0a853d7dbe34dd17a768c34b8130212a9f2f997"; "contract")]
    fn deposit_script_pubkeys_are_stable(address: &str, expected_v1: &str, expected_v2: &str) {
        let signing_keys = [
            "374bfe83198f423d763ddcad92837229b219117750cf8eee106f59f09ebac157",
            "b08d2faade97ce5b7159fc49ed3a98ebfde9dcfe70ba6aaa614da225f4fcf8a6",
            "c4a51ca195d4b7fe6307de43a6dc7758eb60475fabe82862bc4299350c09c21c",
        ]
        .map(|key| key.parse::<XOnlyPublicKey>().unwrap());
        let recipient = recipient(address);
        let v1 = DepositScriptInputs {
            signers_public_key: signing_keys[0],
            recipient: recipient.clone(),
            max_fee: 123_456,
        };
        let deposit =
            DepositScriptInputsV2::new(BTreeSet::from(signing_keys), 2, recipient, 123_456)
                .unwrap();

        let reclaim_key: XOnlyPublicKey =
            "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
                .parse()
                .unwrap();
        let reclaim_script = ScriptBuf::builder()
            .push_int(950)
            .push_opcode(opcodes::OP_CSV)
            .push_opcode(opcodes::OP_DROP)
            .push_slice(reclaim_key.serialize())
            .push_opcode(opcodes::OP_CHECKSIG)
            .into_script();

        assert_eq!(
            to_script_pubkey(v1.deposit_script(), reclaim_script.clone()).to_hex_string(),
            expected_v1
        );
        assert_eq!(
            to_v2_script_pubkey(deposit.deposit_script(), reclaim_script).to_hex_string(),
            expected_v2
        );
    }
}
