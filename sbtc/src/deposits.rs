// Copyright (c) 2026 Stacks Open Internet Foundation
// SPDX-License-Identifier: GPL-3.0-only

//! This is the transaction analysis module
//!

use std::collections::BTreeSet;

use bitcoin::Address;
use bitcoin::Network;
use bitcoin::OutPoint;
use bitcoin::Script;
use bitcoin::ScriptBuf;
use bitcoin::Transaction;
use bitcoin::XOnlyPublicKey;
#[cfg(test)]
use bitcoin::hashes::Hash as _;
use bitcoin::locktime::relative::LockTime;
use bitcoin::opcodes::all as opcodes;
#[cfg(test)]
use bitcoin::script::PushBytesBuf;
use clarity::codec::StacksMessageCodec as _;
use clarity::types::chainstate::StacksAddress;
use clarity::vm::types::PrincipalData;
use clarity::vm::types::QualifiedContractIdentifier;
#[cfg(test)]
use secp256k1::SECP256K1;
use stacks_common::types::chainstate::STACKS_ADDRESS_ENCODED_SIZE;

#[cfg(test)]
use crate::MAX_RECLAIM_SCRIPT_LENGTH;
use crate::SignerKeySet;
use crate::error::Error;

/// This is the length of the fixed portion of the deposit script, which
/// is:
/// ```text
///  OP_DROP OP_PUSHBYTES_32 <x-only-public-key> OP_CHECKSIG
/// ```
/// Since we are using Schnorr signatures, we only use the x-coordinate of
/// the public key. The full public key is assumed to be even.
const DEPOSIT_SCRIPT_FIXED_LENGTH: usize = 35;

/// This is the typical number of bytes of a deposit script. It's 1 byte
/// for the length of the following 30 bytes of data, which is 8 bytes for
/// the max fee followed by 1 byte for the address type, 21 bytes the
/// actual standard stacks address, followed by 34 bytes for the fixed
/// length portion of the deposit script. So we have the standard length is
/// 1 + 1 + 8 + 21 + 34 = 65.
const STANDARD_SCRIPT_LENGTH: usize =
    1 + 1 + 8 + STACKS_ADDRESS_ENCODED_SIZE as usize + DEPOSIT_SCRIPT_FIXED_LENGTH;

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

/// Script opcodes as the bytes in bitcoin Script.
///
/// Drops the top stack item
const OP_DROP: u8 = opcodes::OP_DROP.to_u8();
/// <https://en.bitcoin.it/wiki/OP_CHECKSIG> pushing 1/0 for
/// success/failure.
const OP_CHECKSIG: u8 = opcodes::OP_CHECKSIG.to_u8();
/// Read the next byte as N; push the next N bytes as an array onto the
/// stack.
const OP_PUSHDATA1: u8 = opcodes::OP_PUSHDATA1.to_u8();
/// The OP_CHECKSEQUENCEVERIFY opcode described in
/// https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki
#[cfg(test)]
const OP_CSV: u8 = opcodes::OP_CSV.to_u8();
/// Represents the number 1.
#[cfg(test)]
const OP_PUSHNUM_1: u8 = opcodes::OP_PUSHNUM_1.to_u8();

/// All the info required to verify the validity of a deposit
/// transaction. This info is sent by the user to the Emily API
#[derive(Debug, Clone)]
pub struct CreateDepositRequest {
    /// The output index and txid of the depositing transaction.
    pub outpoint: OutPoint,
    /// The raw reclaim script.
    pub reclaim_script: ScriptBuf,
    /// The raw deposit script.
    pub deposit_script: ScriptBuf,
    /// The recipient supplied alongside a v2 deposit script.
    ///
    /// Version 1 scripts encode this value in the script itself, so this is
    /// ignored for v1 deposits and required for v2 deposits.
    pub recipient: Option<PrincipalData>,
    /// The maximum fee supplied alongside a v2 deposit script.
    ///
    /// Version 1 scripts encode this value in the script itself, so this is
    /// ignored for v1 deposits and required for v2 deposits.
    pub max_fee: Option<u64>,
}

/// The version of an sBTC deposit script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DepositScriptVersion {
    /// The legacy aggregate-key deposit script.
    V1,
    /// The independent-signature `multi_a` deposit script.
    V2,
}

/// The signing scheme and key material locking a deposit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositSigningInfo {
    /// A legacy deposit locked by a WSTS aggregate key.
    V1 {
        /// The aggregate x-only public key.
        public_key: XOnlyPublicKey,
    },
    /// A deposit locked by an independent-signature `multi_a` script.
    V2 {
        /// The validated signer key set encoded by the deposit script.
        key_set: SignerKeySet,
    },
}

impl DepositSigningInfo {
    /// Return the deposit script version represented by this signing information.
    pub fn version(&self) -> DepositScriptVersion {
        match self {
            Self::V1 { .. } => DepositScriptVersion::V1,
            Self::V2 { .. } => DepositScriptVersion::V2,
        }
    }
}

/// All the deposit script with the relevant parts of the deposit and
/// reclaim scripts parsed.
#[derive(Debug, Clone)]
pub struct DepositInfo {
    /// The UTXO to be spent by the signers.
    pub outpoint: OutPoint,
    /// The max fee amount to use for the BTC deposit transaction.
    pub max_fee: u64,
    /// The amount of sats in the deposit UTXO.
    pub amount: u64,
    /// The deposit script used so that the signers' can spend funds.
    pub deposit_script: ScriptBuf,
    /// The reclaim script for the deposit.
    pub reclaim_script: ScriptBuf,
    /// The signing scheme and key material locking this deposit.
    pub signing_info: DepositSigningInfo,
    /// The stacks address to deposit the sBTC to. This can be either a
    /// standard address or a contract address.
    pub recipient: PrincipalData,
    /// The relative lock time in the reclaim script.
    pub lock_time: LockTime,
}

impl DepositInfo {
    /// Return the deposit script version.
    pub fn version(&self) -> DepositScriptVersion {
        self.signing_info.version()
    }
}

/// Common parsed fields shared by both deposit script versions.
struct ParsedDepositScript {
    /// The canonical deposit leaf reconstructed from the parsed fields.
    deposit_script: ScriptBuf,
    /// The Stacks principal that will receive the minted sBTC.
    recipient: PrincipalData,
    /// The maximum fee the depositor permits the signers to deduct.
    max_fee: u64,
    /// The signing scheme and key material encoded by the deposit leaf.
    signing_info: DepositSigningInfo,
}

impl CreateDepositRequest {
    /// Parse and validate the v2 deposit leaf using the off-chain request
    /// fields committed to by the script.
    pub fn parse_v2_deposit_script(&self) -> Result<DepositScriptInputsV2, Error> {
        let recipient = self
            .recipient
            .clone()
            .ok_or(Error::MissingV2DepositRecipient)?;
        let max_fee = self.max_fee.ok_or(Error::MissingV2DepositMaxFee)?;
        DepositScriptInputsV2::parse(&self.deposit_script, recipient, max_fee)
    }

    /// Parse either supported deposit script format into its common fields.
    fn parse_deposit_script(&self) -> Result<ParsedDepositScript, Error> {
        match self.deposit_script.first_opcode() {
            // All v2 deposit scripts start with OP_SIZE.
            Some(opcodes::OP_SIZE) => {
                let deposit = self.parse_v2_deposit_script()?;
                Ok(ParsedDepositScript {
                    deposit_script: deposit.deposit_script(),
                    recipient: deposit.recipient,
                    max_fee: deposit.max_fee,
                    signing_info: DepositSigningInfo::V2 {
                        key_set: deposit.signer_key_set,
                    },
                })
            }
            // All v1 deposit scripts start with either OP_PUSHBYTES_N, or
            // OP_PUSHDATA1.
            Some(_) => {
                let deposit = DepositScriptInputs::parse(&self.deposit_script)?;
                Ok(ParsedDepositScript {
                    deposit_script: deposit.deposit_script(),
                    recipient: deposit.recipient,
                    max_fee: deposit.max_fee,
                    signing_info: DepositSigningInfo::V1 {
                        public_key: deposit.signers_public_key,
                    },
                })
            }
            _ => Err(Error::InvalidDepositScriptLength),
        }
    }

    /// Validate this deposit request.
    ///
    /// This function checks the following
    /// * That the transaction's txid matches the expected txid from the
    ///   request.
    /// * That the expected UTXO is in the transaction.
    /// * That the deposit script and reclaim script in the request match
    ///   the expected formats for deposit transactions.
    /// * That deposit script and the reclaim script are part of the UTXO
    ///   ScriptPubKey.
    /// * That the Stacks network for the recipient address matches the one
    ///   given as input to this function.
    pub fn validate_tx(&self, tx: &Transaction, is_mainnet: bool) -> Result<DepositInfo, Error> {
        if tx.compute_txid() != self.outpoint.txid {
            // The expectation is that the transaction was fetched from the
            // blockchain using the txid, so in practice this should never
            // happen.
            return Err(Error::TxidMismatch {
                from_request: self.outpoint.txid,
                from_tx: tx.compute_txid(),
            });
        }

        let tx_out = tx
            .tx_out(self.outpoint.vout as usize)
            .map_err(|err| Error::OutpointIndex(err, self.outpoint))?;
        // Validate that the deposit and reclaim scripts in the request
        // match the expected formats for deposit transactions.
        let deposit = self.parse_deposit_script()?;
        let reclaim = ReclaimScriptInputs::parse(&self.reclaim_script)?;
        // Okay, the deposit and reclaim scripts are valid. Now make sure
        // that the ScriptPubKey in the transaction matches the one implied
        // by the given scripts. So now create the expected ScriptPubKey.
        let reclaim_script = reclaim.reclaim_script();

        if deposit.deposit_script != self.deposit_script {
            return Err(Error::InvalidDepositScript);
        }
        if reclaim_script != self.reclaim_script {
            return Err(Error::InvalidReclaimScript);
        }

        let deposit_script = deposit.deposit_script.clone();
        let expected_script_pubkey = match deposit.signing_info.version() {
            DepositScriptVersion::V1 => to_script_pubkey(deposit_script, reclaim_script.clone()),
            DepositScriptVersion::V2 => to_v2_script_pubkey(deposit_script, reclaim_script.clone()),
        };
        // Check that the expected scriptPubkey matches the actual public
        // key of our parsed UTXO.
        if expected_script_pubkey != tx_out.script_pubkey {
            return Err(Error::UtxoScriptPubKeyMismatch(self.outpoint));
        }

        // Check that the recipient network matches what we expect
        if principal_is_mainnet(deposit.recipient.clone()) != is_mainnet {
            return Err(Error::RecipientNetworkMismatch(deposit.recipient));
        }

        Ok(DepositInfo {
            max_fee: deposit.max_fee,
            deposit_script: deposit.deposit_script,
            reclaim_script,
            signing_info: deposit.signing_info,
            recipient: deposit.recipient,
            lock_time: LockTime::from_consensus(reclaim.lock_time())
                .map_err(Error::DisabledLockTime)?,
            amount: tx_out.value.to_sat(),
            outpoint: self.outpoint,
        })
    }
}

/// Return whether the given principal address is a mainnet address.
fn principal_is_mainnet(principal: PrincipalData) -> bool {
    let standard_address = match principal {
        PrincipalData::Contract(QualifiedContractIdentifier { issuer, .. }) => issuer,
        PrincipalData::Standard(issuer) => issuer,
    };
    StacksAddress::from(standard_address).is_mainnet()
}

use sbtc_primitives::deposits::p2tr_address;
#[cfg(test)]
use sbtc_primitives::deposits::v2_deposit_prefix;
pub use sbtc_primitives::deposits::{
    to_script_pubkey, to_taproot, to_v2_script_pubkey, to_v2_taproot,
};

/// This struct contains the key variable inputs when constructing a
/// deposit script address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositScriptInputs {
    /// The last known public key of the signers.
    pub signers_public_key: XOnlyPublicKey,
    /// The stacks address to deposit the sBTC to. This can be either a
    /// standard address or a contract address.
    pub recipient: PrincipalData,
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
        sbtc_primitives::deposits::DepositScriptInputs {
            signers_public_key: self.signers_public_key,
            recipient: self.recipient.serialize_to_vec(),
            max_fee: self.max_fee,
        }
        .deposit_script()
    }

    /// This function checks that the deposit script is valid.
    ///
    /// Specifically, it checks that it follows the format laid out in
    /// https://github.com/stacks-network/sbtc/issues/30, where the script
    /// is expected to be
    /// ```text
    ///  <deposit-data> OP_DROP OP_PUSHBYTES_32 <x-only-public-key> OP_CHECKSIG
    /// ```
    /// The <deposit-data> is expected to have the format
    /// <max-fee><recipient-address>, where the recipient address follows
    /// the format for a principal from SIP-005. So the expected wire
    /// format is:
    ///
    /// ```text
    /// 0         8             9         10        30            31             159
    /// |---------|-------------|---------|---------|-------------|---------------|
    ///   max fee   type prefix   version   hash160   name length   contract name
    ///                                               (optional)    (optional)
    /// ```
    ///
    /// Above, the max fee is expressed as an 8-byte big endian integer and
    /// the contract name is a UTF-8 encoded string and must be accepted by
    /// the regex `^[a-zA-Z]([a-zA-Z0-9]|[-_])*$`.
    ///
    /// SIP-005:
    /// https://github.com/stacksgov/sips/blob/0b19b15a9f2dd43caf6607de4fe53cad8313ff40/sips/sip-005/sip-005-blocks-and-transactions.md#transaction-post-conditions
    pub fn parse(deposit_script: &ScriptBuf) -> Result<Self, Error> {
        let script = deposit_script.as_bytes();

        // Valid deposit scripts cannot be less than this length.
        if script.len() < STANDARD_SCRIPT_LENGTH {
            return Err(Error::InvalidDepositScriptLength);
        }
        // This cannot panic because of the above check and the fact that
        // DEPOSIT_SCRIPT_FIXED_LENGTH < STANDARD_SCRIPT_LENGTH.
        let (params, check) = script.split_at(script.len() - DEPOSIT_SCRIPT_FIXED_LENGTH);
        // Below, we know the script length is DEPOSIT_SCRIPT_FIXED_LENGTH,
        // because of how `slice::split_at` works, so we know the
        // public_key variable has length 32.
        let [OP_DROP, 32, public_key @ .., OP_CHECKSIG] = check else {
            return Err(Error::InvalidDepositCheckSigPart);
        };
        // In bitcoin script, the code for pushing N bytes onto the stack
        // is OP_PUSHBYTES_N where N is between 1 and 75 inclusive. The
        // byte representation of these opcodes is the byte representation
        // of N. If you need to push between 76 and 255 bytes of data then
        // you need to use the OP_PUSHDATA1 opcode (you can also use this
        // opcode to push between 1 and 75 bytes on the stack, but it's
        // non-standard and cheaper to use the OP_PUSHBYTES_N opcodes when
        // you can). We need to check all cases since contract addresses
        // can have a size of up to 151 bytes. Note that the data slice
        // here starts with the 8 byte max fee.
        let deposit_data = match params {
            // This branch represents a contract address. We reject scripts
            // that use OP_PUSHDATA1 to push less than 76 bytes of data
            // because those scripts, while valid and do not break
            // consensus rules, are non-standard. Accepting them would make
            // it very difficult for the signers to accept the deposit
            // since bitcoin-core nodes do not relay non-standard
            // transactions.
            [OP_PUSHDATA1, n, data @ ..] if data.len() == *n as usize && 75 < *n && *n < 160 => {
                data
            }
            [OP_PUSHDATA1, n, data @ ..] if data.len() == *n as usize && *n < 76 => {
                return Err(Error::NonMinimalPushDepositScript);
            }
            // This branch can be a standard (non-contract) Stacks
            // addresses when n == 30 (8 byte max fee + 22 byte address)
            // and is a contract address otherwise.
            [n, data @ ..] if data.len() == *n as usize && *n < 76 => data,
            _ => return Err(Error::InvalidDepositScript),
        };
        // Here `split_first_chunk::<N>` returns Option<(&[u8; N], &[u8])>,
        // where None is returned if the length of the slice is less than
        // N. Since N is 8 and the data variable has a length 30 or
        // greater, the error path cannot happen.
        let Some((max_fee_bytes, mut address)) = deposit_data.split_first_chunk::<8>() else {
            return Err(Error::InvalidDepositScript);
        };
        let recipient = PrincipalData::consensus_deserialize(&mut address)
            .map_err(Error::ParseStacksAddress)?;

        Ok(DepositScriptInputs {
            signers_public_key: XOnlyPublicKey::from_slice(public_key)
                .map_err(Error::InvalidXOnlyPublicKey)?,
            max_fee: u64::from_be_bytes(*max_fee_bytes),
            recipient,
        })
    }
}

/// This struct contains the key variable inputs when constructing a v2
/// deposit script.
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
    /// The Stacks principal committed to by the script.
    pub recipient: PrincipalData,
    /// The maximum fee committed to by the script.
    pub max_fee: u64,
}

impl DepositScriptInputsV2 {
    /// Create validated v2 deposit inputs.
    pub fn new(
        signer_public_keys: BTreeSet<XOnlyPublicKey>,
        signatures_required: u16,
        recipient: PrincipalData,
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
        sbtc_primitives::deposits::DepositScriptInputsV2 {
            signer_key_set: self.signer_key_set.0.clone(),
            recipient: self.recipient.serialize_to_vec(),
            max_fee: self.max_fee,
        }
        .deposit_script()
    }

    /// Parse and validate the v2 deposit script against recipient and
    /// max-fee.
    pub fn parse(
        deposit_script: &ScriptBuf,
        recipient: PrincipalData,
        max_fee: u64,
    ) -> Result<Self, Error> {
        let parsed = sbtc_primitives::deposits::DepositScriptInputsV2::parse(
            deposit_script,
            recipient.serialize_to_vec(),
            max_fee,
        )?;
        let signer_key_set = SignerKeySet(parsed.signer_key_set);

        Ok(Self {
            signer_key_set,
            recipient,
            max_fee,
        })
    }
}

/// Return the 32-byte preimage that a v2 deposit script commits to, and that
/// the signers reveal when spending the deposit.
pub fn deposit_data_preimage(max_fee: u64, recipient: &PrincipalData) -> [u8; 32] {
    sbtc_primitives::deposits::deposit_data_preimage(max_fee, &recipient.serialize_to_vec())
}

/// Return the hash committed to by a v2 deposit script.
#[cfg(any(test, feature = "testing"))]
fn deposit_data_commitment(max_fee: u64, recipient: &PrincipalData) -> [u8; 32] {
    sbtc_primitives::deposits::deposit_data_commitment(max_fee, &recipient.serialize_to_vec())
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
pub struct ReclaimScriptInputs(sbtc_primitives::deposits::ReclaimScriptInputs);

impl ReclaimScriptInputs {
    /// Validate the lock time and user-supplied reclaim script.
    pub fn try_new(lock_time: u32, script: ScriptBuf) -> Result<Self, Error> {
        sbtc_primitives::deposits::ReclaimScriptInputs::try_new(lock_time, script)
            .map(Self)
            .map_err(Into::into)
    }
    /// Validate only the lock time, for validation tests.
    #[cfg(any(test, feature = "testing"))]
    pub fn try_new_unvalidated(lock_time: u32, script: ScriptBuf) -> Result<Self, Error> {
        sbtc_primitives::deposits::ReclaimScriptInputs::try_new_unvalidated(lock_time, script)
            .map(Self)
            .map_err(Into::into)
    }
    /// Return the consensus lock time.
    pub fn lock_time(&self) -> u32 {
        self.0.lock_time()
    }
    /// Return the script following the lock-time prefix.
    pub fn user_script(&self) -> &Script {
        self.0.user_script()
    }
    /// Construct the reclaim script.
    pub fn reclaim_script(&self) -> ScriptBuf {
        self.0.reclaim_script()
    }
    /// Parse and validate a reclaim script.
    pub fn parse(script: &ScriptBuf) -> Result<Self, Error> {
        sbtc_primitives::deposits::ReclaimScriptInputs::parse(script)
            .map(Self)
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::AddressType;
    use bitcoin::NetworkKind;
    use bitcoin::Txid;
    use bitcoin::bip32::ChainCode;
    use bitcoin::bip32::ChildNumber;
    use bitcoin::bip32::Fingerprint;
    use bitcoin::bip32::Xpub;
    use bitcoin::hex::DisplayHex as _;
    use rand::rngs::OsRng;
    use secp256k1::Parity;
    use secp256k1::PublicKey;
    use secp256k1::SecretKey;
    use stacks_common::types::chainstate::StacksAddress;

    use super::*;
    use crate::testing;
    use crate::testing::deposits::TxSetup;

    use test_case::test_case;

    const CONTRACT_ADDRESS: &str = "ST1RQHF4VE5CZ6EK3MZPZVQBA0JVSMM9H5PMHMS1Y.contract-name";

    /// A full reclaim script with a p2pk script at the end.
    fn reclaim_p2pk(lock_time: i64) -> ScriptBuf {
        ScriptBuf::builder()
            .push_int(lock_time)
            .push_opcode(opcodes::OP_CSV)
            .push_opcode(opcodes::OP_DROP)
            .push_slice([0; 32])
            .push_opcode(opcodes::OP_CHECKSIG)
            .into_script()
    }

    /// Construct representative v2 deposit inputs for parser tests.
    fn v2_deposit_inputs() -> DepositScriptInputsV2 {
        let recipient = PrincipalData::from(StacksAddress::burn_address(false));
        let public_keys = (0..3)
            .map(|_| SecretKey::new(&mut OsRng).x_only_public_key(SECP256K1).0)
            .collect();
        DepositScriptInputsV2::new(public_keys, 2, recipient, 25_000).unwrap()
    }

    /// Check that manually creating the expected script can correctly be
    /// parsed.
    #[test_case(PrincipalData::from(StacksAddress::burn_address(false)) ; "standard address")]
    #[test_case(PrincipalData::parse(CONTRACT_ADDRESS).unwrap(); "contract address")]
    fn deposit_script_parsing_works_standard_principal(recipient: PrincipalData) {
        let secret_key = SecretKey::new(&mut OsRng);
        let public_key = secret_key.x_only_public_key(SECP256K1).0;
        let max_fee: u64 = 15000;

        let mut deposit_data = max_fee.to_be_bytes().to_vec();
        deposit_data.extend_from_slice(&recipient.serialize_to_vec());

        let deposit_data: PushBytesBuf = deposit_data.try_into().unwrap();

        let script = ScriptBuf::builder()
            .push_slice(deposit_data)
            .push_opcode(opcodes::OP_DROP)
            .push_slice(public_key.serialize())
            .push_opcode(opcodes::OP_CHECKSIG)
            .into_script();

        if matches!(recipient, PrincipalData::Standard(_)) {
            assert_eq!(script.len(), STANDARD_SCRIPT_LENGTH);
        }

        let extracts = DepositScriptInputs::parse(&script).unwrap();
        assert_eq!(extracts.signers_public_key, public_key);
        assert_eq!(extracts.recipient, recipient);
        assert_eq!(extracts.max_fee, max_fee);
        assert_eq!(extracts.deposit_script(), script);
    }

    #[test]
    fn v2_deposit_script_round_trip_and_commitment_validation() {
        let recipient = PrincipalData::from(StacksAddress::burn_address(false));
        let keys: BTreeSet<_> = (0..5)
            .map(|_| SecretKey::new(&mut OsRng).x_only_public_key(SECP256K1).0)
            .collect();
        let inputs = DepositScriptInputsV2::new(keys, 3, recipient.clone(), 25_000).unwrap();
        let script = inputs.deposit_script();

        let parsed = DepositScriptInputsV2::parse(&script, recipient.clone(), 25_000).unwrap();
        assert_eq!(parsed, inputs);
        assert_eq!(parsed.deposit_script(), script);

        let request = CreateDepositRequest {
            outpoint: OutPoint::null(),
            deposit_script: script.clone(),
            reclaim_script: ScriptBuf::new(),
            recipient: Some(recipient.clone()),
            max_fee: Some(25_000),
        };
        assert_eq!(request.parse_v2_deposit_script().unwrap(), inputs);
    }

    #[test]
    fn v2_validation_exposes_only_v2_signing_information() {
        let recipient = PrincipalData::from(StacksAddress::burn_address(false));
        let public_keys = (0..3)
            .map(|_| SecretKey::new(&mut OsRng).x_only_public_key(SECP256K1).0)
            .collect::<BTreeSet<_>>();
        let deposit =
            DepositScriptInputsV2::new(public_keys.clone(), 2, recipient.clone(), 25_000).unwrap();
        let deposit_script = deposit.deposit_script();
        let reclaim_script = reclaim_p2pk(150);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(500_000),
                script_pubkey: to_v2_script_pubkey(deposit_script.clone(), reclaim_script.clone()),
            }],
        };
        let request = CreateDepositRequest {
            outpoint: OutPoint::new(tx.compute_txid(), 0),
            deposit_script,
            reclaim_script,
            recipient: Some(recipient),
            max_fee: Some(25_000),
        };

        let info = request.validate_tx(&tx, false).unwrap();

        assert_eq!(
            info.signing_info,
            DepositSigningInfo::V2 {
                key_set: SignerKeySet::new(public_keys, 2).unwrap(),
            }
        );
        assert_eq!(info.version(), DepositScriptVersion::V2);

        let key_set_id = match info.signing_info {
            DepositSigningInfo::V1 { public_key } => public_key.serialize().into(),
            DepositSigningInfo::V2 { key_set } => key_set.id(),
        };
        assert_eq!(key_set_id, deposit.signer_key_set.id());
    }

    #[test]
    fn v2_deposit_script_matches_opcode_construction() {
        let recipient = PrincipalData::from(StacksAddress::burn_address(false));
        let public_keys = (0..3)
            .map(|_| SecretKey::new(&mut OsRng).x_only_public_key(SECP256K1).0)
            .collect::<BTreeSet<_>>();
        let deposit =
            DepositScriptInputsV2::new(public_keys.clone(), 2, recipient, 25_000).unwrap();
        let key_set = SignerKeySet::new(public_keys, 2).unwrap();

        let mut expected = ScriptBuf::builder()
            .push_opcode(opcodes::OP_SIZE)
            .push_int(32)
            .push_opcode(opcodes::OP_EQUALVERIFY)
            .push_opcode(opcodes::OP_SHA256)
            .push_slice(deposit.commitment())
            .push_opcode(opcodes::OP_EQUALVERIFY)
            .into_script()
            .into_bytes();
        expected.extend_from_slice(key_set.signing_script().as_bytes());

        assert_eq!(deposit.deposit_script().as_bytes(), expected.as_slice());
    }

    #[test]
    fn v2_deposit_prefix_has_expected_wire_encoding() {
        let commitment = [0x42; 32];
        let mut expected = vec![
            opcodes::OP_SIZE.to_u8(),
            opcodes::OP_PUSHBYTES_1.to_u8(),
            32,
            opcodes::OP_EQUALVERIFY.to_u8(),
            opcodes::OP_SHA256.to_u8(),
            opcodes::OP_PUSHBYTES_32.to_u8(),
        ];
        expected.extend_from_slice(&commitment);
        expected.push(opcodes::OP_EQUALVERIFY.to_u8());

        assert_eq!(v2_deposit_prefix(commitment).as_bytes(), expected);
    }

    #[test_case("SP000000000000000000002Q6VF78"; "standard")]
    #[test_case("SP000000000000000000002Q6VF78.my-contract"; "contract")]
    fn typed_builders_match_primitives(address: &str) {
        let recipient = PrincipalData::parse(address).unwrap();
        let mut expected = vec![5, 22];
        expected.extend([0; 20]);
        if address.ends_with(".my-contract") {
            expected[0] = 6;
            expected.push(11);
            expected.extend(b"my-contract");
        }
        assert_eq!(recipient.serialize_to_vec(), expected);
        let encoded = expected;
        let key: XOnlyPublicKey =
            "374bfe83198f423d763ddcad92837229b219117750cf8eee106f59f09ebac157"
                .parse()
                .unwrap();
        let typed = DepositScriptInputs {
            signers_public_key: key,
            recipient: recipient.clone(),
            max_fee: 123_456,
        };
        let raw = sbtc_primitives::deposits::DepositScriptInputs {
            signers_public_key: key,
            recipient: encoded.clone(),
            max_fee: 123_456,
        };
        assert_eq!(typed.deposit_script(), raw.deposit_script());
        assert_eq!(
            DepositScriptInputs::parse(&raw.deposit_script()).unwrap(),
            typed
        );
        let typed =
            DepositScriptInputsV2::new(BTreeSet::from([key]), 1, recipient.clone(), 123_456)
                .unwrap();
        let raw = sbtc_primitives::deposits::DepositScriptInputsV2::new(
            BTreeSet::from([key]),
            1,
            encoded.clone(),
            123_456,
        )
        .unwrap();
        assert_eq!(typed.deposit_script(), raw.deposit_script());
        assert_eq!(
            deposit_data_preimage(123_456, &recipient),
            sbtc_primitives::deposits::deposit_data_preimage(123_456, &encoded)
        );
        assert_eq!(
            DepositScriptInputsV2::parse(&raw.deposit_script(), recipient.clone(), 123_456)
                .unwrap(),
            typed
        );
        assert!(matches!(
            DepositScriptInputsV2::parse(&raw.deposit_script(), recipient, 123_457),
            Err(Error::InvalidDepositPrefix { .. })
        ));
        assert!(matches!(
            SignerKeySet::new([key], 0),
            Err(Error::InvalidDepositThreshold { .. })
        ));
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
        let recipient = PrincipalData::parse(case.recipient).unwrap();

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
    #[test]
    fn v2_deposit_script_pubkey_is_stable() {
        let signing_keys = [
            "374bfe83198f423d763ddcad92837229b219117750cf8eee106f59f09ebac157",
            "b08d2faade97ce5b7159fc49ed3a98ebfde9dcfe70ba6aaa614da225f4fcf8a6",
            "c4a51ca195d4b7fe6307de43a6dc7758eb60475fabe82862bc4299350c09c21c",
        ]
        .map(|key| key.parse::<XOnlyPublicKey>().unwrap());
        let recipient = PrincipalData::parse("SP000000000000000000002Q6VF78.my-contract").unwrap();
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

        let script_pubkey = to_v2_script_pubkey(deposit.deposit_script(), reclaim_script);
        assert_eq!(
            script_pubkey.to_hex_string(),
            "51201c7da221d03a975094a5b500a0a853d7dbe34dd17a768c34b8130212a9f2f997"
        );
    }

    #[test_case(0..1, vec![opcodes::OP_DROP.to_u8()]; "OP_SIZE")]
    #[test_case(1..2, vec![opcodes::OP_DROP.to_u8()]; "size push opcode")]
    #[test_case(2..3, vec![31]; "wrong preimage size")]
    #[test_case(3..4, vec![opcodes::OP_DROP.to_u8()]; "first OP_EQUALVERIFY")]
    #[test_case(4..5, vec![opcodes::OP_DROP.to_u8()]; "OP_SHA256")]
    #[test_case(5..6, vec![opcodes::OP_DROP.to_u8()]; "commitment push opcode")]
    #[test_case(38..39, vec![opcodes::OP_DROP.to_u8()]; "second OP_EQUALVERIFY")]
    #[test_case(1..3, vec![opcodes::OP_PUSHDATA1.to_u8(), 1, 32]; "non-minimal size push")]
    #[test_case(5..6, vec![opcodes::OP_PUSHDATA1.to_u8(), 32]; "non-minimal commitment push")]
    #[test_case(5..6, vec![opcodes::OP_PUSHBYTES_31.to_u8()]; "wrong commitment length")]
    fn v2_parser_rejects_malformed_prefix(
        replaced_range: std::ops::Range<usize>,
        replacement: Vec<u8>,
    ) {
        let deposit = v2_deposit_inputs();
        let mut malformed_script = deposit.deposit_script().into_bytes();
        malformed_script.splice(replaced_range, replacement);

        let error = DepositScriptInputsV2::parse(
            &ScriptBuf::from_bytes(malformed_script),
            deposit.recipient,
            deposit.max_fee,
        )
        .unwrap_err();

        std::assert_matches!(error, Error::InvalidDepositPrefix { .. });
    }

    #[test]
    fn v2_parser_rejects_truncated_prefixes() {
        let deposit = v2_deposit_inputs();
        let prefix = v2_deposit_prefix(deposit.commitment()).into_bytes();

        for length in 0..prefix.len() {
            let truncated = ScriptBuf::from_bytes(prefix[..length].to_vec());
            let error = DepositScriptInputsV2::parse(
                &truncated,
                deposit.recipient.clone(),
                deposit.max_fee,
            )
            .unwrap_err();

            std::assert_matches!(error, Error::InvalidDepositScriptLength);
        }
    }

    #[test]
    fn v2_parser_reports_actual_and_expected_prefixes() {
        let deposit = v2_deposit_inputs();
        let script = deposit.deposit_script();
        let expected = v2_deposit_prefix(deposit_data_commitment(
            deposit.max_fee + 1,
            &deposit.recipient,
        ));
        let actual = v2_deposit_prefix(deposit.commitment());

        let error =
            DepositScriptInputsV2::parse(&script, deposit.recipient.clone(), deposit.max_fee + 1)
                .unwrap_err();
        std::assert_matches!(
            error,
            Error::InvalidDepositPrefix {
                actual: error_actual,
                expected: error_expected,
            } if error_actual == actual && error_expected == expected
        );
    }

    #[test]
    fn v2_parser_rejects_invalid_signer_script_remainder() {
        let deposit = v2_deposit_inputs();
        let script = v2_deposit_prefix(deposit.commitment());

        let error =
            DepositScriptInputsV2::parse(&script, deposit.recipient, deposit.max_fee).unwrap_err();

        std::assert_matches!(error, Error::InvalidDepositScript);
    }

    /// Construct a parsable deposit script that is non-standard and check
    /// that it errors.
    #[test]
    fn non_standard_deposit_scripts() {
        let secret_key = SecretKey::new(&mut OsRng);
        let public_key = secret_key.x_only_public_key(SECP256K1).0;

        // We construct valid deposit data so that we know that the issue
        // doesn't lie there.
        let recipient = PrincipalData::parse(CONTRACT_ADDRESS).unwrap();
        let max_fee: u64 = 15000;

        let mut deposit_data = [0; 44];
        deposit_data[..8].copy_from_slice(&max_fee.to_be_bytes());
        deposit_data[8..].copy_from_slice(&recipient.serialize_to_vec());

        // This is non-standard script because it does not follow the
        // minimal push rule. We use the OP_PUSHDATA1 when we can use
        // fewer bytes for the same outcome in the script.
        let deposit_script = ScriptBuf::builder()
            .push_opcode(opcodes::OP_PUSHDATA1)
            .push_slice(deposit_data)
            .push_opcode(opcodes::OP_DROP)
            .push_slice(public_key.serialize())
            .push_opcode(opcodes::OP_CHECKSIG)
            .into_script();

        let extracts = DepositScriptInputs::parse(&deposit_script);
        assert!(matches!(extracts, Err(Error::NonMinimalPushDepositScript)));
    }

    /// Check that `DepositScript::deposit_script` and the
    /// `parse_deposit_script` function are inverses of one another.
    #[test_case(PrincipalData::from(StacksAddress::burn_address(false)) ; "standard address")]
    #[test_case(PrincipalData::parse(CONTRACT_ADDRESS).unwrap(); "contract address")]
    fn deposit_script_parsing_and_creation_are_inverses(recipient: PrincipalData) {
        let secret_key = SecretKey::new(&mut OsRng);

        let deposit = DepositScriptInputs {
            signers_public_key: secret_key.x_only_public_key(SECP256K1).0,
            max_fee: 15000,
            recipient,
        };

        let deposit_script = deposit.deposit_script();
        let parsed_deposit = DepositScriptInputs::parse(&deposit_script).unwrap();

        assert_eq!(deposit, parsed_deposit);
    }

    #[test]
    fn deposit_script_128_byte_contract_name() {
        let contract_name = "a".repeat(128);
        let principal_str = format!("{}.{contract_name}", StacksAddress::burn_address(false));
        let secret_key = SecretKey::new(&mut OsRng);

        let deposit = DepositScriptInputs {
            signers_public_key: secret_key.x_only_public_key(SECP256K1).0,
            max_fee: 25000,
            recipient: PrincipalData::parse(&principal_str).unwrap(),
        };

        assert_eq!(deposit.recipient.serialize_to_vec().len(), 151);

        let deposit_script = deposit.deposit_script();
        let parsed_deposit = DepositScriptInputs::parse(&deposit_script).unwrap();

        assert_eq!(deposit, parsed_deposit);
    }

    /// Basic check that we can create an address without any issues
    #[test_case(PrincipalData::from(StacksAddress::burn_address(false)) ; "standard address")]
    #[test_case(PrincipalData::parse(CONTRACT_ADDRESS).unwrap(); "contract address")]
    fn btc_address(recipient: PrincipalData) {
        let secret_key = SecretKey::new(&mut OsRng);

        let deposit = DepositScriptInputs {
            signers_public_key: secret_key.x_only_public_key(SECP256K1).0,
            max_fee: 15000,
            recipient,
        };

        let address = deposit.to_address(ScriptBuf::new(), Network::Regtest);
        assert_eq!(address.address_type(), Some(AddressType::P2tr));
    }

    #[test_case(0; "sneaky guy setting the lock time to zero")]
    #[test_case(6; "6, a minimal number")]
    #[test_case(15; "15, another minimal number")]
    #[test_case(0x000000ff; "1 byte non-minimal")]
    #[test_case(0x0000ffff; "2 bytes non-minimal")]
    fn reclaim_script_lock_time(lock_time: u32) {
        let reclaim_script = reclaim_p2pk(lock_time as i64);

        let extracts = ReclaimScriptInputs::parse(&reclaim_script).unwrap();
        assert_eq!(extracts.lock_time(), lock_time);
        assert_eq!(extracts.reclaim_script(), reclaim_script);

        // Let's check that ReclaimScriptInputs::reclaim_script and
        // parse_reclaim_script and are inverses in the other direction.
        let script = ScriptBuf::builder()
            .push_opcode(opcodes::OP_DROP)
            .push_slice([2; 32])
            .push_opcode(opcodes::OP_CHECKSIG)
            .into_script();

        let inputs = ReclaimScriptInputs::try_new(lock_time, script.clone()).unwrap();
        let reclaim_script = inputs.reclaim_script();
        assert_eq!(inputs.user_script(), script.as_script());
        assert_eq!(ReclaimScriptInputs::parse(&reclaim_script).unwrap(), inputs);
    }

    #[test]
    fn reclaim_6_bytes_bad() {
        let lock_time = 0x10000000000;
        let reclaim_script = reclaim_p2pk(lock_time);
        assert!(ReclaimScriptInputs::parse(&reclaim_script).is_err());
    }

    #[test_case(-1; "negative one")]
    #[test_case(-16; "negative sixteen")]
    #[test_case(-1000; "negative 1000")]
    fn reclaim_negative_numbers_bytes_bad(lock_time: i64) {
        let reclaim_script = reclaim_p2pk(lock_time);

        match ReclaimScriptInputs::parse(&reclaim_script) {
            Err(Error::InvalidReclaimScriptLockTime(parsed_lock_time)) => {
                assert_eq!(parsed_lock_time, lock_time)
            }
            _ => panic!("This shouldn't trigger"),
        };
    }

    #[test]
    fn no_real_reclaim_script_is_fine() {
        let lock_time = 150;
        let reclaim_script = ScriptBuf::builder()
            .push_int(lock_time)
            .push_opcode(opcodes::OP_CSV)
            .into_script();

        let extracts = ReclaimScriptInputs::parse(&reclaim_script).unwrap();
        assert_eq!(extracts.lock_time(), lock_time as u32);
        assert_eq!(extracts.reclaim_script(), reclaim_script);
    }

    #[test_case(ScriptBuf::builder()
        .push_opcode(opcodes::OP_RETURN)
        .push_int(150)
        .push_opcode(opcodes::OP_CSV)
        .into_script() ; "start with OP_RETURN")]
    #[test_case(ScriptBuf::builder()
        .push_opcode(opcodes::OP_PUSHNUM_1)
        .push_int(150)
        .push_opcode(opcodes::OP_CSV)
        .into_script() ; "start with OP_TRUE")]
    #[test_case(ScriptBuf::builder()
        .push_int(0)
        .push_int(150)
        .push_opcode(opcodes::OP_CSV)
        .into_script() ; "start with 0")]
    #[test_case(ScriptBuf::builder()
        .push_int(1 << (31 + 15))
        .push_opcode(opcodes::OP_CSV)
        .into_script() ; "is a lock-disabling number")]
    #[test_case(ScriptBuf::builder()
        .push_int(-4)
        .push_opcode(opcodes::OP_CSV)
        .into_script() ; "is a negative number")]
    fn invalid_script_start(reclaim_script: ScriptBuf) {
        // The script must start with `<lock-time> OP_CSV` or we get an
        // error.
        assert!(ReclaimScriptInputs::parse(&reclaim_script).is_err());
    }

    #[test]
    fn set_disabled_flag() {
        // Another check that having the specific bit set in the lock time
        // will lead to a failure to create a ReclaimScriptInputs struct.
        let lock_time = 56 | SEQUENCE_LOCKTIME_DISABLE_FLAG;
        let reclaim = ReclaimScriptInputs::try_new(lock_time, ScriptBuf::new());
        assert!(reclaim.is_err());

        let lock_time = 56;
        let reclaim = ReclaimScriptInputs::try_new(lock_time, ScriptBuf::new());
        assert!(reclaim.is_ok());
    }

    #[test]
    fn lock_time_as_time() {
        // We do not support time based lock times. Check that
        let lock_time = LockTime::from_seconds_ceil(20000)
            .unwrap()
            .to_consensus_u32();
        let reclaim = ReclaimScriptInputs::try_new(lock_time, ScriptBuf::new()).unwrap_err();

        assert!(matches!(reclaim, Error::UnsupportedLockTimeUnits(_)));
    }

    /// A user script of exactly `MAX_RECLAIM_SCRIPT_LENGTH` bytes is
    /// accepted; one byte more is rejected.
    #[test]
    fn reclaim_script_length_boundary() {
        let lock_time = 50;

        // Build a script of length exactly MAX_RECLAIM_SCRIPT_LENGTH out
        // of OP_CSV opcodes. OP_CSV is a single byte and is not an
        // OP_SUCCESSx opcode, so it isolates the length check.
        let max_script = ScriptBuf::from_bytes(vec![OP_CSV; MAX_RECLAIM_SCRIPT_LENGTH]);
        assert_eq!(max_script.len(), MAX_RECLAIM_SCRIPT_LENGTH);
        ReclaimScriptInputs::try_new(lock_time, max_script).unwrap();

        let too_long = ScriptBuf::from_bytes(vec![OP_CSV; MAX_RECLAIM_SCRIPT_LENGTH + 1]);
        let err = ReclaimScriptInputs::try_new(lock_time, too_long).unwrap_err();
        assert_matches::assert_matches!(err, Error::InvalidReclaimScriptLength(n) if n == MAX_RECLAIM_SCRIPT_LENGTH + 1);
    }

    /// Each opcode in the BIP-342 `OP_SUCCESSx` range causes the
    /// user-supplied reclaim script to be rejected.
    #[test_case(opcodes::OP_RESERVED ; "OP_RESERVED (80)")]
    #[test_case(opcodes::OP_VER ; "OP_VER (98)")]
    #[test_case(opcodes::OP_CAT ; "OP_CAT (126)")]
    #[test_case(opcodes::OP_SUBSTR ; "OP_SUBSTR (127)")]
    #[test_case(opcodes::OP_INVERT ; "OP_INVERT (131)")]
    #[test_case(opcodes::OP_RESERVED1 ; "OP_RESERVED1 (137)")]
    #[test_case(opcodes::OP_2MUL ; "OP_2MUL (141)")]
    #[test_case(opcodes::OP_MUL ; "OP_MUL (149)")]
    #[test_case(opcodes::OP_RETURN_187 ; "OP_RETURN_187 (187)")]
    #[test_case(opcodes::OP_RETURN_254 ; "OP_RETURN_254 (254)")]
    fn reclaim_script_op_success_rejected(op: bitcoin::opcodes::Opcode) {
        let lock_time = 50;

        let script = ScriptBuf::builder()
            .push_opcode(opcodes::OP_RETURN)
            .push_opcode(op)
            .into_script();

        let err = ReclaimScriptInputs::try_new(lock_time, script).unwrap_err();
        assert_matches::assert_matches!(err, Error::ReclaimScriptWithSuccessOp(_));
    }

    /// `OP_INVALIDOPCODE` (255) is not in the BIP-342 `OP_SUCCESSx`
    /// range, so a script containing it as an opcode is not flagged by
    /// the `OP_SUCCESSx` check. The script is still bytewise within the
    /// length limit, so `try_new` accepts it.
    #[test]
    fn reclaim_script_op_invalidopcode_not_op_success() {
        let lock_time = 50;
        let script = ScriptBuf::from_bytes(vec![opcodes::OP_INVALIDOPCODE.to_u8()]);
        ReclaimScriptInputs::try_new(lock_time, script).unwrap();
    }

    /// Bytes that *equal* an `OP_SUCCESSx` value but appear inside a
    /// pushed data payload must not trigger the `OP_SUCCESSx` check.
    /// Bitcoin-core's scan walks opcodes (skipping over push payloads),
    /// and ours must do the same.
    #[test]
    fn reclaim_script_op_success_byte_in_pushdata_allowed() {
        let lock_time = 50;
        // A 32-byte payload of `OP_RETURN_187` bytes pushed via
        // `push_slice` — the leading length byte is the opcode and the
        // payload bytes are skipped by the instruction iterator.
        let script = ScriptBuf::builder()
            .push_slice([opcodes::OP_RETURN_187.to_u8(); 32])
            .push_opcode(opcodes::OP_DROP)
            .into_script();

        ReclaimScriptInputs::try_new(lock_time, script).unwrap();

        // For comparison: the same byte used as a bare opcode (rather
        // than inside a push payload) is rejected.
        let script = ScriptBuf::builder()
            .push_opcode(opcodes::OP_RETURN_187)
            .push_opcode(opcodes::OP_DROP)
            .into_script();

        let err = ReclaimScriptInputs::try_new(lock_time, script).unwrap_err();
        assert_matches::assert_matches!(err, Error::ReclaimScriptWithSuccessOp(_));
    }

    /// We check that we catch reclaim scripts with OP_SUCCESSx opcodes
    /// that are also unparsable on bitcoin-core.
    #[test]
    fn reclaim_script_op_success_byte_in_malformed_script() {
        let lock_time = 50;
        let bytes: Vec<u8> = vec![
            // (1) OP_SUCCESS first — short-circuits the rest of the script
            opcodes::OP_RETURN_187.to_u8(),
            // (2) Malformed push: OP_PUSHDATA1 followed by length 0xff, but
            //     zero bytes of payload. bitcoin-core's GetOp on this should
            //     return false and fail the script.
            OP_PUSHDATA1,
            0xff, // "the next 255 bytes are the push", except not really
        ];

        let script = ScriptBuf::from_bytes(bytes);

        // check that the script is malformed
        let is_malformed = script.instructions().any(|op| op.is_err());
        assert!(is_malformed);

        let err = ReclaimScriptInputs::try_new(lock_time, script).unwrap_err();
        assert_matches::assert_matches!(err, Error::ReclaimScriptWithSuccessOp(_));
    }

    #[test]
    fn happy_path_tx_validation() {
        let max_fee: u64 = 15000;
        let amount_sats = 500_000;
        let lock_time = 150;

        let setup: TxSetup = testing::deposits::tx_setup(lock_time, max_fee, &[amount_sats]);

        let request = CreateDepositRequest {
            outpoint: OutPoint::new(setup.tx.compute_txid(), 0),
            reclaim_script: setup.reclaims.first().unwrap().reclaim_script(),
            deposit_script: setup.deposits.first().unwrap().deposit_script(),
            recipient: None,
            max_fee: None,
        };

        let parsed = request.validate_tx(&setup.tx, false).unwrap();

        assert_eq!(parsed.outpoint, request.outpoint);
        assert_eq!(parsed.deposit_script, request.deposit_script);
        assert_eq!(parsed.reclaim_script, request.reclaim_script);
        assert_eq!(parsed.amount, amount_sats);
        assert_eq!(
            parsed.signing_info,
            DepositSigningInfo::V1 {
                public_key: setup.deposits.first().unwrap().signers_public_key,
            }
        );
        assert_eq!(parsed.lock_time, LockTime::from_height(lock_time as u16));
        assert_eq!(parsed.recipient, setup.deposits.first().unwrap().recipient);
    }

    #[test_case(true ; "is mainnet address")]
    #[test_case(false ; "is testnet address")]
    fn tx_validation_network(is_mainnet: bool) {
        let recipient = StacksAddress::burn_address(is_mainnet);
        let setup: TxSetup =
            testing::deposits::tx_setup_with_recipient(150, 2500, &[35000], recipient);

        let request = CreateDepositRequest {
            outpoint: OutPoint::new(setup.tx.compute_txid(), 0),
            reclaim_script: setup.reclaims.first().unwrap().reclaim_script(),
            deposit_script: setup.deposits.first().unwrap().deposit_script(),
            recipient: None,
            max_fee: None,
        };

        assert!(request.validate_tx(&setup.tx, is_mainnet).is_ok());
        assert!(request.validate_tx(&setup.tx, !is_mainnet).is_err());
    }

    #[test]
    fn valid_deposit_script_not_matching_tx_rejected() {
        let max_fee: u64 = 15000;
        let amount_sats = 500_000;
        let lock_time = 150;

        let mut setup: TxSetup = testing::deposits::tx_setup(lock_time, max_fee, &[amount_sats]);

        // Let's modify the max_fee of the deposit script and send that in
        // the request.
        setup.deposits.first_mut().unwrap().max_fee = 3000;

        let request = CreateDepositRequest {
            outpoint: OutPoint::new(setup.tx.compute_txid(), 0),
            deposit_script: setup.deposits.first().unwrap().deposit_script(),
            reclaim_script: setup.reclaims.first().unwrap().reclaim_script(),
            recipient: None,
            max_fee: None,
        };

        let error = request.validate_tx(&setup.tx, false).unwrap_err();
        assert!(matches!(error, Error::UtxoScriptPubKeyMismatch(_)));
    }

    #[test]
    fn valid_reclaim_script_not_matching_tx_rejected() {
        let max_fee: u64 = 15000;
        let amount_sats = 500_000;
        let lock_time = 0;

        let mut setup: TxSetup = testing::deposits::tx_setup(lock_time, max_fee, &[amount_sats]);

        // Let's modify the lock time of the reclaim script to look more
        // reasonable in the request.
        let reclaim = setup.reclaims.first_mut().unwrap();
        *reclaim = ReclaimScriptInputs::try_new(150, reclaim.user_script().to_owned()).unwrap();

        let request = CreateDepositRequest {
            outpoint: OutPoint::new(setup.tx.compute_txid(), 0),
            deposit_script: setup.deposits.first().unwrap().deposit_script(),
            reclaim_script: setup.reclaims.first().unwrap().reclaim_script(),
            recipient: None,
            max_fee: None,
        };

        let error = request.validate_tx(&setup.tx, false).unwrap_err();
        assert!(matches!(error, Error::UtxoScriptPubKeyMismatch(_)));
    }

    #[test]
    fn incorrect_tx_outpoint_rejected() {
        let max_fee: u64 = 15000;
        let amount_sats = 500_000;
        let lock_time = 150;

        let setup: TxSetup = testing::deposits::tx_setup(lock_time, max_fee, &[amount_sats]);

        let request = CreateDepositRequest {
            // This output index is guaranteed to always be incorrect.
            outpoint: OutPoint::new(setup.tx.compute_txid(), setup.tx.output.len() as u32),
            deposit_script: setup.deposits.first().unwrap().deposit_script(),
            reclaim_script: setup.reclaims.first().unwrap().reclaim_script(),
            recipient: None,
            max_fee: None,
        };

        let error = request.validate_tx(&setup.tx, false).unwrap_err();
        assert!(matches!(error, Error::OutpointIndex(_, _)));

        let request = CreateDepositRequest {
            // This txid is almost certainly incorrect.
            outpoint: OutPoint::new(Txid::all_zeros(), 0),
            deposit_script: setup.deposits.first().unwrap().deposit_script(),
            reclaim_script: setup.reclaims.first().unwrap().reclaim_script(),
            recipient: None,
            max_fee: None,
        };

        let error = request.validate_tx(&setup.tx, false).unwrap_err();
        assert!(matches!(error, Error::TxidMismatch { .. }));
    }

    #[test]
    fn correct_tx_request_has_invalid_deposit_or_reclaim_script() {
        let max_fee: u64 = 15000;
        let amount_sats = 500_000;
        let lock_time = 150;

        let setup: TxSetup = testing::deposits::tx_setup(lock_time, max_fee, &[amount_sats]);

        let request = CreateDepositRequest {
            outpoint: OutPoint::new(setup.tx.compute_txid(), 0),
            // The actual deposit script in the transaction is fine, but
            // they told us a lie and sent us an invalid deposit script in
            // their request.
            deposit_script: ScriptBuf::new(),
            reclaim_script: setup.reclaims.first().unwrap().reclaim_script(),
            recipient: None,
            max_fee: None,
        };

        let error = request.validate_tx(&setup.tx, false).unwrap_err();
        assert!(matches!(error, Error::InvalidDepositScriptLength));

        let request = CreateDepositRequest {
            outpoint: OutPoint::new(setup.tx.compute_txid(), 0),
            deposit_script: setup.deposits.first().unwrap().deposit_script(),
            // The actual reclaim script in the transaction is fine, but
            // they told us a lie, and sent us an invalid reclaim script in
            // their request.
            reclaim_script: ScriptBuf::new(),
            recipient: None,
            max_fee: None,
        };

        let error = request.validate_tx(&setup.tx, false).unwrap_err();
        assert!(matches!(error, Error::InvalidReclaimScript));
    }

    #[test]
    fn unspendable_taproot_key_no_panic() {
        // The following function calls unwrap() when called the first
        // time, check that it does not panic.
        let var1 = *crate::UNSPENDABLE_TAPROOT_KEY;
        let var2 = *crate::UNSPENDABLE_TAPROOT_KEY;
        assert_eq!(var1, var2);
    }

    #[test]
    fn v2_unspendable_taproot_key_is_nums_xpub_child_at_zero_zero() {
        let nums_xpub = Xpub {
            network: NetworkKind::Test,
            depth: 0,
            parent_fingerprint: Fingerprint::default(),
            child_number: ChildNumber::Normal { index: 0 },
            public_key: PublicKey::from_x_only_public_key(
                *crate::UNSPENDABLE_TAPROOT_KEY,
                Parity::Even,
            ),
            chain_code: ChainCode::from([0; 32]),
        };
        // This is the NUMS tpub used by Ledger's Bitcoin application tests:
        // https://github.com/LedgerHQ/app-bitcoin/blob/2.5.0/tests/test_register_wallet.py#L480-L492
        assert_eq!(
            nums_xpub.to_string(),
            "tpubD6NzVbkrYhZ4WLczPJWReQycCJdd6YVWXubbVUFnJ5KgU5MDQrD998ZJLSmaB7GVcCnJSDWprxmrGkJ6SvgQC6QAffVpqSvonXmeizXcrkN"
        );
        let path = [
            ChildNumber::Normal { index: 0 },
            ChildNumber::Normal { index: 0 },
        ];

        let derived_key = nums_xpub
            .derive_pub(SECP256K1, &path)
            .unwrap()
            .to_x_only_pub();

        assert_eq!(derived_key, *crate::V2_UNSPENDABLE_TAPROOT_KEY);
    }

    #[test_case::test_matrix(1..=16)]
    fn op_push_names_allowed(num: u8) {
        // These need to be minimal pushes, so we need to use the
        // OP_PUSHNUM_X representations.
        let lock_time = num + OP_PUSHNUM_1 - 1;

        let reclaim_script = ScriptBuf::from_bytes(vec![lock_time, OP_CSV]);
        let reclaim = ReclaimScriptInputs::parse(&reclaim_script).unwrap();

        assert_eq!(reclaim.lock_time(), num as u32);
        assert_eq!(reclaim.reclaim_script(), reclaim_script);
    }
}
