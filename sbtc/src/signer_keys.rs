// Copyright (c) 2026 Stacks Open Internet Foundation
// SPDX-License-Identifier: GPL-3.0-only

//! Compatibility adapters for the shared Bitcoin signer primitives.

use crate::error::Error;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::{ScriptBuf, XOnlyPublicKey};
#[cfg(any(test, feature = "testing"))]
pub use sbtc_primitives::signer_keys::signer_set_descriptor;
pub use sbtc_primitives::signer_keys::{
    KeySetId, derive_signing_public_key, derive_signing_secret_key,
};
use secp256k1::PublicKey;
use std::collections::BTreeSet;

/// A v2 signer key set, preserving the sBTC error API.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignerKeySet(pub(crate) sbtc_primitives::SignerKeySet);

impl SignerKeySet {
    /// Construct a key set from already-derived public keys.
    pub fn new<I: IntoIterator<Item = XOnlyPublicKey>>(
        keys: I,
        threshold: u16,
    ) -> Result<Self, Error> {
        sbtc_primitives::SignerKeySet::new(keys, threshold)
            .map(Self)
            .map_err(Into::into)
    }
    /// Construct a key set already known to lock an output, without validation.
    pub fn new_unchecked<I: IntoIterator<Item = XOnlyPublicKey>>(keys: I, threshold: u16) -> Self {
        Self(sbtc_primitives::SignerKeySet::new_unchecked(
            keys, threshold,
        ))
    }
    /// Return the sorted signing keys.
    pub fn public_keys(&self) -> &BTreeSet<XOnlyPublicKey> {
        self.0.public_keys()
    }
    /// Return the signing threshold.
    pub fn signatures_required(&self) -> u16 {
        self.0.signatures_required()
    }
    /// Derive and construct a key set from configured signer public keys.
    pub fn derive<I: IntoIterator<Item = PublicKey>>(
        keys: I,
        threshold: u16,
    ) -> Result<Self, Error> {
        sbtc_primitives::SignerKeySet::derive(keys, threshold)
            .map(Self)
            .map_err(Into::into)
    }
    /// Return the stable key-set identifier.
    pub fn id(&self) -> KeySetId {
        self.0.id()
    }
    /// Parse a canonical signer script.
    pub fn parse(script: &bitcoin::Script) -> Result<Self, Error> {
        sbtc_primitives::SignerKeySet::parse(script)
            .map(Self)
            .map_err(Into::into)
    }
    /// Construct the canonical signing script.
    pub fn signing_script(&self) -> ScriptBuf {
        self.0.signing_script()
    }
    /// Construct signer UTXO spend information.
    pub fn taproot(&self) -> TaprootSpendInfo {
        self.0.taproot()
    }
    /// Construct the signer UTXO scriptPubKey.
    pub fn script_pubkey(&self) -> ScriptBuf {
        self.0.script_pubkey()
    }
    /// Return the sole script leaf's control block.
    pub fn control_block(&self) -> bitcoin::taproot::ControlBlock {
        self.0.control_block()
    }
    /// Return the signer UTXO descriptor without a checksum.
    #[cfg(any(test, feature = "testing"))]
    pub fn descriptor(&self) -> String {
        self.0.descriptor()
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use secp256k1::PublicKey;
    use secp256k1::SecretKey;
    use test_case::test_case;

    use super::*;
    use crate::MAX_SIGNERS;
    use secp256k1::SECP256K1;

    #[test]
    fn public_and_private_derivation_match() {
        let secret_key = SecretKey::new(&mut OsRng);
        let public_key = PublicKey::from_secret_key(SECP256K1, &secret_key);
        let derived_secret = derive_signing_secret_key(secret_key);
        let from_secret = derived_secret.x_only_public_key(SECP256K1).0;
        let from_public = derive_signing_public_key(public_key);
        assert_eq!(from_secret, from_public);
    }

    #[test]
    fn key_set_is_order_independent() {
        let keys: Vec<_> = (0..4)
            .map(|_| SecretKey::new(&mut OsRng).x_only_public_key(SECP256K1).0)
            .collect();
        let mut reversed = keys.clone();
        reversed.reverse();
        let first = SignerKeySet::new(keys, 3).unwrap();
        let second = SignerKeySet::new(reversed, 3).unwrap();
        assert_eq!(first.id(), second.id());
        assert_eq!(first.signing_script(), second.signing_script());
        assert_eq!(first.script_pubkey(), second.script_pubkey());
    }

    #[test]
    fn key_set_rejects_more_than_sixteen_signers() {
        let keys = (0..17)
            .map(|_| SecretKey::new(&mut OsRng).x_only_public_key(SECP256K1).0)
            .collect::<Vec<_>>();
        std::assert_matches!(
            SignerKeySet::new(keys, 12),
            Err(Error::TooManySignerKeys {
                signer_count: 17,
                max_signers: MAX_SIGNERS,
            })
        );
    }

    /// The bootstrap signing set in the devenv signer config.
    const DEVENV_SIGNER_KEYS: [&str; 3] = [
        "035249137286c077ccee65ecc43e724b9b9e5a588e3d7f51e3b62f9624c2a49e46",
        "031a4d9f4903da97498945a4e01a5023a1d53bc96ad670bfe03adf8a06c52e6380",
        "02007311430123d4cad97f4f7e86e023b28143130a18099ecf094d36fef0f6135c",
    ];

    /// The bootstrap signing set in the sample testnet signer config.
    const TESTNET_SIGNER_KEYS: [&str; 15] = [
        "03fc6197a1396680f7acc4241ac3935ba4af560deac0224abec45c47c5e73ea638",
        "0390d76b21867e9c5aa25a903423d3ddb0da65604f0470390ed903f2056c5adb4b",
        "03fb16c76ae6773951b2ea957f723dc0f5f4ccd795313793308a38a37a3c4aa582",
        "024681893c76fb2d52bdbcd6341c66f15f14698aed638d6c1a2fc9440948b5f11a",
        "0341a8f3562d805ab240c2ce2dd220313329ef75459f115bd818b250a2ad2df6aa",
        "02a963be44cd7efd07e59e28f02f5d2bafdf28b5b13b3b13b5c2a9e3f4c1b1e5bf",
        "03c4382afb075bf577acbb13196e6130c386a3d8261326402f587fb7c42d0dbd5e",
        "02c2b53974a2b1a05103a7c42a4861c859c9b999ed196c065bcec952438ae8ec9b",
        "034646af6402dab3a265688b2ea67a7aa88d9fc6eca663385a6e92336f7f081c59",
        "02629d043197e659ac45f0332b219760b9542d22499ff6431c113ec64d60e86628",
        "033f3dd6b1e8e4cfff219054dce240d312b6deda10386c3a815459224a2ba0f411",
        "031c7e1267b272d5a11257f46c61e0e5005337ebcebb6f2b71798addfd04e5a38a",
        "02ae3a560f4f67ce8c0f4b2e46d24f51232a768cfc69cf08a02ea02426d77bd64c",
        "026fb0b3c3ea60a3197e94f2dcd37d7f302e6d33c75351f4f5024e9c31ac327c11",
        "0374e256948a14799c2a788960ab6657dc5d322b070abae4ce83b2a0df4df2c727",
    ];

    /// A randomly generated key, for a key set with a single signer.
    const RANDOM_SIGNER_KEYS: [&str; 1] =
        ["027212421e4a9c34e251a7cd523146c4434451e42c230d576b07fe8874f97a694d"];

    /// Signer UTXOs locked by a key set must stay spendable by that key
    /// set, so the scriptPubKey that we derive from the signers' public
    /// keys and threshold must never change.
    ///
    /// Each expected scriptPubKey was checked against Bitcoin Core, which
    /// derives the same address from the descriptor returned by
    /// [`signer_set_descriptor`] with [`NetworkKind::Test`]. Bitcoin Core does the
    /// BIP32 derivation itself, so this also checks our derivation. To
    /// repeat the check, run
    ///
    /// ```text
    /// bitcoin-cli -regtest getdescriptorinfo "<descriptor>"
    /// bitcoin-cli -regtest deriveaddresses "<descriptor with checksum>"
    /// ```
    ///
    /// and compare the result with the regtest address of the expected
    /// scriptPubKey.
    #[test_case(
        DEVENV_SIGNER_KEYS, 2,
        "512044d42c5fdc191818e50ec6591d2103f17ec2771c1a0ea5dc1db95ca56dd377b5";
        "devenv 2-of-3"
    )]
    #[test_case(
        TESTNET_SIGNER_KEYS, 11,
        "512036beeeb78d2eff65baa60f8da199b5ecd06ee833dd3c8f6340f8b6d4102a595c";
        "testnet 11-of-15"
    )]
    #[test_case(
        RANDOM_SIGNER_KEYS, 1,
        "5120a014d46c5ec41d7d059755296e1d12566ca7416d3707a7789d2a3c88ee1eeca2";
        "random 1-of-1"
    )]
    fn key_set_script_pubkey_is_stable<const N: usize>(
        signer_keys: [&str; N],
        signatures_required: u16,
        expected_script_pubkey: &str,
    ) {
        let public_keys = signer_keys
            .iter()
            .map(|key| key.parse::<PublicKey>().unwrap());
        let key_set = SignerKeySet::derive(public_keys, signatures_required).unwrap();

        let script_pubkey = key_set.script_pubkey();
        assert_eq!(script_pubkey.to_hex_string(), expected_script_pubkey);
    }
}
