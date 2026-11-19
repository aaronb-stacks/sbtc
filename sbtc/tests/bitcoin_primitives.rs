// Copyright (C) 2026 Stacks Open Internet Foundation
// SPDX-License-Identifier: GPL-3.0-only
//! Frozen Bitcoin vectors for the Stacks-independent deposit builders.

use bitcoin::ScriptBuf;
use bitcoin::XOnlyPublicKey;
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::opcodes::all as opcodes;
use bitcoin::secp256k1::{PublicKey, SECP256K1, SecretKey};
use sbtc::SignerKeySet;
use sbtc::deposits::{
    ReclaimScriptInputs, deposit_data_preimage_bytes, deposit_script, deposit_script_v2,
    to_script_pubkey, to_v2_script_pubkey,
};

/// Standard and contract principals from the existing commitment vectors.
const RECIPIENTS: [(&str, u64, &str, &str); 2] = [
    (
        "05160000000000000000000000000000000000000000",
        80_000,
        "7b7fe3bbc53fcb13556d204e0b69371e3db6e0993ad80e3a08d17a9f0347664a",
        "bc94e3d783ea495b3e32378c650a0d3ebcf1db9289b9457d8fdd49e069e35392",
    ),
    (
        "061600000000000000000000000000000000000000000b6d792d636f6e7472616374",
        123_456,
        "46d23f398c2c553eb97e7c8a3cfdacae20ff64585aaf41348c47b08896997c22",
        "605806257b04557450ba77a3c9b09ea07dd3f20dd54f357851e3894fc7a1809f",
    ),
];

fn keys() -> [XOnlyPublicKey; 3] {
    [
        "374bfe83198f423d763ddcad92837229b219117750cf8eee106f59f09ebac157",
        "b08d2faade97ce5b7159fc49ed3a98ebfde9dcfe70ba6aaa614da225f4fcf8a6",
        "c4a51ca195d4b7fe6307de43a6dc7758eb60475fabe82862bc4299350c09c21c",
    ]
    .map(|key| key.parse().unwrap())
}

fn reclaim() -> ScriptBuf {
    let key: XOnlyPublicKey = "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
        .parse()
        .unwrap();
    let script = ScriptBuf::builder()
        .push_opcode(opcodes::OP_DROP)
        .push_slice(key.serialize())
        .push_opcode(opcodes::OP_CHECKSIG)
        .into_script();
    ReclaimScriptInputs::try_new(950, script)
        .unwrap()
        .reclaim_script()
}

#[test]
fn deposit_vectors() {
    let key_set = SignerKeySet::new(keys(), 2).unwrap();
    // Recorded from the unmodified typed v1 implementation at 0165961e.
    let v1_outputs = [
        "512090a5abaac71381f39b6e0e3efbef09b7eba9f2e45f2ea34e7a6fe7d98285993d",
        "51209f613f9438995dfa82ca3ea3b635d936bcda6d4d2ae860cc9ba24e7bc4b5a2a0",
    ];
    for ((recipient_hex, max_fee, preimage, commitment), v1_output) in
        RECIPIENTS.into_iter().zip(v1_outputs)
    {
        let bytes = Vec::from_hex(recipient_hex).unwrap();
        let recipient = bytes.as_slice();
        assert_eq!(
            deposit_data_preimage_bytes(max_fee, recipient).to_lower_hex_string(),
            preimage
        );
        let v1 = deposit_script(keys()[0], max_fee, recipient);
        let expected_v1 = format!(
            "{:02x}{max_fee:016x}{recipient_hex}7520{}ac",
            bytes.len() + 8,
            keys()[0]
        );
        assert_eq!(v1.to_hex_string(), expected_v1);
        assert_eq!(
            to_script_pubkey(v1.clone(), reclaim()).to_hex_string(),
            v1_output
        );
        let v2 = deposit_script_v2(&key_set, max_fee, recipient);
        assert_eq!(
            v2.to_hex_string(),
            format!(
                "82012088a820{commitment}88{}",
                key_set.signing_script().to_hex_string()
            )
        );
        assert_ne!(
            to_script_pubkey(v1.clone(), reclaim()),
            to_v2_script_pubkey(v2.clone(), reclaim())
        );
        // Exercise the caller's fee and recipient bytes independently.
        assert_ne!(v1, deposit_script(keys()[0], max_fee + 1, recipient));
        assert_ne!(v2, deposit_script_v2(&key_set, max_fee + 1, recipient));
        let mut other = bytes.clone();
        other[2] = 1;
        assert_ne!(v2, deposit_script_v2(&key_set, max_fee, &other));
    }
    let bytes = Vec::from_hex(RECIPIENTS[1].0).unwrap();
    let v2 = deposit_script_v2(&key_set, RECIPIENTS[1].1, &bytes);
    assert_eq!(
        to_v2_script_pubkey(v2, reclaim()).to_hex_string(),
        "51201c7da221d03a975094a5b500a0a853d7dbe34dd17a768c34b8130212a9f2f997"
    );
    assert_eq!(
        reclaim().to_hex_string(),
        "02b603b275201b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fac"
    );
}

#[test]
fn signer_keys_remain_available() {
    let public: PublicKey = "027212421e4a9c34e251a7cd523146c4434451e42c230d576b07fe8874f97a694d"
        .parse()
        .unwrap();
    let set = SignerKeySet::derive([public], 1).unwrap();
    assert_eq!(
        set.script_pubkey().to_hex_string(),
        "5120a014d46c5ec41d7d059755296e1d12566ca7416d3707a7789d2a3c88ee1eeca2"
    );
    let secret = SecretKey::from_slice(&[1; 32]).unwrap();
    assert_eq!(
        sbtc::derive_signing_public_key(secret.public_key(SECP256K1)),
        sbtc::derive_signing_secret_key(secret)
            .x_only_public_key(SECP256K1)
            .0
    );
    let [a, b, c] = keys();
    assert_eq!(
        SignerKeySet::new([c, a, b, a], 2).unwrap(),
        SignerKeySet::new([a, b, c], 2).unwrap()
    );
    assert!(SignerKeySet::new([a], 0).is_err());
    assert!(SignerKeySet::new([a], 2).is_err());
}
