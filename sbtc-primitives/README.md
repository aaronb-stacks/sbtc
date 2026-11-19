# sbtc-primitives

Bitcoin script and signing primitives shared by sBTC and stacks-core, with no
Stacks dependencies under any feature. This crate owns key derivation,
`SignerKeySet`, v1/v2 deposit construction, reclaim construction and parsing,
commitments, Taproot helpers, and their constants and errors.

Consumers in the sBTC workspace use `sbtc-primitives.workspace = true`. External
consumers can select `package = "sbtc-primitives"` from the same git repository
and pin the desired revision. No Cargo patches are needed. The `testing` feature
adds descriptors and validation-test helpers; it also remains Stacks-independent.

Serialize a valid principal with the consumer's Clarity API and pass its bytes
directly. `PrincipalData` already bounds the serialized size; external callers
enforce this at the integration boundary. The primitive APIs do not validate
principal bytes or check the network. Pass the bytes to `DepositScriptInputs`
or `DepositScriptInputsV2`, or use them with
`deposit_data_preimage`. The caller chooses the protocol version and any epoch
or fallback behavior.

The `sbtc` crate preserves its existing APIs through adapters. Its signer and
reclaim wrappers translate primitive errors into the existing `sbtc::error::Error`
variants; key derivation, `KeySetId`, constants, and Taproot helpers are re-exports.
V1 principal parsing and transaction/network validation remain in `sbtc`.
No script format, acceptance rule, database schema, or protocol behavior changes.

Run the primitive tests from the root:

```sh
cargo test --locked -p sbtc-primitives --all-features
```

Existing `sbtc` tests also check typed/byte adapter equivalence
and frozen vectors. Their normal prerequisite is `make emily-cdk-synth`.
