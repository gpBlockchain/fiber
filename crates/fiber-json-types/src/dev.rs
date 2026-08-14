//! Development/debug types for the Fiber Network JSON-RPC API.

use crate::invoice::HashAlgorithm;
use crate::schema_helpers::*;
use crate::serde_utils::{Hash256, U128Hex, U64Hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// Parameters for sending a commitment_signed message.
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct CommitmentSignedParams {
    /// The channel ID of the channel to send the commitment_signed message to
    pub channel_id: Hash256,
}

/// Parameters for adding a TLC.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct AddTlcParams {
    /// The channel ID of the channel to add the TLC to
    pub channel_id: Hash256,
    /// The amount of the TLC
    #[serde_as(as = "U128Hex")]
    #[schemars(schema_with = "schema_as_uint_hex")]
    pub amount: u128,
    /// The payment hash of the TLC
    pub payment_hash: Hash256,
    /// The expiry of the TLC
    #[serde_as(as = "U64Hex")]
    #[schemars(schema_with = "schema_as_uint_hex")]
    pub expiry: u64,
    /// The hash algorithm of the TLC
    pub hash_algorithm: Option<HashAlgorithm>,
}

/// Result of adding a TLC.
#[serde_as]
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
pub struct AddTlcResult {
    /// The ID of the TLC
    #[serde_as(as = "U64Hex")]
    #[schemars(schema_with = "schema_as_uint_hex")]
    pub tlc_id: u64,
}

/// Parameters for removing a TLC.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
pub struct RemoveTlcParams {
    /// The channel ID of the channel to remove the TLC from
    pub channel_id: Hash256,
    #[serde_as(as = "U64Hex")]
    #[schemars(schema_with = "schema_as_uint_hex")]
    /// The ID of the TLC to remove
    pub tlc_id: u64,
    /// The reason for removing the TLC, either a 32-byte hash for preimage fulfillment or an u32 error code for removal
    pub reason: RemoveTlcReason,
}

/// The reason for removing a TLC.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(untagged)]
pub enum RemoveTlcReason {
    /// The reason for removing the TLC is that it was fulfilled
    RemoveTlcFulfill { payment_preimage: Hash256 },
    /// The reason for removing the TLC is that it failed
    RemoveTlcFail { error_code: String },
}

/// Parameters for submitting a commitment transaction.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
pub struct SubmitCommitmentTransactionParams {
    /// Channel ID
    pub channel_id: Hash256,
    /// Commitment number
    #[serde_as(as = "U64Hex")]
    #[schemars(schema_with = "schema_as_uint_hex")]
    pub commitment_number: u64,
}

/// Result of submitting a commitment transaction.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
pub struct SubmitCommitmentTransactionResult {
    /// Submitted commitment transaction hash
    pub tx_hash: Hash256,
}

/// Parameters for checking channel shutdown.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
pub struct CheckChannelShutdownParams {
    /// Channel ID
    pub channel_id: Hash256,
}

/// Parameters for signing an external funding transaction.
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
pub struct SignExternalFundingTxParams {
    /// The unsigned funding transaction returned from `open_channel_with_external_funding`.
    pub unsigned_funding_tx: ckb_jsonrpc_types::Transaction,
    /// The private key to sign the transaction, as a 0x-prefixed 32-byte hex string.
    /// Note: This is a development-only RPC and the private key is provided directly.
    pub private_key: String,
}

/// Result of signing an external funding transaction.
#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub struct SignExternalFundingTxResult {
    /// The signed funding transaction that can be submitted via `submit_signed_funding_tx`.
    pub signed_funding_tx: ckb_jsonrpc_types::Transaction,
}

/// Parameters for intercepting Fiber channel messages on this node.
///
/// Debug-only. Used to drive a malicious or faulty peer from outside the node.
/// Kind names match `FiberChannelMessage` (`CommitmentSigned`, `RevokeAndAck`,
/// `AddTlc`, ...). Snake case (`commitment_signed`) is also accepted.
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
pub struct SetFiberMessageInterceptParams {
    /// The channel whose messages should be intercepted
    pub channel_id: Hash256,
    /// If true, outbound `RevokeAndAck` messages for this channel are dropped.
    /// Kept for the nonce-reuse tests. Prefer `outbound_drop_kinds`.
    #[serde(default)]
    pub suppress_outbound_revoke_and_ack: bool,
    /// If true and `inbound_capture_kinds` is empty, every inbound channel
    /// message is queued and not delivered to the honest channel actor.
    #[serde(default)]
    pub capture_inbound: bool,
    /// Inbound kinds to queue for `take_captured_fiber_messages` / `deliver_captured_fiber_messages`.
    /// When non-empty, only these kinds are captured (`capture_inbound` is ignored).
    #[serde(default)]
    pub inbound_capture_kinds: Vec<String>,
    /// Inbound kinds to drop silently (not queued, not delivered).
    #[serde(default)]
    pub inbound_drop_kinds: Vec<String>,
    /// Outbound kinds to drop before they hit the wire.
    #[serde(default)]
    pub outbound_drop_kinds: Vec<String>,
    /// Outbound kinds to hold for `release_held_outbound_fiber_messages`.
    #[serde(default)]
    pub outbound_hold_kinds: Vec<String>,
}

/// Parameters for delivering previously captured inbound messages to the channel actor.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
pub struct DeliverCapturedFiberMessagesParams {
    /// Max number of matching messages to deliver. Omit to deliver all matching.
    #[serde_as(as = "Option<U64Hex>")]
    #[schemars(schema_with = "schema_as_uint_hex_optional")]
    pub count: Option<u64>,
    /// If set, only these kinds are delivered (FIFO among matches).
    #[serde(default)]
    pub kinds: Vec<String>,
}

/// Result of delivering captured inbound messages.
#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub struct DeliverCapturedFiberMessagesResult {
    /// How many messages were delivered
    #[serde_as(as = "U64Hex")]
    #[schemars(schema_with = "schema_as_uint_hex")]
    pub delivered: u64,
}

/// Parameters for releasing held outbound messages to the wire.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
pub struct ReleaseHeldOutboundFiberMessagesParams {
    /// Max number of matching messages to send. Omit to send all matching.
    #[serde_as(as = "Option<U64Hex>")]
    #[schemars(schema_with = "schema_as_uint_hex_optional")]
    pub count: Option<u64>,
    /// If set, only these kinds are released (FIFO among matches).
    #[serde(default)]
    pub kinds: Vec<String>,
}

/// Result of releasing held outbound messages.
#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub struct ReleaseHeldOutboundFiberMessagesResult {
    /// How many messages were sent
    #[serde_as(as = "U64Hex")]
    #[schemars(schema_with = "schema_as_uint_hex")]
    pub released: u64,
}

/// One Fiber channel message captured or held by the intercept.
#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub struct CapturedFiberMessage {
    /// Peer that sent the message (identity pubkey, hex without 0x prefix)
    pub peer_pubkey: crate::serde_utils::Pubkey,
    /// Channel this message belongs to, if it is a channel message
    pub channel_id: Option<Hash256>,
    /// Fiber channel message kind, e.g. `CommitmentSigned`, `ClosingSigned`, `Shutdown`, `RevokeAndAck`
    pub kind: String,
    /// Molecule-encoded Fiber message, `0x`-prefixed hex
    #[schemars(schema_with = "schema_as_hex_bytes")]
    pub payload: String,
    /// Partial signature from `CommitmentSigned.funding_tx_partial_signature`, if any
    #[schemars(schema_with = "schema_as_hex_bytes_optional")]
    pub funding_tx_partial_signature: Option<String>,
    /// Partial signature from `ClosingSigned.partial_signature`, if any
    #[schemars(schema_with = "schema_as_hex_bytes_optional")]
    pub closing_partial_signature: Option<String>,
    /// `next_commitment_nonce` from `CommitmentSigned`, if any
    #[schemars(schema_with = "schema_as_hex_bytes_optional")]
    pub next_commitment_nonce: Option<String>,
    /// Close script from an inbound `Shutdown`, if any
    pub close_script: Option<ckb_jsonrpc_types::Script>,
    /// Fee rate from an inbound `Shutdown`, if any
    #[serde_as(as = "Option<U64Hex>")]
    #[schemars(schema_with = "schema_as_uint_hex_optional")]
    pub fee_rate: Option<u64>,
    /// `AddTlc.tlc_id` or `RemoveTlc.tlc_id`, if any
    #[serde_as(as = "Option<U64Hex>")]
    #[schemars(schema_with = "schema_as_uint_hex_optional")]
    pub tlc_id: Option<u64>,
    /// `AddTlc.payment_hash`, if any
    pub payment_hash: Option<Hash256>,
    /// `ReestablishChannel.local_commitment_number`, if any
    #[serde_as(as = "Option<U64Hex>")]
    #[schemars(schema_with = "schema_as_uint_hex_optional")]
    pub local_commitment_number: Option<u64>,
    /// `ReestablishChannel.remote_commitment_number`, if any
    #[serde_as(as = "Option<U64Hex>")]
    #[schemars(schema_with = "schema_as_uint_hex_optional")]
    pub remote_commitment_number: Option<u64>,
}

/// Result of taking captured inbound Fiber messages.
#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub struct TakeCapturedFiberMessagesResult {
    /// Messages captured since the previous take (FIFO). The intercept stays active.
    pub messages: Vec<CapturedFiberMessage>,
}

/// Kind of raw channel message to send, bypassing the honest channel actor.
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RawChannelMessageKind {
    /// Build and send a `CommitmentSigned` from this node's channel state
    CommitmentSigned,
    /// Send a `Shutdown` from this node
    Shutdown,
    /// Send an `AddTlc` without running the honest add/commit path
    AddTlc,
    /// Send a `RemoveTlc` (fail) without running the honest remove/commit path
    RemoveTlc,
    /// Send a `ReestablishChannel`, optionally with forged commitment numbers
    ReestablishChannel,
    /// Send a `TxAbort`
    TxAbort,
}

/// Parameters for sending a raw Fiber channel message without running the
/// honest channel-actor send path (so this node will not automatically
/// `RevokeAndAck` or advance its commitment number).
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
pub struct SendRawChannelMessageParams {
    /// The channel to send on
    pub channel_id: Hash256,
    /// Which wire message to send
    pub kind: RawChannelMessageKind,
    /// Optional commitment number used to derive the musig2 nonce when sending
    /// `CommitmentSigned`. Defaults to this node's current local commitment number.
    /// Pass `local_cn + 1` to craft the second empty CS of the no-RAA attack.
    #[serde_as(as = "Option<U64Hex>")]
    #[schemars(schema_with = "schema_as_uint_hex_optional")]
    pub nonce_commitment_number: Option<u64>,
    /// Close script for `Shutdown`. Defaults to this node's local shutdown script.
    pub close_script: Option<ckb_jsonrpc_types::Script>,
    /// Fee rate for `Shutdown`. Defaults to the node commitment fee rate.
    #[serde_as(as = "Option<U64Hex>")]
    #[schemars(schema_with = "schema_as_uint_hex_optional")]
    pub fee_rate: Option<u64>,
    /// TLC amount for `AddTlc`. Defaults to 1 shannon.
    #[serde_as(as = "Option<U128Hex>")]
    #[schemars(schema_with = "schema_as_uint_hex_optional")]
    pub amount: Option<u128>,
    /// Payment hash for `AddTlc`. Defaults to 32 zero bytes.
    pub payment_hash: Option<Hash256>,
    /// Expiry (unix ms) for `AddTlc`. Defaults to now + 24h.
    #[serde_as(as = "Option<U64Hex>")]
    #[schemars(schema_with = "schema_as_uint_hex_optional")]
    pub expiry: Option<u64>,
    /// TLC id for `AddTlc` / `RemoveTlc`. Defaults to this node's next offered id for `AddTlc`.
    #[serde_as(as = "Option<U64Hex>")]
    #[schemars(schema_with = "schema_as_uint_hex_optional")]
    pub tlc_id: Option<u64>,
    /// Error code name for `RemoveTlc` fail, e.g. `TemporaryChannelFailure`. Defaults to that.
    pub remove_fail_error_code: Option<String>,
    /// Forged local commitment number for `ReestablishChannel`. Defaults to this node's local cn.
    #[serde_as(as = "Option<U64Hex>")]
    #[schemars(schema_with = "schema_as_uint_hex_optional")]
    pub local_commitment_number: Option<u64>,
    /// Forged remote commitment number for `ReestablishChannel`. Defaults to this node's remote cn.
    #[serde_as(as = "Option<U64Hex>")]
    #[schemars(schema_with = "schema_as_uint_hex_optional")]
    pub remote_commitment_number: Option<u64>,
    /// Abort reason bytes for `TxAbort`, as `0x`-prefixed hex or utf8 text. Defaults to `p2p-test`.
    pub abort_message: Option<String>,
}

/// Result of sending a raw Fiber channel message.
#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub struct SendRawChannelMessageResult {
    /// Partial signature included in a sent `CommitmentSigned`, if any
    #[schemars(schema_with = "schema_as_hex_bytes_optional")]
    pub funding_tx_partial_signature: Option<String>,
    /// `next_commitment_nonce` included in a sent `CommitmentSigned`, if any
    #[schemars(schema_with = "schema_as_hex_bytes_optional")]
    pub next_commitment_nonce: Option<String>,
}

/// Parameters for reading the public musig2 session of a channel (attacker view).
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
pub struct GetChannelMusig2PublicParams {
    /// The channel ID
    pub channel_id: Hash256,
}

/// Public musig2 / commitment-tx inputs a peer can compute from its own state.
#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub struct GetChannelMusig2PublicResult {
    /// This node's funding pubkey (hex without 0x prefix)
    pub local_funding_pubkey: crate::serde_utils::Pubkey,
    /// Counterparty funding pubkey (hex without 0x prefix)
    pub remote_funding_pubkey: crate::serde_utils::Pubkey,
    /// This node's local commitment number
    #[serde_as(as = "U64Hex")]
    #[schemars(schema_with = "schema_as_uint_hex")]
    pub local_commitment_number: u64,
    /// Counterparty commitment number as this node currently tracks it
    #[serde_as(as = "U64Hex")]
    #[schemars(schema_with = "schema_as_uint_hex")]
    pub remote_commitment_number: u64,
    /// This node's current commitment pubnonce (`0x`-prefixed hex)
    #[schemars(schema_with = "schema_as_hex_bytes")]
    pub local_pubnonce: String,
    /// Last pubnonce the counterparty committed (`0x`-prefixed hex)
    #[schemars(schema_with = "schema_as_hex_bytes")]
    pub last_committed_remote_nonce: String,
    /// Next commitment pubnonce this node would advertise (`0x`-prefixed hex)
    #[schemars(schema_with = "schema_as_hex_bytes")]
    pub next_commitment_nonce: String,
    /// Sighash of this node's own commitment tx (the message signed in our `CommitmentSigned`)
    pub own_commitment_message: Hash256,
    /// Sighash of the counterparty commitment tx (the message we counter-sign while verifying)
    pub peer_commitment_message: Hash256,
    /// Funding cell outpoint
    pub funding_outpoint: ckb_jsonrpc_types::OutPoint,
    /// Whether this node's funding pubkey is first in musig2 key aggregation
    pub local_first: bool,
}

/// Parameters for rebuilding the shutdown transaction message from public close scripts.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
pub struct BuildShutdownTxMessageParams {
    /// The channel ID
    pub channel_id: Hash256,
    /// This node's close script (as used in our `Shutdown`)
    pub local_close_script: ckb_jsonrpc_types::Script,
    /// Counterparty close script (as observed in their `Shutdown`)
    pub remote_close_script: ckb_jsonrpc_types::Script,
    /// Fee rate from our `Shutdown`
    #[serde_as(as = "U64Hex")]
    #[schemars(schema_with = "schema_as_uint_hex")]
    pub local_fee_rate: u64,
    /// Fee rate from the counterparty `Shutdown` (auto-accept uses 0)
    #[serde_as(as = "U64Hex")]
    #[schemars(schema_with = "schema_as_uint_hex")]
    pub remote_fee_rate: u64,
}

/// Result of rebuilding the shutdown transaction sighash.
#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub struct BuildShutdownTxMessageResult {
    /// Sighash of the shutdown transaction
    pub message: Hash256,
}
