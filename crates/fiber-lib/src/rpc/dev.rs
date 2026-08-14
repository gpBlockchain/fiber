// #[cfg(not(target_arch = "wasm32"))]
// use crate::watchtower::WatchtowerStore;
use crate::fiber::{
    channel::{ChannelCommand, ChannelCommandWithId, RemoveTlcCommand},
    network::{
        BuildShutdownTxMessageCommand, CapturedInboundFiberMessage,
        DeliverCapturedFiberMessagesCommand, FiberMessageIntercept, RawChannelMessageKind,
        ReleaseHeldOutboundFiberMessagesCommand, SendRawChannelMessageCommand,
    },
    types::{FiberChannelMessage, FiberMessage},
    NetworkActorCommand, NetworkActorMessage,
};
use crate::rpc::utils::rpc_error;
use ckb_sdk::util::blake160;
use ckb_types::core::TransactionView;
use ckb_types::prelude::{Entity, Unpack};
use fiber_json_types::serde_utils::Hash256 as JsonHash256;
use fiber_types::{
    AddTlcCommand, Hash256, HashAlgorithm, RemoveTlcFulfill, TlcErr, TlcErrPacket, TlcErrorCode,
    NO_SHARED_SECRET,
};
#[cfg(not(target_arch = "wasm32"))]
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;
use musig2::BinaryEncoding;

use ractor::call;
use std::str::FromStr;
use std::{collections::HashMap, sync::Arc};

use ractor::{call_t, ActorRef};
use tokio::sync::RwLock;

use crate::{
    ckb::CkbChainMessage, fiber::network::DEFAULT_CHAIN_ACTOR_TIMEOUT, handle_actor_call,
    log_and_error,
};

pub use fiber_json_types::{
    AddTlcParams, AddTlcResult, BuildShutdownTxMessageParams, BuildShutdownTxMessageResult,
    CapturedFiberMessage, CheckChannelShutdownParams, CommitmentSignedParams,
    DeliverCapturedFiberMessagesParams, DeliverCapturedFiberMessagesResult,
    GetChannelMusig2PublicParams, GetChannelMusig2PublicResult,
    ReleaseHeldOutboundFiberMessagesParams, ReleaseHeldOutboundFiberMessagesResult,
    RemoveTlcParams, RemoveTlcReason, SendRawChannelMessageParams, SendRawChannelMessageResult,
    SetFiberMessageInterceptParams, SignExternalFundingTxParams, SignExternalFundingTxResult,
    SubmitCommitmentTransactionParams, SubmitCommitmentTransactionResult,
    TakeCapturedFiberMessagesResult,
};

/// RPC module for development purposes, this module is not intended to be used in production.
/// This module will be disabled in release build.
#[cfg(not(target_arch = "wasm32"))]
#[rpc(server)]
trait DevRpc {
    /// Sends a commitment_signed message to the peer.
    #[method(name = "commitment_signed")]
    async fn commitment_signed(
        &self,
        params: CommitmentSignedParams,
    ) -> Result<(), ErrorObjectOwned>;

    /// Adds a TLC to a channel.
    #[method(name = "add_tlc")]
    async fn add_tlc(&self, params: AddTlcParams) -> Result<AddTlcResult, ErrorObjectOwned>;

    /// Removes a TLC from a channel.
    #[method(name = "remove_tlc")]
    async fn remove_tlc(&self, params: RemoveTlcParams) -> Result<(), ErrorObjectOwned>;

    /// Submit a commitment transaction to the chain
    #[method(name = "submit_commitment_transaction")]
    async fn submit_commitment_transaction(
        &self,
        params: SubmitCommitmentTransactionParams,
    ) -> Result<SubmitCommitmentTransactionResult, ErrorObjectOwned>;

    /// Manually trigger CheckShutdownTx on all channels
    #[method(name = "check_channel_shutdown")]
    async fn check_channel_shutdown(
        &self,
        params: CheckChannelShutdownParams,
    ) -> Result<(), ErrorObjectOwned>;

    /// Sign an external funding transaction with a provided private key.
    ///
    /// This is a development-only RPC that signs an unsigned funding transaction
    /// (returned from `open_channel_with_external_funding`) using the provided private key.
    /// The signed transaction can then be submitted via `submit_signed_funding_tx`.
    #[method(name = "sign_external_funding_tx")]
    async fn sign_external_funding_tx(
        &self,
        params: SignExternalFundingTxParams,
    ) -> Result<SignExternalFundingTxResult, ErrorObjectOwned>;

    /// Intercept Fiber channel messages on this node so a test client can act as a
    /// malicious peer: drop outbound `RevokeAndAck` and capture inbound messages
    /// without delivering them to the honest channel actor.
    #[method(name = "set_fiber_message_intercept")]
    async fn set_fiber_message_intercept(
        &self,
        params: SetFiberMessageInterceptParams,
    ) -> Result<(), ErrorObjectOwned>;

    /// Drain inbound Fiber messages captured by `set_fiber_message_intercept`.
    /// The intercept stays active.
    #[method(name = "take_captured_fiber_messages")]
    async fn take_captured_fiber_messages(
        &self,
    ) -> Result<TakeCapturedFiberMessagesResult, ErrorObjectOwned>;

    /// Deliver previously captured inbound messages to the honest channel actor
    /// (delay / later-release). Consumes the delivered messages from the capture queue.
    #[method(name = "deliver_captured_fiber_messages")]
    async fn deliver_captured_fiber_messages(
        &self,
        params: DeliverCapturedFiberMessagesParams,
    ) -> Result<DeliverCapturedFiberMessagesResult, ErrorObjectOwned>;

    /// Drain outbound messages held by `outbound_hold_kinds` without sending them.
    #[method(name = "take_held_outbound_fiber_messages")]
    async fn take_held_outbound_fiber_messages(
        &self,
    ) -> Result<TakeCapturedFiberMessagesResult, ErrorObjectOwned>;

    /// Send previously held outbound messages to the peer.
    #[method(name = "release_held_outbound_fiber_messages")]
    async fn release_held_outbound_fiber_messages(
        &self,
        params: ReleaseHeldOutboundFiberMessagesParams,
    ) -> Result<ReleaseHeldOutboundFiberMessagesResult, ErrorObjectOwned>;

    /// Send a `CommitmentSigned` or `Shutdown` without running the honest channel-actor
    /// send path (no automatic `RevokeAndAck`, no local commitment-number advance).
    #[method(name = "send_raw_channel_message")]
    async fn send_raw_channel_message(
        &self,
        params: SendRawChannelMessageParams,
    ) -> Result<SendRawChannelMessageResult, ErrorObjectOwned>;

    /// Return the public musig2 session of a channel from this node's own state.
    #[method(name = "get_channel_musig2_public")]
    async fn get_channel_musig2_public(
        &self,
        params: GetChannelMusig2PublicParams,
    ) -> Result<GetChannelMusig2PublicResult, ErrorObjectOwned>;

    /// Rebuild the shutdown-transaction sighash from publicly observed close scripts.
    #[method(name = "build_shutdown_tx_message")]
    async fn build_shutdown_tx_message(
        &self,
        params: BuildShutdownTxMessageParams,
    ) -> Result<BuildShutdownTxMessageResult, ErrorObjectOwned>;
}

pub struct DevRpcServerImpl {
    ckb_rpc_url: String,
    ckb_chain_actor: ActorRef<CkbChainMessage>,
    network_actor: ActorRef<NetworkActorMessage>,
    commitment_txs: Arc<RwLock<HashMap<(Hash256, u64), TransactionView>>>,
}

impl DevRpcServerImpl {
    pub fn new(
        ckb_rpc_url: String,
        ckb_chain_actor: ActorRef<CkbChainMessage>,
        network_actor: ActorRef<NetworkActorMessage>,
        commitment_txs: Arc<RwLock<HashMap<(Hash256, u64), TransactionView>>>,
    ) -> Self {
        Self {
            ckb_rpc_url,
            ckb_chain_actor,
            network_actor,
            commitment_txs,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl DevRpcServer for DevRpcServerImpl {
    /// Sends a commitment_signed message to the peer.
    async fn commitment_signed(
        &self,
        params: CommitmentSignedParams,
    ) -> Result<(), ErrorObjectOwned> {
        self.commitment_signed(params).await
    }

    /// Adds a TLC to a channel.
    async fn add_tlc(&self, params: AddTlcParams) -> Result<AddTlcResult, ErrorObjectOwned> {
        self.add_tlc(params).await
    }

    /// Removes a TLC from a channel.
    async fn remove_tlc(&self, params: RemoveTlcParams) -> Result<(), ErrorObjectOwned> {
        self.remove_tlc(params).await
    }

    /// Submit a commitment transaction to the chain
    async fn submit_commitment_transaction(
        &self,
        params: SubmitCommitmentTransactionParams,
    ) -> Result<SubmitCommitmentTransactionResult, ErrorObjectOwned> {
        self.submit_commitment_transaction(params).await
    }

    async fn check_channel_shutdown(
        &self,
        params: CheckChannelShutdownParams,
    ) -> Result<(), ErrorObjectOwned> {
        self.check_channel_shutdown(params).await
    }

    async fn sign_external_funding_tx(
        &self,
        params: SignExternalFundingTxParams,
    ) -> Result<SignExternalFundingTxResult, ErrorObjectOwned> {
        self.sign_external_funding_tx(params).await
    }

    async fn set_fiber_message_intercept(
        &self,
        params: SetFiberMessageInterceptParams,
    ) -> Result<(), ErrorObjectOwned> {
        self.set_fiber_message_intercept(params).await
    }

    async fn take_captured_fiber_messages(
        &self,
    ) -> Result<TakeCapturedFiberMessagesResult, ErrorObjectOwned> {
        self.take_captured_fiber_messages().await
    }

    async fn deliver_captured_fiber_messages(
        &self,
        params: DeliverCapturedFiberMessagesParams,
    ) -> Result<DeliverCapturedFiberMessagesResult, ErrorObjectOwned> {
        self.deliver_captured_fiber_messages(params).await
    }

    async fn take_held_outbound_fiber_messages(
        &self,
    ) -> Result<TakeCapturedFiberMessagesResult, ErrorObjectOwned> {
        self.take_held_outbound_fiber_messages().await
    }

    async fn release_held_outbound_fiber_messages(
        &self,
        params: ReleaseHeldOutboundFiberMessagesParams,
    ) -> Result<ReleaseHeldOutboundFiberMessagesResult, ErrorObjectOwned> {
        self.release_held_outbound_fiber_messages(params).await
    }

    async fn send_raw_channel_message(
        &self,
        params: SendRawChannelMessageParams,
    ) -> Result<SendRawChannelMessageResult, ErrorObjectOwned> {
        self.send_raw_channel_message(params).await
    }

    async fn get_channel_musig2_public(
        &self,
        params: GetChannelMusig2PublicParams,
    ) -> Result<GetChannelMusig2PublicResult, ErrorObjectOwned> {
        self.get_channel_musig2_public(params).await
    }

    async fn build_shutdown_tx_message(
        &self,
        params: BuildShutdownTxMessageParams,
    ) -> Result<BuildShutdownTxMessageResult, ErrorObjectOwned> {
        self.build_shutdown_tx_message(params).await
    }
}
impl DevRpcServerImpl {
    pub async fn commitment_signed(
        &self,
        params: CommitmentSignedParams,
    ) -> Result<(), ErrorObjectOwned> {
        let channel_id = params.channel_id.into();
        let message = |rpc_reply| {
            NetworkActorMessage::Command(NetworkActorCommand::ControlFiberChannel(
                ChannelCommandWithId {
                    channel_id,
                    command: ChannelCommand::CommitmentSigned(Some(rpc_reply)),
                },
            ))
        };
        handle_actor_call!(self.network_actor, message, params)
    }

    pub async fn add_tlc(&self, params: AddTlcParams) -> Result<AddTlcResult, ErrorObjectOwned> {
        let channel_id = params.channel_id.into();
        let payment_hash = params.payment_hash.into();
        let hash_algorithm = params
            .hash_algorithm
            .map(HashAlgorithm::from)
            .unwrap_or_default();

        let message = |rpc_reply| -> NetworkActorMessage {
            NetworkActorMessage::Command(NetworkActorCommand::ControlFiberChannel(
                ChannelCommandWithId {
                    channel_id,
                    command: ChannelCommand::AddTlc(
                        AddTlcCommand {
                            amount: params.amount,
                            payment_hash,
                            attempt_id: None,
                            expiry: params.expiry,
                            hash_algorithm,
                            onion_packet: None,
                            shared_secret: NO_SHARED_SECRET,
                            is_trampoline_hop: false,
                            previous_tlc: None,
                        },
                        rpc_reply,
                    ),
                },
            ))
        };
        handle_actor_call!(self.network_actor, message, params).map(|response| AddTlcResult {
            tlc_id: response.tlc_id,
        })
    }

    pub async fn remove_tlc(&self, params: RemoveTlcParams) -> Result<(), ErrorObjectOwned> {
        let channel_id = params.channel_id.into();
        let err_code = match &params.reason {
            RemoveTlcReason::RemoveTlcFail { error_code } => {
                let Ok(err) = TlcErrorCode::from_str(error_code) else {
                    return log_and_error!(params, format!("invalid error code: {}", error_code));
                };
                Some(err)
            }
            _ => None,
        };
        let reason = match &params.reason {
            RemoveTlcReason::RemoveTlcFulfill { payment_preimage } => {
                let preimage = (*payment_preimage).into();
                crate::fiber::types::RemoveTlcReason::RemoveTlcFulfill(RemoveTlcFulfill {
                    payment_preimage: preimage,
                })
            }
            RemoveTlcReason::RemoveTlcFail { .. } => {
                // TODO: maybe we should remove this PRC or move add_tlc and remove_tlc to `test` module?
                crate::fiber::types::RemoveTlcReason::RemoveTlcFail(TlcErrPacket::new(
                    TlcErr::new(err_code.expect("expect error code")),
                    // TODO: use tlc id to look up the shared secret in the store
                    &NO_SHARED_SECRET,
                ))
            }
        };
        let message = |rpc_reply| -> NetworkActorMessage {
            NetworkActorMessage::Command(NetworkActorCommand::ControlFiberChannel(
                ChannelCommandWithId {
                    channel_id,
                    command: ChannelCommand::RemoveTlc(
                        RemoveTlcCommand {
                            id: params.tlc_id,
                            reason,
                        },
                        rpc_reply,
                    ),
                },
            ))
        };

        handle_actor_call!(self.network_actor, message, params)
    }

    pub async fn submit_commitment_transaction(
        &self,
        params: SubmitCommitmentTransactionParams,
    ) -> Result<SubmitCommitmentTransactionResult, ErrorObjectOwned> {
        let channel_id = params.channel_id.into();
        if let Some(tx) = self
            .commitment_txs
            .read()
            .await
            .get(&(channel_id, params.commitment_number))
        {
            if let Err(err) = call_t!(
                &self.ckb_chain_actor,
                CkbChainMessage::SendTx,
                DEFAULT_CHAIN_ACTOR_TIMEOUT,
                tx.clone()
            )
            .unwrap()
            {
                Err(rpc_error(err.to_string()))
            } else {
                Ok(SubmitCommitmentTransactionResult {
                    tx_hash: JsonHash256(
                        tx.hash().as_slice().try_into().expect("Byte32 is 32 bytes"),
                    ),
                })
            }
        } else {
            Err(rpc_error("Commitment transaction not found".to_string()))
        }
    }

    pub async fn check_channel_shutdown(
        &self,
        params: CheckChannelShutdownParams,
    ) -> Result<(), ErrorObjectOwned> {
        let channel_id = params.channel_id.into();
        let message = |rpc_reply| {
            NetworkActorMessage::Command(NetworkActorCommand::CheckChannelShutdown(
                channel_id, rpc_reply,
            ))
        };

        handle_actor_call!(self.network_actor, message, params)
    }

    pub async fn sign_external_funding_tx(
        &self,
        params: SignExternalFundingTxParams,
    ) -> Result<SignExternalFundingTxResult, ErrorObjectOwned> {
        use ckb_sdk::{
            traits::{SecpCkbRawKeySigner, Signer},
            types::ScriptGroup,
            unlock::generate_message,
        };
        use ckb_types::{
            bytes::Bytes,
            packed::{self, WitnessArgs},
            prelude::{Builder, Entity, IntoTransactionView, Pack},
        };
        use secp256k1::SecretKey;
        use std::collections::hash_map::Entry;

        // Parse the private key
        let private_key_hex = params
            .private_key
            .strip_prefix("0x")
            .unwrap_or(&params.private_key);
        let private_key_bytes = hex::decode(private_key_hex)
            .map_err(|e| rpc_error(format!("invalid private key hex: {}", e)))?;
        if private_key_bytes.len() != 32 {
            return Err(rpc_error(format!(
                "invalid private key length: expected 32 bytes, got {}",
                private_key_bytes.len()
            )));
        }
        let secret_key = SecretKey::from_slice(&private_key_bytes)
            .map_err(|e| rpc_error(format!("invalid private key: {}", e)))?;

        // Convert the JSON transaction to a packed transaction
        let packed_tx: ckb_types::packed::Transaction = params.unsigned_funding_tx.clone().into();
        let tx_view = packed_tx.into_view();

        // Create signer for secp256k1 sighash
        let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![std::str::FromStr::from_str(
            hex::encode(secret_key.as_ref()).as_ref(),
        )
        .map_err(|e| rpc_error(format!("failed to create signer: {}", e)))?]);

        let pubkey_hash = blake160(
            secret_key
                .public_key(secp256k1::SECP256K1)
                .serialize()
                .as_ref(),
        );
        let ckb_client = crate::ckb::config::new_ckb_rpc_async_client(&self.ckb_rpc_url);

        // Resolve each input's previous output lock and keep only the secp sighash locks
        // owned by the provided private key. Inputs sharing the same lock script must be
        // signed as one script group.
        let mut signing_groups: Vec<ScriptGroup> = Vec::new();
        let mut group_index_by_lock: HashMap<Vec<u8>, usize> = HashMap::new();
        for (input_idx, input) in tx_view.inputs().into_iter().enumerate() {
            let previous_output = input.previous_output();
            let tx_hash: ckb_types::H256 = previous_output.tx_hash().unpack();
            let output_index: u32 = previous_output.index().unpack();
            let output_index = output_index as usize;
            let previous_tx = ckb_client
                .get_transaction(tx_hash.clone())
                .await
                .map_err(|e| rpc_error(format!("failed to fetch previous transaction: {}", e)))?;
            let previous_tx = previous_tx.and_then(|response| {
                response.transaction.map(|tx| match tx.inner {
                    ckb_jsonrpc_types::Either::Left(json) => {
                        let packed_tx: packed::Transaction = json.inner.into();
                        packed_tx.into_view()
                    }
                    ckb_jsonrpc_types::Either::Right(_) => {
                        panic!("bytes response format not used");
                    }
                })
            });
            let previous_tx = previous_tx.ok_or_else(|| {
                rpc_error(format!(
                    "previous transaction not found for input {}: {}",
                    input_idx, tx_hash
                ))
            })?;
            let previous_output = previous_tx.outputs().get(output_index).ok_or_else(|| {
                rpc_error(format!(
                    "previous output index {} out of bounds for input {}",
                    output_index, input_idx
                ))
            })?;
            let lock_script = previous_output.lock();
            if lock_script.args().raw_data().as_ref() != pubkey_hash.as_bytes() {
                continue;
            }

            let lock_script_key = lock_script.as_slice().to_vec();
            match group_index_by_lock.entry(lock_script_key) {
                Entry::Occupied(entry) => {
                    signing_groups[*entry.get()].input_indices.push(input_idx);
                }
                Entry::Vacant(entry) => {
                    let mut script_group = ScriptGroup::from_lock_script(&lock_script);
                    script_group.input_indices.push(input_idx);
                    let group_index = signing_groups.len();
                    signing_groups.push(script_group);
                    entry.insert(group_index);
                }
            }
        }

        if signing_groups.is_empty() {
            return Err(rpc_error(
                "no transaction inputs matched the provided private key".to_string(),
            ));
        }

        let mut witnesses: Vec<packed::Bytes> = tx_view.witnesses().into_iter().collect();
        for script_group in signing_groups {
            let input_idx = *script_group
                .input_indices
                .first()
                .expect("script group should contain at least one input");
            let zero_lock = Bytes::from(vec![0u8; 65]);
            let message = generate_message(&tx_view, &script_group, zero_lock)
                .map_err(|e| rpc_error(format!("failed to generate sighash message: {}", e)))?;

            let signature = signer
                .sign(pubkey_hash.as_bytes(), &message, true, &tx_view)
                .map_err(|e| rpc_error(format!("failed to sign message: {}", e)))?;

            while witnesses.len() <= input_idx {
                witnesses.push(Default::default());
            }

            let witness_data = witnesses[input_idx].raw_data();
            let witness: WitnessArgs = WitnessArgs::from_slice(&witness_data).unwrap_or_default();

            let updated_witness = witness.as_builder().lock(Some(signature).pack()).build();
            witnesses[input_idx] = updated_witness.as_bytes().pack();
        }

        // Build the signed transaction
        let signed_tx = tx_view
            .as_advanced_builder()
            .set_witnesses(witnesses)
            .build();

        // Convert back to JSON transaction
        let signed_funding_tx = ckb_jsonrpc_types::Transaction::from(signed_tx.data());

        Ok(SignExternalFundingTxResult { signed_funding_tx })
    }

    pub async fn set_fiber_message_intercept(
        &self,
        params: SetFiberMessageInterceptParams,
    ) -> Result<(), ErrorObjectOwned> {
        let intercept = FiberMessageIntercept {
            channel_id: params.channel_id.into(),
            suppress_outbound_revoke_and_ack: params.suppress_outbound_revoke_and_ack,
            capture_inbound: params.capture_inbound,
            inbound_capture_kinds: params.inbound_capture_kinds.clone(),
            inbound_drop_kinds: params.inbound_drop_kinds.clone(),
            outbound_drop_kinds: params.outbound_drop_kinds.clone(),
            outbound_hold_kinds: params.outbound_hold_kinds.clone(),
        };
        let message = |rpc_reply| {
            NetworkActorMessage::Command(NetworkActorCommand::SetFiberMessageIntercept(
                intercept, rpc_reply,
            ))
        };
        handle_actor_call!(self.network_actor, message, params)
    }

    pub async fn take_captured_fiber_messages(
        &self,
    ) -> Result<TakeCapturedFiberMessagesResult, ErrorObjectOwned> {
        let message = |rpc_reply| {
            NetworkActorMessage::Command(NetworkActorCommand::TakeCapturedFiberMessages(rpc_reply))
        };
        match call!(self.network_actor, message) {
            Ok(captured) => Ok(TakeCapturedFiberMessagesResult {
                messages: captured
                    .into_iter()
                    .map(captured_fiber_message_from)
                    .collect(),
            }),
            Err(e) => Err(rpc_error(e.to_string())),
        }
    }

    pub async fn deliver_captured_fiber_messages(
        &self,
        params: DeliverCapturedFiberMessagesParams,
    ) -> Result<DeliverCapturedFiberMessagesResult, ErrorObjectOwned> {
        let command = DeliverCapturedFiberMessagesCommand {
            count: params.count,
            kinds: params.kinds,
        };
        let message = |rpc_reply| {
            NetworkActorMessage::Command(NetworkActorCommand::DeliverCapturedFiberMessages(
                command, rpc_reply,
            ))
        };
        match call!(self.network_actor, message) {
            Ok(Ok(delivered)) => Ok(DeliverCapturedFiberMessagesResult { delivered }),
            Ok(Err(e)) => Err(rpc_error(e)),
            Err(e) => Err(rpc_error(e.to_string())),
        }
    }

    pub async fn take_held_outbound_fiber_messages(
        &self,
    ) -> Result<TakeCapturedFiberMessagesResult, ErrorObjectOwned> {
        let message = |rpc_reply| {
            NetworkActorMessage::Command(NetworkActorCommand::TakeHeldOutboundFiberMessages(
                rpc_reply,
            ))
        };
        match call!(self.network_actor, message) {
            Ok(held) => Ok(TakeCapturedFiberMessagesResult {
                messages: held
                    .into_iter()
                    .map(|message| {
                        captured_fiber_message_from(CapturedInboundFiberMessage {
                            peer: message.target,
                            message: message.message,
                        })
                    })
                    .collect(),
            }),
            Err(e) => Err(rpc_error(e.to_string())),
        }
    }

    pub async fn release_held_outbound_fiber_messages(
        &self,
        params: ReleaseHeldOutboundFiberMessagesParams,
    ) -> Result<ReleaseHeldOutboundFiberMessagesResult, ErrorObjectOwned> {
        let command = ReleaseHeldOutboundFiberMessagesCommand {
            count: params.count,
            kinds: params.kinds,
        };
        let message = |rpc_reply| {
            NetworkActorMessage::Command(NetworkActorCommand::ReleaseHeldOutboundFiberMessages(
                command, rpc_reply,
            ))
        };
        match call!(self.network_actor, message) {
            Ok(Ok(released)) => Ok(ReleaseHeldOutboundFiberMessagesResult { released }),
            Ok(Err(e)) => Err(rpc_error(e)),
            Err(e) => Err(rpc_error(e.to_string())),
        }
    }

    pub async fn send_raw_channel_message(
        &self,
        params: SendRawChannelMessageParams,
    ) -> Result<SendRawChannelMessageResult, ErrorObjectOwned> {
        let kind = match params.kind {
            fiber_json_types::RawChannelMessageKind::CommitmentSigned => {
                RawChannelMessageKind::CommitmentSigned
            }
            fiber_json_types::RawChannelMessageKind::Shutdown => RawChannelMessageKind::Shutdown,
            fiber_json_types::RawChannelMessageKind::AddTlc => RawChannelMessageKind::AddTlc,
            fiber_json_types::RawChannelMessageKind::RemoveTlc => RawChannelMessageKind::RemoveTlc,
            fiber_json_types::RawChannelMessageKind::ReestablishChannel => {
                RawChannelMessageKind::ReestablishChannel
            }
            fiber_json_types::RawChannelMessageKind::TxAbort => RawChannelMessageKind::TxAbort,
        };
        let abort_message = params.abort_message.as_deref().map(|value| {
            let hex = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .unwrap_or(value);
            hex::decode(hex).unwrap_or_else(|_| value.as_bytes().to_vec())
        });
        let command = SendRawChannelMessageCommand {
            channel_id: params.channel_id.into(),
            kind,
            nonce_commitment_number: params.nonce_commitment_number,
            close_script: params.close_script.map(Into::into),
            fee_rate: params.fee_rate,
            amount: params.amount,
            payment_hash: params.payment_hash.map(Into::into),
            expiry: params.expiry,
            tlc_id: params.tlc_id,
            remove_fail_error_code: params.remove_fail_error_code,
            local_commitment_number: params.local_commitment_number,
            remote_commitment_number: params.remote_commitment_number,
            abort_message,
        };
        let message = |rpc_reply| {
            NetworkActorMessage::Command(NetworkActorCommand::SendRawChannelMessage(
                command, rpc_reply,
            ))
        };
        match call!(self.network_actor, message) {
            Ok(Ok(result)) => Ok(SendRawChannelMessageResult {
                funding_tx_partial_signature: result
                    .funding_tx_partial_signature
                    .map(|s| hex_0x(&s.serialize())),
                next_commitment_nonce: result
                    .next_commitment_nonce
                    .as_ref()
                    .map(|n| hex_0x(&n.to_bytes())),
            }),
            Ok(Err(e)) => Err(rpc_error(e)),
            Err(e) => Err(rpc_error(e.to_string())),
        }
    }

    pub async fn get_channel_musig2_public(
        &self,
        params: GetChannelMusig2PublicParams,
    ) -> Result<GetChannelMusig2PublicResult, ErrorObjectOwned> {
        let channel_id = params.channel_id.into();
        let message = |rpc_reply| {
            NetworkActorMessage::Command(NetworkActorCommand::GetChannelMusig2Public(
                channel_id, rpc_reply,
            ))
        };
        match call!(self.network_actor, message) {
            Ok(Ok(info)) => Ok(GetChannelMusig2PublicResult {
                local_funding_pubkey: info.local_funding_pubkey.into(),
                remote_funding_pubkey: info.remote_funding_pubkey.into(),
                local_commitment_number: info.local_commitment_number,
                remote_commitment_number: info.remote_commitment_number,
                local_pubnonce: hex_0x(&info.local_pubnonce.to_bytes()),
                last_committed_remote_nonce: hex_0x(&info.last_committed_remote_nonce.to_bytes()),
                next_commitment_nonce: hex_0x(&info.next_commitment_nonce.to_bytes()),
                own_commitment_message: JsonHash256(info.own_commitment_message),
                peer_commitment_message: JsonHash256(info.peer_commitment_message),
                funding_outpoint: info.funding_outpoint.into(),
                local_first: info.local_first,
            }),
            Ok(Err(e)) => Err(rpc_error(e)),
            Err(e) => Err(rpc_error(e.to_string())),
        }
    }

    pub async fn build_shutdown_tx_message(
        &self,
        params: BuildShutdownTxMessageParams,
    ) -> Result<BuildShutdownTxMessageResult, ErrorObjectOwned> {
        let command = BuildShutdownTxMessageCommand {
            channel_id: params.channel_id.into(),
            local_close_script: params.local_close_script.into(),
            remote_close_script: params.remote_close_script.into(),
            local_fee_rate: params.local_fee_rate,
            remote_fee_rate: params.remote_fee_rate,
        };
        let message = |rpc_reply| {
            NetworkActorMessage::Command(NetworkActorCommand::BuildShutdownTxMessage(
                command, rpc_reply,
            ))
        };
        match call!(self.network_actor, message) {
            Ok(Ok(message)) => Ok(BuildShutdownTxMessageResult {
                message: JsonHash256(message),
            }),
            Ok(Err(e)) => Err(rpc_error(e)),
            Err(e) => Err(rpc_error(e.to_string())),
        }
    }
}

fn hex_0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn captured_fiber_message_from(captured: CapturedInboundFiberMessage) -> CapturedFiberMessage {
    let kind;
    let mut funding_tx_partial_signature = None;
    let mut closing_partial_signature = None;
    let mut next_commitment_nonce = None;
    let mut close_script = None;
    let mut fee_rate = None;
    let mut tlc_id = None;
    let mut payment_hash = None;
    let mut local_commitment_number = None;
    let mut remote_commitment_number = None;
    let channel_id = match &captured.message {
        FiberMessage::ChannelNormalOperation(message) => {
            Some(JsonHash256(message.get_channel_id().into()))
        }
        FiberMessage::ChannelInitialization(open) => Some(JsonHash256(open.channel_id.into())),
        _ => None,
    };
    match &captured.message {
        FiberMessage::ChannelNormalOperation(FiberChannelMessage::CommitmentSigned(cs)) => {
            kind = "CommitmentSigned".to_string();
            funding_tx_partial_signature =
                Some(hex_0x(&cs.funding_tx_partial_signature.serialize()));
            next_commitment_nonce = Some(hex_0x(&cs.next_commitment_nonce.to_bytes()));
        }
        FiberMessage::ChannelNormalOperation(FiberChannelMessage::ClosingSigned(cs)) => {
            kind = "ClosingSigned".to_string();
            closing_partial_signature = Some(hex_0x(&cs.partial_signature.serialize()));
        }
        FiberMessage::ChannelNormalOperation(FiberChannelMessage::Shutdown(shutdown)) => {
            kind = "Shutdown".to_string();
            close_script = Some(shutdown.close_script.clone().into());
            fee_rate = Some(shutdown.fee_rate.as_u64());
        }
        FiberMessage::ChannelNormalOperation(FiberChannelMessage::AddTlc(add)) => {
            kind = "AddTlc".to_string();
            tlc_id = Some(add.tlc_id);
            payment_hash = Some(JsonHash256(add.payment_hash.into()));
        }
        FiberMessage::ChannelNormalOperation(FiberChannelMessage::RemoveTlc(remove)) => {
            kind = "RemoveTlc".to_string();
            tlc_id = Some(remove.tlc_id);
        }
        FiberMessage::ChannelNormalOperation(FiberChannelMessage::ReestablishChannel(reest)) => {
            kind = "ReestablishChannel".to_string();
            local_commitment_number = Some(reest.local_commitment_number);
            remote_commitment_number = Some(reest.remote_commitment_number);
        }
        FiberMessage::ChannelNormalOperation(other) => {
            kind = other.to_string();
        }
        FiberMessage::ChannelInitialization(_) => {
            kind = "OpenChannel".to_string();
        }
        FiberMessage::Init(_) => {
            kind = "Init".to_string();
        }
    }
    CapturedFiberMessage {
        peer_pubkey: captured.peer.into(),
        channel_id,
        kind,
        payload: hex_0x(captured.message.clone().to_molecule_bytes().as_ref()),
        funding_tx_partial_signature,
        closing_partial_signature,
        next_commitment_nonce,
        close_script,
        fee_rate,
        tlc_id,
        payment_hash,
        local_commitment_number,
        remote_commitment_number,
    }
}
