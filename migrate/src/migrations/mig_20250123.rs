use fiber::{store::migration::Migration, Error};
use indicatif::ProgressBar;
use std::{collections::HashSet, sync::Arc};
use tracing::info;

const MIGRATION_DB_VERSION: &str = "20250123051223";

pub use fiber_v031::fiber::channel::ChannelActorState as ChannelActorStateV031;
pub use fiber_v031::fiber::channel::RetryableTlcOperation as RetryableTlcOperationV031;
pub use fiber_v031::fiber::channel::{
    ChannelTlcInfo as ChannelTlcInfoV031, PendingTlcs as PendingTlcsV031, TlcInfo as TlcInfoV031,
    TlcState as TlcStateV031,
};

use crate::util::convert;
pub use fiber_v040::fiber::channel::ChannelActorState as ChannelActorStateV040;
pub use fiber_v040::fiber::channel::{
    ChannelTlcInfo as ChannelTlcInfoV040, PendingTlcs as PendingTlcsV040,
    PublicChannelInfo as PublicChannelInfoV040, RetryableTlcOperation as RetryableTlcOperationV040,
    TlcInfo as TlcInfoV040, TlcState as TlcStateV040,
};

pub struct MigrationObj {
    version: String,
}

impl MigrationObj {
    pub fn new() -> Self {
        Self {
            version: MIGRATION_DB_VERSION.to_string(),
        }
    }
}

fn convert_tlc_info(old: TlcInfoV031) -> TlcInfoV040 {
    TlcInfoV040 {
        channel_id: convert(old.channel_id),
        status: convert(old.status),
        tlc_id: convert(old.tlc_id),
        amount: convert(old.amount),
        payment_hash: convert(old.payment_hash),
        expiry: convert(old.expiry),
        hash_algorithm: convert(old.hash_algorithm),
        onion_packet: convert(old.onion_packet),
        shared_secret: convert(old.shared_secret),
        created_at: convert(old.created_at),
        removed_reason: convert(old.removed_reason),
        previous_tlc: convert(old.previous_tlc),
        // new field in v040
        removed_confirmed_at: None,
    }
}

fn convert_pending_tlcs(old: PendingTlcsV031) -> PendingTlcsV040 {
    PendingTlcsV040 {
        tlcs: old
            .tlcs
            .into_iter()
            .map(|tlc| (convert_tlc_info(tlc)))
            .collect(),
        next_tlc_id: convert(old.next_tlc_id),
    }
}

fn convert_retryable_tlc_operations(
    old: Vec<RetryableTlcOperationV031>,
    old_tlc_state: &TlcStateV031,
) -> Vec<RetryableTlcOperationV040> {
    old.into_iter()
        .map(|op| convert_retryable_op(op, old_tlc_state))
        .collect()
}

fn convert_retryable_op(
    old: RetryableTlcOperationV031,
    old_tlc_state: &TlcStateV031,
) -> RetryableTlcOperationV040 {
    match old {
        RetryableTlcOperationV031::RemoveTlc(tlc_id, reason) => {
            RetryableTlcOperationV040::RemoveTlc(convert(tlc_id), convert(reason))
        }
        RetryableTlcOperationV031::RelayRemoveTlc(channel_id, tlc_id, reason) => {
            RetryableTlcOperationV040::RelayRemoveTlc(
                convert(channel_id),
                convert(tlc_id),
                convert(reason),
            )
        }
        RetryableTlcOperationV031::ForwardTlc(channel_id, tlc_id, onion_packet, is_retry) => {
            let received_amount = old_tlc_state
                .get(&tlc_id)
                .expect("tlc info not found")
                .amount;
            let forward_amount = onion_packet.current.amount;
            // Next forwarding channel will get the forward_fee and check if it's enough.
            let forward_fee = received_amount.saturating_sub(forward_amount);
            RetryableTlcOperationV040::ForwardTlc(
                convert(channel_id),
                convert(tlc_id),
                convert(onion_packet),
                forward_fee,
                is_retry,
            )
        }
    }
}

impl Migration for MigrationObj {
    fn migrate<'a>(
        &self,
        db: &'a fiber::store::Store,
        _pb: Arc<dyn Fn(u64) -> ProgressBar + Send + Sync>,
    ) -> Result<&'a fiber::store::Store, Error> {
        info!(
            "MigrationObj::migrate to {} ...........",
            MIGRATION_DB_VERSION
        );

        const CHANNEL_ACTOR_STATE_PREFIX: u8 = 0;
        let prefix = vec![CHANNEL_ACTOR_STATE_PREFIX];

        for (k, v) in db
            .prefix_iterator(prefix.clone().as_slice())
            .take_while(move |(col_key, _)| col_key.starts_with(prefix.as_slice()))
        {
            if let Ok(_) = bincode::deserialize::<ChannelActorStateV040>(&v) {
                // if we can deserialize the data correctly with new version, just skip it.
                continue;
            }

            let old_channel_state: ChannelActorStateV031 =
                bincode::deserialize(&v).expect("deserialize to old channel state");

            let old_tlc_state = old_channel_state.tlc_state.clone();
            let new_tlc_state = TlcStateV040 {
                offered_tlcs: convert_pending_tlcs(old_tlc_state.offered_tlcs),
                received_tlcs: convert_pending_tlcs(old_tlc_state.received_tlcs),
                // changed field in v040
                retryable_tlc_operations: convert_retryable_tlc_operations(
                    old_tlc_state.retryable_tlc_operations,
                    &old_channel_state.tlc_state,
                ),
                applied_add_tlcs: convert(old_tlc_state.applied_add_tlcs),
                // new field in v040
                applied_remove_tlcs: HashSet::new(),
                waiting_ack: old_tlc_state.waiting_ack,
            };

            let new_channel_state = ChannelActorStateV040 {
                state: convert(old_channel_state.state),
                local_pubkey: convert(old_channel_state.local_pubkey),
                remote_pubkey: convert(old_channel_state.remote_pubkey),
                id: convert(old_channel_state.id),
                funding_tx: old_channel_state.funding_tx,
                funding_tx_confirmed_at: old_channel_state.funding_tx_confirmed_at,
                funding_udt_type_script: old_channel_state.funding_udt_type_script,
                is_acceptor: old_channel_state.is_acceptor,
                to_local_amount: old_channel_state.to_local_amount,
                to_remote_amount: old_channel_state.to_remote_amount,
                local_reserved_ckb_amount: old_channel_state.local_reserved_ckb_amount,
                remote_reserved_ckb_amount: old_channel_state.remote_reserved_ckb_amount,
                commitment_fee_rate: old_channel_state.commitment_fee_rate,
                commitment_delay_epoch: old_channel_state.commitment_delay_epoch,
                funding_fee_rate: old_channel_state.funding_fee_rate,
                signer: convert(old_channel_state.signer),
                local_channel_public_keys: convert(old_channel_state.local_channel_public_keys),
                commitment_numbers: convert(old_channel_state.commitment_numbers),
                local_constraints: convert(old_channel_state.local_constraints),
                remote_constraints: convert(old_channel_state.remote_constraints),
                tlc_state: new_tlc_state,
                remote_shutdown_script: old_channel_state.remote_shutdown_script,
                local_shutdown_script: old_channel_state.local_shutdown_script,
                last_commitment_signed_remote_nonce: old_channel_state
                    .last_commitment_signed_remote_nonce,
                last_revoke_and_ack_remote_nonce: old_channel_state
                    .last_revoke_and_ack_remote_nonce,
                last_committed_remote_nonce: old_channel_state.last_committed_remote_nonce,
                latest_commitment_transaction: old_channel_state.latest_commitment_transaction,
                remote_commitment_points: convert(old_channel_state.remote_commitment_points),
                remote_channel_public_keys: convert(old_channel_state.remote_channel_public_keys),
                local_shutdown_info: convert(old_channel_state.local_shutdown_info),
                remote_shutdown_info: convert(old_channel_state.remote_shutdown_info),
                reestablishing: old_channel_state.reestablishing,
                created_at: old_channel_state.created_at,
                public_channel_info: convert(old_channel_state.public_channel_info),
                local_tlc_info: convert(old_channel_state.local_tlc_info),
                remote_tlc_info: convert(old_channel_state.remote_tlc_info),
            };

            let new_channel_state_bytes =
                bincode::serialize(&new_channel_state).expect("serialize to new channel state");

            db.put(k, new_channel_state_bytes);
        }
        Ok(db)
    }

    fn version(&self) -> &str {
        &self.version
    }
}
