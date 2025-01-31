// Copyright (C) 2020-2021 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

#![allow(clippy::collapsible_match)]

use core::convert::TryFrom;
use curv::{arithmetic::Converter, elliptic::curves::traits::ECScalar};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::SignatureRecid;
use sp_core::ecdsa;
use std::{collections::BTreeSet, convert::TryInto, fmt::Debug, marker::PhantomData, sync::Arc};

use codec::{Codec, Decode, Encode};
use futures::{future, FutureExt, StreamExt};
use log::{debug, error, info, trace, warn};
use parking_lot::Mutex;

use sc_client_api::{Backend, FinalityNotification, FinalityNotifications};
use sc_network_gossip::GossipEngine;

use beefy_primitives::{crypto::Signature, SignedCommitment, VersionedCommitment};

use sp_api::BlockId;
use sp_arithmetic::traits::AtLeast32Bit;
use sp_runtime::{
	generic::OpaqueDigestItemId,
	traits::{Block, Header, NumberFor},
	SaturatedConversion,
};

use beefy_primitives::{
	crypto::{AuthorityId, Public},
	BeefyApi, Commitment, ConsensusLog, MmrRootHash, ValidatorSet, BEEFY_ENGINE_ID, GENESIS_AUTHORITY_SET_ID,
};

use crate::{
	dkg::{webb_topic, DKGMessage, DKGState, MultiPartyECDSARounds},
	error::{self},
	gossip::GossipValidator,
	keystore::BeefyKeystore,
	metric_inc, metric_set,
	metrics::Metrics,
	notification, Client,
};

pub(crate) struct WorkerParams<B, BE, C>
where
	B: Block,
{
	pub client: Arc<C>,
	pub backend: Arc<BE>,
	pub key_store: BeefyKeystore,
	pub signed_commitment_sender: notification::BeefySignedCommitmentSender<B>,
	pub gossip_engine: GossipEngine<B>,
	pub gossip_validator: Arc<GossipValidator<B>>,
	pub min_block_delta: u32,
	pub metrics: Option<Metrics>,
	pub dkg_state: DKGState<(MmrRootHash, NumberFor<B>), Commitment<NumberFor<B>, MmrRootHash>>,
}

/// A BEEFY worker plays the BEEFY protocol
pub(crate) struct BeefyWorker<B, C, BE>
where
	B: Block,
	BE: Backend<B>,
	C: Client<B, BE>,
{
	client: Arc<C>,
	backend: Arc<BE>,
	key_store: BeefyKeystore,
	signed_commitment_sender: notification::BeefySignedCommitmentSender<B>,
	gossip_engine: Arc<Mutex<GossipEngine<B>>>,
	gossip_validator: Arc<GossipValidator<B>>,
	/// Min delta in block numbers between two blocks, BEEFY should vote on
	min_block_delta: u32,
	metrics: Option<Metrics>,
	rounds: MultiPartyECDSARounds<(MmrRootHash, NumberFor<B>), Commitment<NumberFor<B>, MmrRootHash>>,
	finality_notifications: FinalityNotifications<B>,
	/// Best block we received a GRANDPA notification for
	best_grandpa_block: NumberFor<B>,
	/// Best block a BEEFY voting round has been concluded for
	best_beefy_block: Option<NumberFor<B>>,
	/// Current validator set id
	current_validator_set: ValidatorSet<Public>,
	/// Validator set id for the last signed commitment
	last_signed_id: u64,
	// keep rustc happy
	_backend: PhantomData<BE>,
	// dkg state
	dkg_state: DKGState<(MmrRootHash, NumberFor<B>), Commitment<NumberFor<B>, MmrRootHash>>,
}

impl<B, C, BE> BeefyWorker<B, C, BE>
where
	B: Block + Codec,
	BE: Backend<B>,
	C: Client<B, BE>,
	C::Api: BeefyApi<B>,
{
	/// Return a new BEEFY worker instance.
	///
	/// Note that a BEEFY worker is only fully functional if a corresponding
	/// BEEFY pallet has been deployed on-chain.
	///
	/// The BEEFY pallet is needed in order to keep track of the BEEFY authority set.
	pub(crate) fn new(worker_params: WorkerParams<B, BE, C>) -> Self {
		let WorkerParams {
			client,
			backend,
			key_store,
			signed_commitment_sender,
			gossip_engine,
			gossip_validator,
			min_block_delta,
			metrics,
			dkg_state,
		} = worker_params;

		BeefyWorker {
			client: client.clone(),
			backend,
			key_store,
			signed_commitment_sender,
			gossip_engine: Arc::new(Mutex::new(gossip_engine)),
			gossip_validator,
			min_block_delta,
			metrics,
			rounds: MultiPartyECDSARounds::new(0, 0, 1),
			finality_notifications: client.finality_notification_stream(),
			best_grandpa_block: client.info().finalized_number,
			best_beefy_block: None,
			current_validator_set: ValidatorSet::empty(),
			last_signed_id: 0,
			dkg_state,
			_backend: PhantomData,
		}
	}
}

impl<B, C, BE> BeefyWorker<B, C, BE>
where
	B: Block,
	BE: Backend<B>,
	C: Client<B, BE>,
	C::Api: BeefyApi<B>,
{
	fn get_authority_index(&self, header: &B::Header) -> Option<usize> {
		let new = if let Some(new) = find_authorities_change::<B>(header) {
			Some(new)
		} else {
			let at = BlockId::hash(header.hash());
			self.client.runtime_api().validator_set(&at).ok()
		};

		trace!(target: "webb", "🕸️  active validator set: {:?}", new);

		let set = new.unwrap_or_else(|| panic!("Help"));
		let public = self
			.key_store
			.authority_id(&self.key_store.public_keys().unwrap())
			.unwrap_or_else(|| panic!("Halp"));
		for i in 0..set.validators.len() {
			if set.validators[i] == public {
				return Some(i);
			}
		}

		return None;
	}

	fn get_threshold(&self, header: &B::Header) -> Option<u16> {
		let at = BlockId::hash(header.hash());
		return self.client.runtime_api().signature_threshold(&at).ok();
	}

	/// Return `true`, if we should vote on block `number`
	fn should_vote_on(&self, number: NumberFor<B>) -> bool {
		let best_beefy_block = if let Some(block) = self.best_beefy_block {
			block
		} else {
			debug!(target: "beefy", "🥩 Missing best BEEFY block - won't vote for: {:?}", number);
			return false;
		};

		let target = vote_target(self.best_grandpa_block, best_beefy_block, self.min_block_delta);

		trace!(target: "beefy", "🥩 should_vote_on: #{:?}, next_block_to_vote_on: #{:?}", number, target);

		metric_set!(self, beefy_should_vote_on, target);

		number == target
	}

	/// Return the current active validator set at header `header`.
	///
	/// Note that the validator set could be `None`. This is the case if we don't find
	/// a BEEFY authority set change and we can't fetch the authority set from the
	/// BEEFY on-chain state.
	///
	/// Such a failure is usually an indication that the BEEFY pallet has not been deployed (yet).
	fn validator_set(&self, header: &B::Header) -> Option<ValidatorSet<Public>> {
		let new = if let Some(new) = find_authorities_change::<B>(header) {
			Some(new)
		} else {
			let at = BlockId::hash(header.hash());
			self.client.runtime_api().validator_set(&at).ok()
		};

		trace!(target: "beefy", "🥩 active validator set: {:?}", new);

		new
	}

	/// Verify `active` validator set for `block` against the key store
	///
	/// The critical case is, if we do have a public key in the key store which is not
	/// part of the active validator set.
	///
	/// Note that for a non-authority node there will be no keystore, and we will
	/// return an error and don't check. The error can usually be ignored.
	fn verify_validator_set(&self, block: &NumberFor<B>, mut active: ValidatorSet<Public>) -> Result<(), error::Error> {
		let active: BTreeSet<Public> = active.validators.drain(..).collect();

		let store: BTreeSet<Public> = self.key_store.public_keys()?.drain(..).collect();

		let missing: Vec<_> = store.difference(&active).cloned().collect();

		if !missing.is_empty() {
			debug!(target: "beefy", "🥩 for block {:?} public key missing in validator set: {:?}", block, missing);
		}

		Ok(())
	}

	fn handle_finality_notification(&mut self, notification: FinalityNotification<B>) {
		trace!(target: "beefy", "🥩 Finality notification: {:?}", notification);

		// update best GRANDPA finalized block we have seen
		self.best_grandpa_block = *notification.header.number();

		if let Some(active) = self.validator_set(&notification.header) {
			// Authority set change or genesis set id triggers new voting rounds
			//
			// TODO: (adoerr) Enacting a new authority set will also implicitly 'conclude'
			// the currently active BEEFY voting round by starting a new one. This is
			// temporary and needs to be replaced by proper round life cycle handling.
			if active.id != self.current_validator_set.id
				|| (active.id == GENESIS_AUTHORITY_SET_ID && self.best_beefy_block.is_none())
			{
				debug!(target: "beefy", "🥩 New active validator set id: {:?}", active);
				metric_set!(self, beefy_validator_set_id, active.id);

				// BEEFY should produce a signed commitment for each session
				if active.id != self.last_signed_id + 1 && active.id != GENESIS_AUTHORITY_SET_ID {
					metric_inc!(self, beefy_skipped_sessions);
				}

				// verify the new validator set
				let _ = self.verify_validator_set(notification.header.number(), active.clone());
				// Setting new validator set id as curent
				self.current_validator_set = active.clone();

				debug!(target: "beefy", "🥩 New Rounds for id: {:?}", active.id);

				self.best_beefy_block = Some(*notification.header.number());

				// this metric is kind of 'fake'. Best BEEFY block should only be updated once we have a
				// signed commitment for the block. Remove once the above TODO is done.
				metric_set!(self, beefy_best_block, *notification.header.number());

				// Setting up new DKG
				let party_inx = self.get_authority_index(&notification.header).unwrap() + 1;
				let thresh = self.get_threshold(&notification.header).unwrap();
				let n = active.validators.len();

				if let Some(dkg) = self.dkg_state.curr_dkg.take() {
					self.dkg_state.past_dkg = Some(dkg);
				}

				self.rounds =
					MultiPartyECDSARounds::new(u16::try_from(party_inx).unwrap(), thresh, u16::try_from(n).unwrap());

				match self.rounds.start_keygen(active.clone().id) {
					Ok(()) => info!(target: "webb", "Keygen started successfully"),
					Err(err) => error!("Error starting keygen {}", err),
				}

				self.send_outgoing_dkg_messages();
				self.dkg_state.is_epoch_over = !self.dkg_state.is_epoch_over;
			} else {
				// if the DKG has not been prepared / terminated, continue preparing it
				if !self.dkg_state.accepted {
					self.send_outgoing_dkg_messages();
				}
			}
		}

		if self.should_vote_on(*notification.header.number()) {
			if let Some(id) = self
				.key_store
				.authority_id(self.current_validator_set.validators.as_slice())
			{
				debug!(target: "beefy", "🥩 Local authority id: {:?}", id);
				id
			} else {
				debug!(target: "beefy", "🥩 Missing validator id - can't vote for: {:?}", notification.header.hash());
				return;
			};

			let mmr_root = if let Some(hash) = find_mmr_root_digest::<B, Public>(&notification.header) {
				hash
			} else {
				warn!(target: "beefy", "🥩 No MMR root digest found for: {:?}", notification.header.hash());
				return;
			};
			let block_number = notification.header.number().clone();

			let commitment = Commitment {
				payload: mmr_root.clone(),
				block_number: block_number.clone(),
				validator_set_id: self.current_validator_set.id.clone(),
			};

			trace!(target: "webb", "🕸️  Created commitment");
			if self.rounds.is_ready_to_vote() {
				trace!(target: "webb", "🕸️  Signing commitment");

				self.rounds.vote((mmr_root, block_number), commitment).unwrap();

				self.send_outgoing_dkg_messages();
			} else {
				debug!(target: "webb", "Not ready to sign, skipping")
			}
		}
	}

	fn convert_signature(&mut self, sig_recid: &SignatureRecid) -> Option<Signature> {
		let r = sig_recid.r.to_big_int().to_bytes();
		let s = sig_recid.s.to_big_int().to_bytes();
		let v = sig_recid.recid;

		let mut sig_vec: Vec<u8> = Vec::new();

		for _ in 0..(32 - r.len()) {
			sig_vec.extend(&[0]);
		}
		sig_vec.extend_from_slice(&r);

		for _ in 0..(32 - s.len()) {
			sig_vec.extend(&[0]);
		}
		sig_vec.extend_from_slice(&s);

		sig_vec.extend(&[v]);

		if 65 != sig_vec.len() {
			warn!(target: "webb", "🕸️  Invalid signature len: {}, expected 65", sig_vec.len());
			return None;
		}

		let mut dkg_sig_arr: [u8; 65] = [0; 65];
		dkg_sig_arr.copy_from_slice(&sig_vec[0..65]);

		return match ecdsa::Signature(dkg_sig_arr).try_into() {
			Ok(sig) => {
				debug!(target: "webb", "🕸️  Converted signature {:?}", &sig);
				Some(sig)
			}
			Err(err) => {
				warn!(target: "webb", "🕸️  Error converting signature {:?}", err);
				None
			}
		};
	}

	fn process_finished_rounds(&mut self) {
		for finished_round in self.rounds.get_finished_rounds() {
			// id is stored for skipped session metric calculation
			self.last_signed_id = self.current_validator_set.id;

			let round_key = finished_round.key;
			let sig_recid: SignatureRecid = bincode::deserialize(&finished_round.signature).unwrap();
			let signature = self.convert_signature(&sig_recid);

			let mut signatures: Vec<Option<Signature>> = vec![];
			if signature.is_some() {
				signatures.push(signature);
			}

			let signed_commitment = SignedCommitment {
				commitment: finished_round.payload.clone(),
				signatures,
			};

			info!(target: "webb", "🕸️  Round #{} concluded, committed: {:?}.", round_key.1, &signed_commitment);

			if self
				.backend
				.append_justification(
					BlockId::Number(round_key.1),
					(
						BEEFY_ENGINE_ID,
						VersionedCommitment::V1(signed_commitment.clone()).encode(),
					),
				)
				.is_err()
			{
				// just a trace, because until the round lifecycle is improved, we will
				// conclude certain rounds multiple times.
				trace!(target: "beefy", "🥩 Failed to append justification: {:?}", signed_commitment);
			}

			self.signed_commitment_sender.notify(signed_commitment);

			if let Some(best) = self.best_beefy_block {
				if round_key.1 > best {
					self.best_beefy_block = Some(round_key.1);
				}
			} else {
				self.best_beefy_block = Some(round_key.1);
			}

			metric_set!(self, beefy_best_block, round_key.1);
		}
	}

	fn send_outgoing_dkg_messages(&mut self) {
		debug!(target: "webb", "🕸️  Try sending DKG messages");
		let authority_id = if let Some(id) = self
			.key_store
			.authority_id(self.current_validator_set.validators.as_slice())
		{
			debug!(target: "webb", "🕸️  Local authority id: {:?}", id);
			id
		} else {
			panic!("error");
		};

		self.rounds.proceed();

		// TODO: run this in a different place, tied to certain number of blocks probably
		if self.rounds.is_offline_ready() {
			// TODO: use deterministic random signers set
			let signer_set_id = self.current_validator_set.id;
			let s_l = (1..=self.rounds.dkg_params().2).collect();
			match self.rounds.reset_signers(signer_set_id, s_l) {
				Ok(()) => info!(target: "webb", "🕸️  Reset signers"),
				Err(err) => error!("Error resetting signers {}", err),
			}
		}

		for message in self.rounds.get_outgoing_messages() {
			let dkg_message = DKGMessage {
				id: authority_id.clone(),
				payload: message,
			};
			let encoded_dkg_message = dkg_message.encode();
			debug!(
				target: "webb",
				"🕸️  DKG Message: {:?}, encoded: {:?}",
				dkg_message,
				encoded_dkg_message
			);

			self.gossip_engine
				.lock()
				.gossip_message(webb_topic::<B>(), encoded_dkg_message.clone(), true);
			trace!(target: "webb", "🕸️  Sent DKG Message {:?}", encoded_dkg_message);
		}
	}

	fn process_incoming_dkg_message(&mut self, dkg_msg: DKGMessage<Public, (MmrRootHash, NumberFor<B>)>) {
		debug!(target: "webb", "🕸️  Process DKG message {}", &dkg_msg);

		match self.rounds.handle_incoming(dkg_msg.payload) {
			Ok(()) => (),
			Err(err) => debug!(target: "webb", "🕸️  Error while handling DKG message {:?}", err),
		}
		self.send_outgoing_dkg_messages();

		if self.rounds.is_ready_to_vote() {
			debug!(target: "webb", "🕸️  DKG is ready to sign");
			self.dkg_state.accepted = true;
		}

		self.process_finished_rounds();
	}

	pub(crate) async fn run(mut self) {
		let mut webb_dkg = Box::pin(self.gossip_engine.lock().messages_for(webb_topic::<B>()).filter_map(
			|notification| async move {
				// debug!(target: "webb", "🕸️  Got message: {:?}", notification);

				DKGMessage::<Public, (MmrRootHash, NumberFor<B>)>::decode(&mut &notification.message[..]).ok()
			},
		));

		loop {
			let engine = self.gossip_engine.clone();
			let gossip_engine = future::poll_fn(|cx| engine.lock().poll_unpin(cx));

			futures::select! {
				notification = self.finality_notifications.next().fuse() => {
					if let Some(notification) = notification {
						self.handle_finality_notification(notification);
					} else {
						return;
					}
				},
				dkg_msg = webb_dkg.next().fuse() => {
					if let Some(dkg_msg) = dkg_msg {
						self.process_incoming_dkg_message(dkg_msg);
					} else {
						return;
					}
				},
				_ = gossip_engine.fuse() => {
					error!(target: "beefy", "🥩 Gossip engine has terminated.");
					return;
				}
			}
		}
	}
}

/// Extract the MMR root hash from a digest in the given header, if it exists.
fn find_mmr_root_digest<B, Id>(header: &B::Header) -> Option<MmrRootHash>
where
	B: Block,
	Id: Codec,
{
	header.digest().logs().iter().find_map(|log| {
		match log.try_to::<ConsensusLog<Id>>(OpaqueDigestItemId::Consensus(&BEEFY_ENGINE_ID)) {
			Some(ConsensusLog::MmrRoot(root)) => Some(root),
			_ => None,
		}
	})
}

/// Scan the `header` digest log for a BEEFY validator set change. Return either the new
/// validator set or `None` in case no validator set change has been signaled.
fn find_authorities_change<B>(header: &B::Header) -> Option<ValidatorSet<AuthorityId>>
where
	B: Block,
{
	let id = OpaqueDigestItemId::Consensus(&BEEFY_ENGINE_ID);

	let filter = |log: ConsensusLog<AuthorityId>| match log {
		ConsensusLog::AuthoritiesChange(validator_set) => Some(validator_set),
		_ => None,
	};

	header.digest().convert_first(|l| l.try_to(id).and_then(filter))
}

/// Calculate next block number to vote on
fn vote_target<N>(best_grandpa: N, best_beefy: N, min_delta: u32) -> N
where
	N: AtLeast32Bit + Copy + Debug,
{
	let diff = best_grandpa.saturating_sub(best_beefy);
	let diff = diff.saturated_into::<u32>();
	let target = best_beefy + min_delta.max(diff.next_power_of_two()).into();

	trace!(
		target: "beefy",
		"🥩 vote target - diff: {:?}, next_power_of_two: {:?}, target block: #{:?}",
		diff,
		diff.next_power_of_two(),
		target,
	);

	target
}

#[cfg(test)]
mod tests {
	use super::vote_target;

	#[test]
	fn vote_on_min_block_delta() {
		let t = vote_target(1u32, 0, 4);
		assert_eq!(4, t);
		let t = vote_target(2u32, 0, 4);
		assert_eq!(4, t);
		let t = vote_target(3u32, 0, 4);
		assert_eq!(4, t);
		let t = vote_target(4u32, 0, 4);
		assert_eq!(4, t);

		let t = vote_target(4u32, 4, 4);
		assert_eq!(8, t);

		let t = vote_target(10u32, 10, 4);
		assert_eq!(14, t);
		let t = vote_target(11u32, 10, 4);
		assert_eq!(14, t);
		let t = vote_target(12u32, 10, 4);
		assert_eq!(14, t);
		let t = vote_target(13u32, 10, 4);
		assert_eq!(14, t);

		let t = vote_target(10u32, 10, 8);
		assert_eq!(18, t);
		let t = vote_target(11u32, 10, 8);
		assert_eq!(18, t);
		let t = vote_target(12u32, 10, 8);
		assert_eq!(18, t);
		let t = vote_target(13u32, 10, 8);
		assert_eq!(18, t);
	}

	#[test]
	fn vote_on_power_of_two() {
		let t = vote_target(1008u32, 1000, 4);
		assert_eq!(1008, t);

		let t = vote_target(1016u32, 1000, 4);
		assert_eq!(1016, t);

		let t = vote_target(1032u32, 1000, 4);
		assert_eq!(1032, t);

		let t = vote_target(1064u32, 1000, 4);
		assert_eq!(1064, t);

		let t = vote_target(1128u32, 1000, 4);
		assert_eq!(1128, t);

		let t = vote_target(1256u32, 1000, 4);
		assert_eq!(1256, t);

		let t = vote_target(1512u32, 1000, 4);
		assert_eq!(1512, t);

		let t = vote_target(1024u32, 0, 4);
		assert_eq!(1024, t);
	}

	#[test]
	fn vote_on_target_block() {
		let t = vote_target(1008u32, 1002, 4);
		assert_eq!(1010, t);
		let t = vote_target(1010u32, 1002, 4);
		assert_eq!(1010, t);

		let t = vote_target(1016u32, 1006, 4);
		assert_eq!(1022, t);
		let t = vote_target(1022u32, 1006, 4);
		assert_eq!(1022, t);

		let t = vote_target(1032u32, 1012, 4);
		assert_eq!(1044, t);
		let t = vote_target(1044u32, 1012, 4);
		assert_eq!(1044, t);

		let t = vote_target(1064u32, 1014, 4);
		assert_eq!(1078, t);
		let t = vote_target(1078u32, 1014, 4);
		assert_eq!(1078, t);

		let t = vote_target(1128u32, 1008, 4);
		assert_eq!(1136, t);
		let t = vote_target(1136u32, 1008, 4);
		assert_eq!(1136, t);
	}
}
