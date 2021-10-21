use beefy_primitives::Commitment;
use bincode;
use codec::{Decode, Encode};
use curv::{
	arithmetic::Converter,
	cryptographic_primitives::hashing::{hash_sha256::HSha256, traits::Hash as CurvHash},
	BigInt,
};
use log::{debug, error, info, trace, warn};
use round_based::{IsCritical, Msg, StateMachine};
use serde::{Deserialize, Serialize};
use sp_keystore::{Error, SyncCryptoStore};
use sp_runtime::traits::{Block, Hash, Header};
use std::{collections::BTreeMap, fmt, sync::Arc};

pub use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::{
	party_i::*,
	state_machine::{keygen::*, sign::*},
};

#[derive(Debug, Decode, Encode)]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub enum DKGType {
	MultiPartyECDSA,
	Vote,
}

/// Gossip engine webb messages topic
pub(crate) fn webb_topic<B: Block>() -> B::Hash
where
	B: Block,
{
	<<B::Header as Header>::Hashing as Hash>::hash(b"webb")
}

/// A typedef for keygen set id
pub type KeygenSetId = u64;
/// A typedef for signer set id
pub type SignerSetId = u64;

/// WEBB DKG (distributed key generation) message.
///
/// A vote message is a direct vote created by a WEBB node on every voting round
/// and is gossiped to its peers.
#[derive(Debug, Decode, Encode)]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub struct DKGMessage<Public, Key> {
	/// Node authority id
	pub id: Public,
	/// DKG message contents
	pub payload: DKGMsgPayload<Key>,
}

impl<P, K> fmt::Display for DKGMessage<P, K> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let label = match self.payload {
			DKGMsgPayload::Keygen(_) => "Keygen",
			DKGMsgPayload::Offline(_) => "Offline",
			DKGMsgPayload::Vote(_) => "Vote",
		};
		write!(f, "DKGMessage of type {}", label)
	}
}

#[derive(Debug, Decode, Encode)]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub enum DKGMsgPayload<Key> {
	Keygen(DKGKeygenMessage),
	Offline(DKGOfflineMessage),
	Vote(DKGVoteMessage<Key>),
}

#[derive(Debug, Decode, Encode)]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub struct DKGKeygenMessage {
	/// Keygen set epoch id
	pub keygen_set_id: KeygenSetId,
	/// Node signature
	pub keygen_msg: Vec<u8>,
}

#[derive(Debug, Decode, Encode)]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub struct DKGOfflineMessage {
	/// Signer set epoch id
	pub signer_set_id: SignerSetId,
	/// Node signature
	pub offline_msg: Vec<u8>,
}

#[derive(Debug, Decode, Encode)]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub struct DKGVoteMessage<Key> {
	/// Key for the vote signature created for
	pub round_key: Key,
	/// Node signature
	pub partial_signature: Vec<u8>,
}

#[derive(Clone, Debug, Decode, Encode)]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub struct DKGSignedPayload<Key, Payload> {
	/// Payload key
	pub key: Key,
	/// The payload signatures are collected for.
	pub payload: Payload,
	/// Signature for the payload
	/// SignatureRecid serialized as Vec<u8>, since SignatureRecid does not support codec
	pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Decode, Encode)]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub struct DKGSignedCommitment<TBlockNumber, TPayload> {
	/// The commitment signatures are collected for.
	pub commitment: Commitment<TBlockNumber, TPayload>,
	/// GRANDPA validators' signature for the commitment.
	pub signature: Vec<u8>,
}

pub struct DKGState<K, P> {
	pub accepted: bool,
	pub is_epoch_over: bool,
	pub curr_dkg: Option<MultiPartyECDSARounds<K, P>>,
	pub past_dkg: Option<MultiPartyECDSARounds<K, P>>,
}

/// Multi party ECDSA trait for the keystore.
pub trait MultiPartyECDSAKeyStore: SyncCryptoStore {
	/// Generate keys for a new participant.
	fn generate(&self, index: usize) -> Result<Keys, Error>;
	/// Refresh the keys for a participant.
	fn refresh(&self, index: usize) -> Result<Keys, Error> {
		self.generate(index)
	}
}

/// A pointer to a keystore.
pub type MultiPartyCryptoStorePtr = Arc<dyn MultiPartyECDSAKeyStore>;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
enum Stage {
	KeygenReady,
	Keygen,
	OfflineReady,
	Offline,
	ManualReady,
}

impl Stage {
	fn get_next(self) -> Stage {
		match self {
			Stage::KeygenReady => Stage::Keygen,
			Stage::Keygen => Stage::OfflineReady,
			Stage::OfflineReady => Stage::Offline,
			Stage::Offline => Stage::ManualReady,
			Stage::ManualReady => Stage::ManualReady,
		}
	}
}

pub struct MultiPartyECDSARounds<SignPayloadKey, SignPayload> {
	party_index: u16,
	threshold: u16,
	parties: u16,

	keygen_set_id: KeygenSetId,
	signer_set_id: SignerSetId,
	stage: Stage,

	// Message processing
	pending_keygen_msgs: Vec<DKGKeygenMessage>,
	pending_offline_msgs: Vec<DKGOfflineMessage>,

	// Key generation
	keygen: Option<Keygen>,
	local_key: Option<LocalKey>,

	// Offline stage
	offline_stage: Option<OfflineStage>,
	completed_offline_stage: Option<CompletedOfflineStage>,

	// Signing rounds
	rounds: BTreeMap<SignPayloadKey, DKGRoundTracker<SignPayload>>,
	sign_outgoing_msgs: Vec<DKGVoteMessage<SignPayloadKey>>,
	finished_rounds: Vec<DKGSignedPayload<SignPayloadKey, SignPayload>>,
}

impl<K, P> MultiPartyECDSARounds<K, P>
where
	K: Ord + Encode + Copy,
	P: Encode,
{
	/// Public ///

	pub fn new(party_index: u16, threshold: u16, parties: u16) -> Self {
		Self {
			party_index,
			threshold,
			parties,
			keygen_set_id: 0,
			signer_set_id: 0,
			stage: Stage::KeygenReady,
			pending_keygen_msgs: Vec::new(),
			pending_offline_msgs: Vec::new(),
			keygen: None,
			local_key: None,
			offline_stage: None,
			completed_offline_stage: None,
			rounds: BTreeMap::new(),
			sign_outgoing_msgs: Vec::new(),
			finished_rounds: Vec::new(),
		}
	}

	pub fn proceed(&mut self) {
		let finished = match self.stage {
			Stage::Keygen => self.proceed_keygen(),
			Stage::Offline => self.proceed_offline_stage(),
			Stage::ManualReady => self.proceed_vote(),
			_ => false,
		};

		if finished {
			self.advance_stage();
		}
	}

	pub fn get_outgoing_messages(&mut self) -> Vec<DKGMsgPayload<K>> {
		trace!(target: "webb", "Get outgoing, stage {:?}", self.stage);
		match self.stage {
			Stage::Keygen => self
				.get_outgoing_messages_keygen()
				.into_iter()
				.map(|msg| DKGMsgPayload::Keygen(msg))
				.collect(),
			Stage::Offline => self
				.get_outgoing_messages_offline_stage()
				.into_iter()
				.map(|msg| DKGMsgPayload::Offline(msg))
				.collect(),
			Stage::ManualReady => self
				.get_outgoing_messages_vote()
				.into_iter()
				.map(|msg| DKGMsgPayload::Vote(msg))
				.collect(),
			_ => vec![],
		}
	}

	pub fn handle_incoming(&mut self, data: DKGMsgPayload<K>) -> Result<(), String> {
		trace!(target: "webb", "🕸️ Enter handle incoming");

		return match data {
			DKGMsgPayload::Keygen(msg) => {
				// TODO: check keygen_set_id
				if Stage::Keygen == self.stage {
					self.handle_incoming_keygen(msg)
				} else {
					self.pending_keygen_msgs.push(msg);
					Ok(())
				}
			}
			DKGMsgPayload::Offline(msg) => {
				// TODO: check signer_set_id
				if Stage::Offline == self.stage {
					self.handle_incoming_offline_stage(msg)
				} else {
					self.pending_offline_msgs.push(msg);
					Ok(())
				}
			}
			DKGMsgPayload::Vote(msg) => {
				if Stage::ManualReady == self.stage {
					self.handle_incoming_vote(msg)
				} else {
					Ok(())
				}
			}
		};
	}

	pub fn start_keygen(&mut self, keygen_set_id: KeygenSetId) -> Result<(), String> {
		self.keygen_set_id = keygen_set_id;

		match Keygen::new(self.party_index, self.threshold, self.parties) {
			Ok(keygen) => {
				self.keygen = Some(keygen);
				self.advance_stage();

				// Processing pending messages
				for msg in std::mem::take(&mut self.pending_keygen_msgs) {
					if let Err(err) = self.handle_incoming_keygen(msg) {
						warn!(target: "webb", "🕸️ Error handling pending keygen msg {}", err.to_string());
					}
					self.proceed_keygen();
				}
				trace!(target: "webb", "🕸️ Handled {} pending keygen messages", self.pending_keygen_msgs.len());
				self.pending_keygen_msgs.clear();

				Ok(())
			}
			Err(err) => Err(err.to_string()),
		}
	}

	pub fn reset_signers(&mut self, s_l: Vec<u16>) -> Result<(), String> {
		// TODO: set signer set id
		match self.stage {
			Stage::KeygenReady | Stage::Keygen => {
				Err("Cannot reset signers and start offline stage, Keygen is not complete".to_string())
			}
			_ => {
				trace!(target: "webb", "🕸️ Resetting singers {:?}", s_l);

				if let Some(local_key_clone) = self.local_key.clone() {
					return match OfflineStage::new(self.party_index, s_l, local_key_clone) {
						Ok(new_offline_stage) => {
							self.stage = Stage::Offline;
							self.offline_stage = Some(new_offline_stage);
							self.completed_offline_stage = None;

							for msg in std::mem::take(&mut self.pending_offline_msgs) {
								if let Err(err) = self.handle_incoming_offline_stage(msg) {
									warn!(target: "webb", "🕸️ Error handling pending offline msg {}", err.to_string());
								}
								self.proceed_offline_stage();
							}
							self.pending_offline_msgs.clear();
							trace!(target: "webb", "🕸️ Handled {} pending offline messages", self.pending_offline_msgs.len());

							Ok(())
						}
						Err(err) => {
							error!("Error creating new offline stage {}", err);
							Err(err.to_string())
						}
					};
				} else {
					Err("No local key present".to_string())
				}
			}
		}
	}

	pub fn vote(&mut self, round_key: K, data: P) -> Result<(), String> {
		if let Some(completed_offline) = self.completed_offline_stage.as_mut() {
			let round = self.rounds.entry(round_key).or_default();
			let hash = HSha256::create_hash(&[&BigInt::from_bytes(&data.encode())]);

			match SignManual::new(hash, completed_offline.clone()) {
				Ok((sign_manual, sig)) => {
					round.sign_manual = Some(sign_manual);
					round.payload = Some(data);

					match bincode::serialize(&sig) {
						Ok(serialized_sig) => {
							let msg = DKGVoteMessage {
								round_key,
								partial_signature: serialized_sig,
							};
							self.sign_outgoing_msgs.push(msg);
							return Ok(());
						}
						Err(err) => return Err(err.to_string()),
					}
				}
				Err(err) => return Err(err.to_string()),
			}
		}
		Err("Not ready to vote".to_string())
	}

	pub fn is_offline_ready(&self) -> bool {
		Stage::OfflineReady == self.stage
	}

	pub fn is_ready_to_vote(&self) -> bool {
		Stage::ManualReady == self.stage
	}

	pub fn get_finished_rounds(&mut self) -> Vec<DKGSignedPayload<K, P>> {
		std::mem::take(&mut self.finished_rounds)
	}

	pub fn dkg_params(&self) -> (u16, u16, u16) {
		(self.party_index, self.threshold, self.parties)
	}
}

impl<K, P> MultiPartyECDSARounds<K, P>
where
	K: Ord + Encode + Copy,
	P: Encode,
{
	/// Internal ///

	fn advance_stage(&mut self) {
		self.stage = self.stage.get_next();
		info!(target: "webb", "🕸️ New stage {:?}", self.stage);
	}

	/// Proceed to next step for current Stage

	fn proceed_keygen(&mut self) -> bool {
		trace!(target: "webb", "🕸️ Keygen party {} enter proceed", self.party_index);

		let keygen = self.keygen.as_mut().unwrap();

		if keygen.wants_to_proceed() {
			info!(target: "webb", "🕸️ Keygen party {} wants to proceed", keygen.party_ind());
			trace!(target: "webb", "🕸️ before: {:?}", keygen);
			//TODO, handle asynchronously
			match keygen.proceed() {
				Ok(_) => {
					trace!(target: "webb", "🕸️ after: {:?}", keygen);
				}
				Err(err) => {
					error!(target: "webb", "🕸️ error encountered during proceed: {:?}", err);
				}
			}
		}

		self.try_finish_keygen()
	}

	fn proceed_offline_stage(&mut self) -> bool {
		trace!(target: "webb", "🕸️ OfflineStage party {} enter proceed", self.party_index);

		let offline_stage = self.offline_stage.as_mut().unwrap();

		if offline_stage.wants_to_proceed() {
			info!(target: "webb", "🕸️ OfflineStage party {} wants to proceed", offline_stage.party_ind());
			trace!(target: "webb", "🕸️ before: {:?}", offline_stage);
			//TODO, handle asynchronously
			match offline_stage.proceed() {
				Ok(_) => {
					trace!(target: "webb", "🕸️ after: {:?}", offline_stage);
				}
				Err(err) => {
					error!(target: "webb", "🕸️ error encountered during proceed: {:?}", err);
				}
			}
		}

		self.try_finish_offline_stage()
	}

	fn proceed_vote(&mut self) -> bool {
		self.try_finish_vote()
	}

	/// Try finish current Stage

	fn try_finish_keygen(&mut self) -> bool {
		let keygen = self.keygen.as_mut().unwrap();

		if keygen.is_finished() {
			info!(target: "webb", "🕸️ Keygen is finished, extracting output");
			match keygen.pick_output() {
				Some(Ok(k)) => {
					self.local_key = Some(k);
					info!(target: "webb", "🕸️ local share key is extracted");
					return true;
				}
				Some(Err(e)) => panic!("Keygen finished with error result {}", e),
				None => panic!("Keygen finished with no result"),
			}
		}
		return false;
	}

	fn try_finish_offline_stage(&mut self) -> bool {
		let offline_stage = self.offline_stage.as_mut().unwrap();

		if offline_stage.is_finished() {
			info!(target: "webb", "🕸️ OfflineStage is finished, extracting output");
			match offline_stage.pick_output() {
				Some(Ok(cos)) => {
					self.completed_offline_stage = Some(cos);
					info!(target: "webb", "🕸️ CompletedOfflineStage is extracted");
					return true;
				}
				Some(Err(e)) => panic!("OfflineStage finished with error result {}", e),
				None => panic!("OfflineStage finished with no result"),
			}
		}
		return false;
	}

	fn try_finish_vote(&mut self) -> bool {
		let mut finished: Vec<K> = Vec::new();

		for (round_key, round) in self.rounds.iter() {
			if round.is_done(self.threshold.into()) {
				finished.push(*round_key);
			}
		}

		for round_key in finished.iter() {
			if let Some(mut round) = self.rounds.remove(round_key) {
				let sig = round.complete();
				let payload = round.payload;

				if let (Some(payload), Some(sig)) = (payload, sig) {
					match bincode::serialize(&sig) {
						Ok(signature) => {
							let signed_payload = DKGSignedPayload {
								key: *round_key,
								payload,
								signature,
							};

							self.finished_rounds.push(signed_payload);
						}
						Err(err) => debug!("Error serializing signature {}", err.to_string()),
					}
				}
			}
		}

		false
	}

	/// Get outgoing messages for current Stage

	fn get_outgoing_messages_keygen(&mut self) -> Vec<DKGKeygenMessage> {
		trace!(target: "webb", "🕸️ Keygen party {} enter get_outgoing_messages_keygen", self.party_index);

		if let Some(keygen) = self.keygen.as_mut() {
			if !keygen.message_queue().is_empty() {
				trace!(target: "webb", "🕸️ outgoing messages, queue len: {}", keygen.message_queue().len());

				let keygen_set_id = self.keygen_set_id;

				let enc_messages = keygen
					.message_queue()
					.into_iter()
					.map(|m| {
						trace!(target: "webb", "🕸️ MPC protocol message {:?}", m);
						let m_ser = bincode::serialize(m).unwrap();
						return DKGKeygenMessage {
							keygen_set_id: keygen_set_id,
							keygen_msg: m_ser,
						};
					})
					.collect::<Vec<DKGKeygenMessage>>();

				keygen.message_queue().clear();
				return enc_messages;
			}
		}
		vec![]
	}

	fn get_outgoing_messages_offline_stage(&mut self) -> Vec<DKGOfflineMessage> {
		trace!(target: "webb", "🕸️ OfflineStage party {} enter get_outgoing_messages_offline_stage", self.party_index);

		if let Some(offline_stage) = self.offline_stage.as_mut() {
			if !offline_stage.message_queue().is_empty() {
				trace!(target: "webb", "🕸️ outgoing messages, queue len: {}", offline_stage.message_queue().len());

				let singer_set_id = self.signer_set_id;

				let enc_messages = offline_stage
					.message_queue()
					.into_iter()
					.map(|m| {
						trace!(target: "webb", "🕸️ MPC protocol message {:?}", *m);
						let m_ser = bincode::serialize(m).unwrap();
						return DKGOfflineMessage {
							signer_set_id: singer_set_id,
							offline_msg: m_ser,
						};
					})
					.collect::<Vec<DKGOfflineMessage>>();

				offline_stage.message_queue().clear();
				return enc_messages;
			}
		}
		vec![]
	}

	fn get_outgoing_messages_vote(&mut self) -> Vec<DKGVoteMessage<K>> {
		std::mem::take(&mut self.sign_outgoing_msgs)
	}

	/// Handle incoming messages for current Stage

	fn handle_incoming_keygen(&mut self, data: DKGKeygenMessage) -> Result<(), String> {
		let keygen = self.keygen.as_mut().unwrap();

		trace!(target: "webb", "🕸️ handle incoming keygen message");
		if data.keygen_msg.is_empty() {
			warn!(
				target: "webb", "🕸️ got empty message");
			return Ok(());
		}
		let msg: Msg<ProtocolMessage> = match bincode::deserialize(&data.keygen_msg) {
			Ok(msg) => msg,
			Err(err) => {
				error!(target: "webb", "🕸️ Error deserializing msg: {:?}", err);
				return Err("Error deserializing keygen msg".to_string());
			}
		};

		if Some(keygen.party_ind()) != msg.receiver && (msg.receiver.is_some() || msg.sender == keygen.party_ind()) {
			warn!(target: "webb", "🕸️ ignore messages sent by self");
			return Ok(());
		}
		trace!(
			target: "webb", "🕸️ party {} got message from={}, broadcast={}: {:?}",
			keygen.party_ind(),
			msg.sender,
			msg.receiver.is_none(),
			msg.body,
		);
		debug!(target: "webb", "🕸️ state before incoming message processing: {:?}", keygen);
		match keygen.handle_incoming(msg.clone()) {
			Ok(()) => (),
			Err(err) if err.is_critical() => {
				error!(target: "webb", "🕸️ Critical error encountered: {:?}", err);
				return Err("Keygen critical error encountered".to_string());
			}
			Err(err) => {
				error!(target: "webb", "🕸️ Non-critical error encountered: {:?}", err);
			}
		}
		debug!(target: "webb", "🕸️ state after incoming message processing: {:?}", keygen);
		Ok(())
	}

	fn handle_incoming_offline_stage(&mut self, data: DKGOfflineMessage) -> Result<(), String> {
		let offline_stage = self.offline_stage.as_mut().unwrap();

		trace!(target: "webb", "🕸️ handle incoming offline message");
		if data.offline_msg.is_empty() {
			warn!(
				target: "webb", "🕸️ got empty message");
			return Ok(());
		}
		let msg: Msg<OfflineProtocolMessage> = match bincode::deserialize(&data.offline_msg) {
			Ok(msg) => msg,
			Err(err) => {
				error!(target: "webb", "🕸️ Error deserializing msg: {:?}", err);
				return Err("Error deserializing offline msg".to_string());
			}
		};

		if Some(offline_stage.party_ind()) != msg.receiver
			&& (msg.receiver.is_some() || msg.sender == offline_stage.party_ind())
		{
			warn!(target: "webb", "🕸️ ignore messages sent by self");
			return Ok(());
		}
		trace!(
			target: "webb", "🕸️ party {} got message from={}, broadcast={}: {:?}",
			offline_stage.party_ind(),
			msg.sender,
			msg.receiver.is_none(),
			msg.body,
		);
		debug!(target: "webb", "🕸️ state before incoming message processing: {:?}", offline_stage);
		match offline_stage.handle_incoming(msg.clone()) {
			Ok(()) => (),
			Err(err) if err.is_critical() => {
				error!(target: "webb", "🕸️ Critical error encountered: {:?}", err);
				return Err("Offline critical error encountered".to_string());
			}
			Err(err) => {
				error!(target: "webb", "🕸️ Non-critical error encountered: {:?}", err);
			}
		}
		debug!(target: "webb", "🕸️ state after incoming message processing: {:?}", offline_stage);
		Ok(())
	}

	fn handle_incoming_vote(&mut self, data: DKGVoteMessage<K>) -> Result<(), String> {
		trace!(target: "webb", "🕸️ handle vote message");
		match bincode::deserialize(&data.partial_signature) {
			Ok(sig) => {
				self.rounds.entry(data.round_key).or_default().add_vote(sig);
				return Ok(());
			}
			Err(err) => {
				error!(target: "webb", "🕸️ Error deserializing msg: {:?}", err);
				return Err("Error deserializing vote msg".to_string());
			}
		}
	}
}

struct DKGRoundTracker<Payload> {
	votes: Vec<PartialSignature>,
	sign_manual: Option<SignManual>,
	payload: Option<Payload>,
}

impl<P> Default for DKGRoundTracker<P> {
	fn default() -> Self {
		Self {
			votes: Default::default(),
			sign_manual: Default::default(),
			payload: Default::default(),
		}
	}
}

impl<P> DKGRoundTracker<P> {
	fn add_vote(&mut self, vote: PartialSignature) -> bool {
		// TODO: check for duplicates

		self.votes.push(vote);
		true
	}

	fn is_done(&self, threshold: usize) -> bool {
		self.sign_manual.is_some() && self.votes.len() >= threshold
	}

	fn complete(&mut self) -> Option<SignatureRecid> {
		if let Some(sign_manual) = self.sign_manual.take() {
			return match sign_manual.complete(&self.votes) {
				Ok(sig) => {
					debug!("Obtained complete signature: {}", &sig.recid);
					Some(sig)
				}
				Err(err) => {
					error!("Error signing: {:?}", &err);
					None
				}
			};
		}
		None
	}
}

#[cfg(test)]
mod tests {
	use super::{MultiPartyECDSARounds, Stage};
	use curv::{
		arithmetic::Converter,
		cryptographic_primitives::hashing::{hash_sha256::HSha256, traits::Hash as CurvHash},
		BigInt,
	};
	use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::verify;

	// fn check_all_signatures_ready(parties: &mut Vec<MultiPartyECDSARounds>) -> bool {
	// 	for party in &mut parties.into_iter() {
	// 		if let Some(sig) = party.extract_signature() {
	// 			let pub_k = party.completed_offline_stage.as_ref().unwrap().public_key().clone();
	// 			let message = HSha256::create_hash(&[&BigInt::from_bytes(b"Webb")]);
	// 			if !verify(&sig, &pub_k, &message).is_ok() {
	// 				panic!("Invalid signature for party {}", party.party_index);
	// 			}
	// 			println!("Party {}; sig: {:?}", party.party_index, &sig);
	// 		} else {
	// 			panic!("No signature extracted")
	// 		}
	// 	}

	// 	for party in &mut parties.into_iter() {
	// 		match party.stage {
	// 			Stage::ManualReady => (),
	// 			_ => panic!("Stage must be ManualReady, but {:?} found", &party.stage),
	// 		}
	// 	}

	// 	true
	// }

	fn check_all_reached_stage(parties: &mut Vec<MultiPartyECDSARounds>, target_stage: Stage) -> bool {
		for party in &mut parties.into_iter() {
			if party.stage == target_stage {
				continue;
			}
			return false;
		}

		true
	}

	fn run_simulation(parties: &mut Vec<MultiPartyECDSARounds>, target_stage: Stage) {
		println!("Simulation starts");

		let mut msgs_pull = vec![];

		for party in &mut parties.into_iter() {
			party.proceed();

			if let Some(mut msgs) = party.get_outgoing_messages() {
				msgs_pull.append(&mut msgs);
			}
		}

		for _i in 1..100 {
			let msgs_pull_frozen = msgs_pull.split_off(0);

			for party in &mut parties.into_iter() {
				for msg_frozen in &msgs_pull_frozen {
					match party.handle_incoming(&msg_frozen) {
						Ok(()) => (),
						Err(_err) => (),
					}
				}
				if let Some(mut msgs) = party.get_outgoing_messages() {
					msgs_pull.append(&mut msgs);
				}
			}

			for party in &mut parties.into_iter() {
				party.proceed();

				if let Some(mut msgs) = party.get_outgoing_messages() {
					msgs_pull.append(&mut msgs);
				}
			}

			if check_all_reached_stage(parties, target_stage) {
				println!("All parties finished");
				return;
			}
		}

		panic!("Test failed")
	}

	fn simulate_multi_party(t: u16, n: u16, s_l: Vec<u16>) {
		let mut parties: Vec<MultiPartyECDSARounds> = vec![];

		for i in 1..=n {
			parties.push(MultiPartyECDSARounds::new(i, t, n).unwrap());
		}

		// Running Keygen stage
		println!("Running Keygen");
		run_simulation(&mut parties, Stage::OfflineReady);

		// Running Offline stage
		println!("Running Offline");
		let parties_refs = &mut parties;
		for party in &mut parties_refs.into_iter() {
			println!(
				"Resetting signers for party {}, Stage: {:?}",
				party.party_index, party.stage
			);
			match party.reset_signers(s_l.clone()) {
				Ok(()) => (),
				Err(_err) => (),
			}
		}
		run_simulation(&mut parties, Stage::ManualReady);
	}

	#[test]
	fn simulate_multi_party_t2_n3() {
		simulate_multi_party(2, 3, (1..=3).collect());
	}

	#[test]
	fn simulate_multi_party_t9_n10() {
		simulate_multi_party(9, 10, (1..=10).collect());
	}
}
