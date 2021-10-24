use beefy_primitives::{crypto::Public, Commitment, ValidatorSet, ValidatorSetId};
use bincode;
use codec::{Decode, Encode};
use curv::{
	arithmetic::Converter,
	cryptographic_primitives::hashing::{hash_sha256::HSha256, traits::Hash as CurvHash},
	elliptic::curves::{
		secp256_k1::{FE, GE},
		traits::*,
	},
	BigInt,
};
use hex::{self};
use log::{debug, error, info, trace, warn};
use round_based::{IsCritical, Msg, StateMachine};
use secp256k1::curve::{Affine, Field};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use sp_arithmetic::traits::AtLeast32BitUnsigned;
use sp_keystore::{Error, SyncCryptoStore};
use sp_runtime::traits::{Block, Hash, Header, MaybeDisplay};
use std::{collections::BTreeMap, convert::TryInto, hash::Hash as StdHash, sync::Arc};

pub use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::{
	party_i::*,
	state_machine::{keygen::*, sign::*},
};

use crate::error::MPCError;

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

/// WEBB DKG (distributed key generation) message.
///
/// A vote message is a direct vote created by a WEBB node on every voting round
/// and is gossiped to its peers.
#[derive(Debug, Decode, Encode)]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub struct DKGMessage<Public> {
	/// Node authority id
	pub id: Public,
	/// DKG protocol type identifier
	pub dkg_type: DKGType,
	/// DKG message contents
	pub message: Vec<u8>,
}

#[derive(Debug, Decode, Encode)]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub struct DKGVoteMessage<Hash, Number, Id> {
	/// Commit to information extracted from a finalized block
	pub commitment: Commitment<Number, Hash>,
	/// Node authority id
	pub id: Id,
	/// Node signature
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

pub struct DKGState {
	pub accepted: bool,
	pub is_epoch_over: bool,
	pub curr_dkg: Option<MultiPartyECDSASettings>,
	pub past_dkg: Option<MultiPartyECDSASettings>,
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

pub struct MultiPartyECDSASettings {
	pub party_index: u16,
	pub threshold: u16,
	pub parties: u16,

	stage: Stage,

	// Message processing
	pub pending_keygen_msgs: Vec<Vec<u8>>,
	pub pending_offline_msgs: Vec<Vec<u8>>,

	// Key generation
	pub keygen: Option<Keygen>,
	pub local_key: Option<LocalKey>,

	// Signing offline stage
	pub offline_stage: Option<OfflineStage>,
	pub completed_offline_stage: Option<CompletedOfflineStage>,
}

impl MultiPartyECDSASettings {
	pub fn new(party_index: u16, threshold: u16, parties: u16) -> Result<Self, MPCError> {
		Ok(Self {
			party_index,
			threshold,
			parties,
			stage: Stage::KeygenReady,
			pending_keygen_msgs: Vec::new(),
			pending_offline_msgs: Vec::new(),
			keygen: None,
			local_key: None,
			offline_stage: None,
			completed_offline_stage: None,
		})
	}

	/// Public ///

	pub fn proceed(&mut self) {
		let finished = match self.stage {
			Stage::Keygen => self.proceed_keygen(),
			Stage::Offline => self.proceed_offline_stage(),
			_ => false,
		};

		if finished {
			self.advance_stage();
		}
	}

	pub fn get_outgoing_messages(&mut self) -> Option<Vec<Vec<u8>>> {
		trace!(target: "webb", "Get outgoing, stage {:?}", self.stage);
		match self.stage {
			Stage::Keygen => self.get_outgoing_messages_keygen(),
			Stage::Offline => self.get_outgoing_messages_offline_stage(),
			_ => None,
		}
	}

	pub fn handle_incoming(&mut self, data: &[u8]) -> Result<(), MPCError> {
		trace!(target: "webb", "🕸️ Enter handle incoming");

		let decoded_wrapper: (Stage, Vec<u8>) = bincode::deserialize(&data[..]).unwrap();

		if decoded_wrapper.0 == self.stage {
			return match self.stage {
				Stage::Keygen => self.handle_incoming_keygen(&decoded_wrapper.1),
				Stage::Offline => self.handle_incoming_offline_stage(&decoded_wrapper.1),
				_ => Ok(()),
			};
		} else {
			if Stage::Keygen == decoded_wrapper.0 {
				self.pending_keygen_msgs.push(decoded_wrapper.1);
			} else if Stage::Offline == decoded_wrapper.0 {
				self.pending_offline_msgs.push(decoded_wrapper.1)
			}

			Ok(())
		}
	}

	pub fn start_keygen(&mut self) -> Result<(), String> {
		match Keygen::new(self.party_index, self.threshold, self.parties) {
			Ok(keygen) => {
				self.keygen = Some(keygen);
				self.advance_stage();

				// Processing pending messages
				for msg in self.pending_keygen_msgs.clone().iter() {
					if let Err(err) = self.handle_incoming_keygen(&msg) {
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

							for msg in self.pending_offline_msgs.clone().iter() {
								if let Err(err) = self.handle_incoming_offline_stage(&msg) {
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

	pub fn is_offline_ready(&self) -> bool {
		Stage::OfflineReady == self.stage
	}

	pub fn is_ready_to_sign(&self) -> bool {
		Stage::ManualReady == self.stage
	}

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

	/// Get outgoing messages for current Stage

	fn get_outgoing_messages_keygen(&mut self) -> Option<Vec<Vec<u8>>> {
		trace!(target: "webb", "🕸️ Keygen party {} enter get_outgoing_messages_keygen", self.party_index);

		let keygen = self.keygen.as_mut().unwrap();

		if !keygen.message_queue().is_empty() {
			trace!(target: "webb", "🕸️ outgoing messages, queue len: {}", keygen.message_queue().len());

			let enc_messages = keygen
				.message_queue()
				.into_iter()
				.map(|m| {
					trace!(target: "webb", "🕸️ MPC protocol message {:?}", *m);
					let m_ser = bincode::serialize(m).unwrap();
					bincode::serialize(&(Stage::Keygen, m_ser)).unwrap()
				})
				.collect::<Vec<Vec<u8>>>();

			keygen.message_queue().clear();
			return Some(enc_messages);
		}
		None
	}

	fn get_outgoing_messages_offline_stage(&mut self) -> Option<Vec<Vec<u8>>> {
		trace!(target: "webb", "🕸️ OfflineStage party {} enter get_outgoing_messages_offline_stage", self.party_index);

		let offline_stage = self.offline_stage.as_mut().unwrap();

		if !offline_stage.message_queue().is_empty() {
			trace!(target: "webb", "🕸️ outgoing messages, queue len: {}", offline_stage.message_queue().len());

			let enc_messages = offline_stage
				.message_queue()
				.into_iter()
				.map(|m| {
					trace!(target: "webb", "🕸️ MPC protocol message {:?}", *m);
					let m_ser = bincode::serialize(m).unwrap();
					bincode::serialize(&(Stage::Offline, m_ser)).unwrap()
				})
				.collect::<Vec<Vec<u8>>>();

			offline_stage.message_queue().clear();
			return Some(enc_messages);
		}
		None
	}

	/// Handle incoming messages for current Stage

	fn handle_incoming_keygen(&mut self, data: &[u8]) -> Result<(), MPCError> {
		let keygen = self.keygen.as_mut().unwrap();

		trace!(target: "webb", "🕸️ handle incoming message");
		if data.is_empty() {
			warn!(
				target: "webb", "🕸️ got empty message");
			return Ok(());
		}
		let msg: Msg<ProtocolMessage> = match bincode::deserialize(&data[..]) {
			Ok(msg) => msg,
			Err(err) => {
				error!(target: "webb", "🕸️ Error deserializing msg: {:?}", err);
				panic!("🕸️ Error deserializing msg: {:?}", err)
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
				return Err(MPCError::CryptoOperation(err.to_string()));
			}
			Err(err) => {
				error!(target: "webb", "🕸️ Non-critical error encountered: {:?}", err);
			}
		}
		debug!(target: "webb", "🕸️ state after incoming message processing: {:?}", keygen);
		Ok(())
	}

	fn handle_incoming_offline_stage(&mut self, data: &[u8]) -> Result<(), MPCError> {
		let offline_stage = self.offline_stage.as_mut().unwrap();

		trace!(target: "webb", "🕸️ handle incoming message");
		if data.is_empty() {
			warn!(
				target: "webb", "🕸️ got empty message");
			return Ok(());
		}
		let msg: Msg<OfflineProtocolMessage> = match bincode::deserialize(&data[..]) {
			Ok(msg) => msg,
			Err(err) => {
				error!(target: "webb", "🕸️ Error deserializing msg: {:?}", err);
				panic!("🕸️ Error deserializing msg: {:?}", err)
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
				return Err(MPCError::CryptoOperation(err.to_string()));
			}
			Err(err) => {
				error!(target: "webb", "🕸️ Non-critical error encountered: {:?}", err);
			}
		}
		debug!(target: "webb", "🕸️ state after incoming message processing: {:?}", offline_stage);
		Ok(())
	}
}

#[derive(Default)]
struct DKGRoundTracker {
	sign_manual: Option<SignManual>,
	votes: Vec<(GE, PartialSignature)>,
}

impl DKGRoundTracker {
	fn add_vote(&mut self, vote: (GE, PartialSignature)) -> bool {
		self.votes.push(vote);
		true
	}

	fn is_done(&self, threshold: usize) -> bool {
		self.sign_manual.is_some() && self.votes.len() >= threshold
	}

	fn complete(&mut self) -> Option<SignatureRecid> {
		if let Some(sign_manual) = self.sign_manual.take() {
			let partial_sigs: Vec<PartialSignature> = self.votes.iter().map(|vote| vote.1.clone()).collect();

			return match sign_manual.complete(&partial_sigs) {
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

pub struct DKGRounds<Hash, Number> {
	validator_set: ValidatorSet<Public>,
	dkg_settings: MultiPartyECDSASettings,
	rounds: BTreeMap<(Hash, Number), DKGRoundTracker>,
}

impl<H, N> DKGRounds<H, N>
where
	H: Ord + StdHash,
	N: Ord + AtLeast32BitUnsigned + MaybeDisplay,
{
	pub(crate) fn new(validator_set: ValidatorSet<Public>, party_index: u16, threshold: u16, parties: u16) -> Self {
		DKGRounds {
			validator_set,
			dkg_settings: MultiPartyECDSASettings::new(party_index, threshold, parties).unwrap(),
			rounds: BTreeMap::new(),
		}
	}
}

impl<H, N> DKGRounds<H, N>
where
	H: Ord + StdHash,
	N: Ord + AtLeast32BitUnsigned + MaybeDisplay,
{
	pub fn validator_set_id(&self) -> ValidatorSetId {
		self.validator_set.id
	}

	pub fn validators(&self) -> Vec<Public> {
		self.validator_set.validators.clone()
	}

	// DKG setup

	pub fn proceed(&mut self) {
		self.dkg_settings.proceed()
	}

	pub fn get_outgoing_messages(&mut self) -> Option<Vec<Vec<u8>>> {
		self.dkg_settings.get_outgoing_messages()
	}

	pub fn handle_incoming(&mut self, data: &[u8]) -> Result<(), MPCError> {
		self.dkg_settings.handle_incoming(data)
	}

	pub fn start_keygen(&mut self) -> Result<(), String> {
		self.dkg_settings.start_keygen()
	}

	pub fn reset_signers(&mut self, s_l: Vec<u16>) -> Result<(), String> {
		self.dkg_settings.reset_signers(s_l)
	}

	pub fn is_offline_ready(&self) -> bool {
		self.dkg_settings.is_offline_ready()
	}

	pub fn is_ready_to_sign(&self) -> bool {
		self.dkg_settings.is_ready_to_sign()
	}

	pub fn dkg_params(&self) -> (u16, u16, u16) {
		(
			self.dkg_settings.party_index,
			self.dkg_settings.threshold,
			self.dkg_settings.parties,
		)
	}

	// DKG vote rounds

	pub fn vote(&mut self, round: (H, N), data: &[u8]) -> Option<(GE, PartialSignature)> {
		if let (Some(local_key), Some(completed_offline)) = (
			self.dkg_settings.local_key.as_mut(),
			self.dkg_settings.completed_offline_stage.as_mut(),
		) {
			let round = self.rounds.entry(round).or_default();
			let hash = HSha256::create_hash(&[&BigInt::from_bytes(data)]);
			if let Ok((sign_manual, sig)) = SignManual::new(hash, completed_offline.clone()) {
				round.sign_manual = Some(sign_manual);
				return Some((local_key.public_key().clone(), sig));
			}
		}
		None
	}

	pub fn add_vote(&mut self, round: (H, N), vote: (GE, PartialSignature)) -> bool {
		self.rounds.entry(round).or_default().add_vote(vote)
	}

	pub fn is_done(&self, round: &(H, N)) -> bool {
		let done = self
			.rounds
			.get(round)
			.map(|tracker| tracker.is_done(self.dkg_settings.threshold.into()))
			.unwrap_or(false);

		debug!(target: "webb", "🕸️ Round #{} done: {}", round.1, done);

		done
	}

	pub fn drop(&mut self, round: &(H, N)) -> Option<SignatureRecid> {
		trace!(target: "webb", "🕸️ About to drop round #{}", round.1);

		let signature = self.rounds.remove(round)?.complete();
		signature
	}

	pub fn drop_stale(&mut self) {
		// TODO: drop obsolete rounds according to some condition (e.g. number of blocks passed)
	}
}

pub fn recover_pub_key(sig: &SignatureRecid, message: &BigInt) -> Result<GE, String> {
	recover_pub_key_raw(message, sig.recid, sig.r, sig.s)
}

pub fn recover_pub_key_raw(message: &BigInt, v: u8, r: FE, s: FE) -> Result<GE, String> {
	// r^-1 * (s*R - z*G) = R * s * r^-1 - G * z * r^-1

	let p_minus_order: Field = Field::new(0, 0, 0, 1, 0x45512319, 0x50B75FC4, 0x402DA172, 0x2FC9BAEE);

	let order_as_fe: Field = Field::new(
		0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xBAAEDCE6, 0xAF48A03B, 0xBFD25E8C, 0xD0364141,
	);

	// r value as X coordinate in a Field format
	let mut fx = Field::default();
	let r_bytes: [u8; 32] = match r.to_big_int().to_bytes().try_into() {
		Ok(res) => res,
		Err(_err) => return Err("Invalid r value".to_string()),
	};
	let overflow = fx.set_b32(&r_bytes);
	debug_assert!(overflow);

	// Check validity of a point constructed from r value
	if v & 2 > 0 {
		if fx >= p_minus_order {
			return Err("Invalalid signature".to_string());
		}
		fx += order_as_fe;
	}

	// point, calculated from r value
	let mut r_calc_point = Affine::default();
	if !r_calc_point.set_xo_var(&fx, v & 1 > 0) {
		return Err("Invalid signature".to_string());
	}
	r_calc_point.x.normalize();
	r_calc_point.y.normalize();

	// point, calculated from r value in Secp256k1Point format
	let r_calc = {
		let mut r_calc_bytes: Vec<u8> = Vec::new();
		r_calc_bytes.extend_from_slice(&r_calc_point.x.b32());
		r_calc_bytes.extend_from_slice(&r_calc_point.y.b32());

		match GE::from_bytes(&r_calc_bytes) {
			Ok(res) => res,
			Err(_err) => return Err("Could not construct Secp256k1Point from r value".to_string()),
		}
	};

	let g: GE = ECPoint::generator(); // G
	let z: FE = ECScalar::from(message); // z

	let rn = r.invert(); // r^-1

	let rsrn = r_calc * s * rn; // R * s * r^-1
	let gzrn = g * z * rn; // G * z * r^-1

	let pub_key = rsrn.sub_point(&gzrn.get_element());

	return Ok(pub_key);
}

pub fn convert_to_checksum_eth_address(addr: &str) -> Result<String, String> {
	let addr = addr.to_lowercase();

	let addr_hash = {
		let mut hasher = Keccak256::new();
		hasher.update(addr.as_bytes());
		hex::encode(hasher.finalize())
	};

	let addr_vec = addr.chars().collect::<Vec<char>>();
	let addr_hash_vec = addr_hash.chars().collect::<Vec<char>>();

	let mut checksum_addr = String::new();

	for i in 0..addr_vec.len() {
		let n = match u16::from_str_radix(&addr_hash_vec[i].to_string(), 16) {
			Ok(res) => res,
			Err(err) => return Err(err.to_string()),
		};

		if n > 7 {
			checksum_addr.push_str(&addr_vec[i].to_uppercase().to_string());
		} else {
			checksum_addr.push(addr_vec[i]);
		}
	}

	return Ok(checksum_addr);
}

pub fn convert_to_eth_address(pub_key: &GE) -> Result<String, String> {
	let x = match pub_key.x_coor() {
		Some(res) => res,
		None => return Err("X coordinate is absent".to_string()),
	};
	let y = match pub_key.y_coor() {
		Some(res) => res,
		None => return Err("Y coordinate is absent".to_string()),
	};

	let mut serialized_pub_key = x.to_hex().to_owned();
	serialized_pub_key.push_str(&y.to_hex());

	let mut hasher = Keccak256::new();
	match hex::decode(serialized_pub_key) {
		Ok(decoded) => hasher.update(decoded),
		Err(err) => return Err(err.to_string()),
	}
	let pub_key_hash = hasher.finalize();

	let serialized_pub_key_hash = hex::encode(&pub_key_hash);
	let eth_address = &serialized_pub_key_hash[24..serialized_pub_key_hash.len()];

	return convert_to_checksum_eth_address(eth_address);
}

#[cfg(test)]
mod tests {
	use super::{
		convert_to_checksum_eth_address, convert_to_eth_address, recover_pub_key_raw, MultiPartyECDSASettings, Stage,
	};
	use curv::{
		arithmetic::Converter,
		elliptic::curves::{
			secp256_k1::GE,
			traits::{ECPoint, ECScalar},
		},
		BigInt,
	};

	fn check_all_reached_stage(parties: &mut Vec<MultiPartyECDSASettings>, target_stage: Stage) -> bool {
		for party in &mut parties.into_iter() {
			if party.stage == target_stage {
				continue;
			}
			return false;
		}

		true
	}

	fn run_simulation(parties: &mut Vec<MultiPartyECDSASettings>, target_stage: Stage) {
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
		let mut parties: Vec<MultiPartyECDSASettings> = vec![];

		for i in 1..=n {
			parties.push(MultiPartyECDSASettings::new(i, t, n).unwrap());
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

	#[test]
	fn test_recover_pub_key_raw() {
		let message = BigInt::from_hex("4ff5b6816dd118b8c362939cfb7332f667ff071a1828aa96c760871e1b5634fd").unwrap();

		println!("Message: {:?}", message.to_hex());

		let v: u8 = 0;
		let r = ECScalar::from(
			&BigInt::from_hex("4f282dd8be26cc20c27ccb986452411cc90ba9b9e9802256b7ecd3ba98b6fac4").unwrap(),
		);
		let s = ECScalar::from(
			&BigInt::from_hex("5e378bbb7f7c7db9c4c7baf898134d636c810d2cb2cec5c85e36ee2c341265be").unwrap(),
		);

		println!("r: {:?}", &r);
		println!("s: {:?}", &s);

		let recovered = recover_pub_key_raw(&message, v, r, s).unwrap();

		let expected_x = BigInt::from_hex("91a27f998f3971e5b62bbde231264271faf91f837c506fde88c4bfb9c533f1c2").unwrap();
		let expected_y = BigInt::from_hex("c7b40c9fdca6815d43b315c8b039ecda1ba7eabd97794496c3023730581d7d63").unwrap();

		let actual_x = recovered.x_coor().unwrap();
		let actual_y = recovered.y_coor().unwrap();

		println!("Expected pubkey: {}{}", expected_x.to_hex(), expected_y.to_hex());
		println!("Recovered pubkey: {}{}", actual_x.to_hex(), actual_y.to_hex());

		assert_eq!(actual_x, expected_x);
		assert_eq!(actual_y, expected_y);
	}

	#[test]
	fn test_convert_to_checksum_eth_address() {
		let test = |addr: &str| {
			assert_eq!(addr, &convert_to_checksum_eth_address(&addr).unwrap());
		};

		test("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
		test("fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359");
		test("dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB");
		test("D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb");
	}

	#[test]
	fn test_convert_to_eth_address() {
		let x = BigInt::from_hex("91a27f998f3971e5b62bbde231264271faf91f837c506fde88c4bfb9c533f1c2").unwrap();
		let y = BigInt::from_hex("c7b40c9fdca6815d43b315c8b039ecda1ba7eabd97794496c3023730581d7d63").unwrap();

		let eth_addr = convert_to_eth_address(&GE::from_coor(&x, &y)).unwrap();

		assert_eq!("E24FAFbc593B2Dbb8DaF296F9BBf5DA94E633A40", eth_addr);
	}
}
