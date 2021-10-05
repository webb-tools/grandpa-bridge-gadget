use bincode;
use codec::{Decode, Encode};
use curv::{
	arithmetic::Converter,
	cryptographic_primitives::hashing::{hash_sha256::HSha256, traits::Hash as CurvHash},
	BigInt,
};
use log::{debug, error, info, trace, warn};
use round_based::{IsCritical, Msg, StateMachine};
use sp_keystore::{Error, SyncCryptoStore};
use sp_runtime::traits::{Block, Hash, Header};
use std::sync::Arc;

pub use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::{
	party_i::*,
	state_machine::{keygen::*, sign::*},
};

use crate::error::MPCError;

#[derive(Debug, Decode, Encode)]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub enum DKGType {
	MultiPartyECDSA,
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

#[derive(Debug, Clone, Copy)]
enum Stage {
	Keygen,
	Offline,
	ManualReady,
	ManualProcessing,
	SignatureReady,
}

impl Stage {
	fn get_next(self) -> Stage {
		match self {
			Stage::Keygen => Stage::Offline,
			Stage::Offline => Stage::ManualReady,
			Stage::ManualReady => Stage::ManualProcessing,
			Stage::ManualProcessing => Stage::SignatureReady,
			Stage::SignatureReady => Stage::ManualReady,
		}
	}
}

pub struct MultiPartyECDSASettings {
	pub party_index: u16,
	pub threshold: u16,
	pub parties: u16,

	pub signers: Vec<usize>,

	stage: Stage,

	// Key generation
	pub keygen: Keygen,
	pub local_key: Option<LocalKey>,

	// Signing offline stage
	pub offline_stage: Option<OfflineStage>,
	pub completed_offline_stage: Option<CompletedOfflineStage>,

	// Message signing
	pub sign_manual: Option<SignManual>,
	sign_outgoing_msg_q: Vec<Msg<PartialSignature>>,
	sign_incoming_msg_q: Vec<Msg<PartialSignature>>,
	pub signature: Option<SignatureRecid>,
}

impl MultiPartyECDSASettings {
	pub fn new(party_index: u16, threshold: u16, parties: u16) -> Result<Self, MPCError> {
		let keygen = Keygen::new(party_index, threshold, parties)?;
		Ok(Self {
			party_index,
			threshold,
			parties,
			signers: (1..=usize::from(threshold)).collect(),
			stage: Stage::Keygen,
			keygen,
			local_key: None,
			offline_stage: None,
			completed_offline_stage: None,
			sign_manual: None,
			sign_outgoing_msg_q: vec![],
			sign_incoming_msg_q: vec![],
			signature: None,
		})
	}

	/// Public ///

	pub fn get_outgoing_messages(&mut self) -> Option<Vec<Vec<u8>>> {
		match self.stage {
			Stage::Keygen => self.get_outgoing_messages_keygen(),
			Stage::Offline => self.get_outgoing_messages_offline_stage(),
			Stage::ManualProcessing => self.get_outgoing_messages_sign_manual(),
			_ => None,
		}
	}

	pub fn proceed(&mut self) {
		match self.stage {
			Stage::Keygen => self.proceed_keygen(),
			Stage::Offline => self.proceed_offline_stage(),
			Stage::ManualProcessing => self.proceed_sign_manual(),
			_ => return,
		}
	}

	pub fn handle_incoming(&mut self, data: &[u8]) -> Result<(), MPCError> {
		match self.stage {
			Stage::Keygen => self.handle_incoming_keygen(data),
			Stage::Offline => self.handle_incoming_offline_stage(data),
			Stage::ManualProcessing => self.handle_incoming_sign_manual(data),
			_ => Ok(()),
		}
	}

	pub fn try_finish(&mut self) {
		let finished = match self.stage {
			Stage::Keygen => self.try_finish_keygen(),
			Stage::Offline => self.try_finish_offline_stage(),
			Stage::ManualProcessing => self.try_finish_sign_manual(),
			_ => false,
		};

		if finished {
			self.advance_stage();
		}
	}

	pub fn try_sign(&mut self, message: &[u8]) -> Result<(), String> {
		match self.stage {
			Stage::ManualReady => {
				let message = HSha256::create_hash(&[&BigInt::from_bytes(message)]);
				let (sign_manual, partial_sig) =
					SignManual::new(message.clone(), self.completed_offline_stage.clone().unwrap()).unwrap();

				self.sign_manual = Some(sign_manual);

				let protocol_msg = Msg {
					sender: self.party_index,
					receiver: None,
					body: partial_sig,
				};
				self.sign_outgoing_msg_q.push(protocol_msg);

				self.advance_stage();

				Ok(())
			}
			_ => Err("Current stage is not ManualReady".to_string()),
		}
	}

	pub fn is_ready_to_sing(self) -> bool {
		match self.stage {
			Stage::ManualReady => true,
			_ => false,
		}
	}

	/// Internal ///

	fn advance_stage(&mut self) {
		self.stage = self.stage.get_next();

		match self.stage {
			Stage::Offline => {
				let local_key_clone = self.local_key.clone().unwrap();

				// TODO(temld4): maybe make manual stage advance
				self.offline_stage =
					Some(OfflineStage::new(self.party_index, (1..=self.parties).collect(), local_key_clone).unwrap());
			}
			_ => (),
		}
	}

	/// Get outgoing messages for current Stage

	fn get_outgoing_messages_keygen(&mut self) -> Option<Vec<Vec<u8>>> {
		if !self.keygen.message_queue().is_empty() {
			trace!(target: "webb", "🕸️ outgoing messages, queue len: {}", self.keygen.message_queue().len());

			let enc_messages = self
				.keygen
				.message_queue()
				.into_iter()
				.map(|m| {
					trace!(target: "webb", "🕸️ MPC protocol message {:?}", *m);
					let m_ser = bincode::serialize(m).unwrap();
					m_ser
				})
				.collect::<Vec<Vec<u8>>>();

			self.keygen.message_queue().clear();
			return Some(enc_messages);
		}
		None
	}

	fn get_outgoing_messages_offline_stage(&mut self) -> Option<Vec<Vec<u8>>> {
		let offline_stage = self.offline_stage.as_mut().unwrap();

		if !offline_stage.message_queue().is_empty() {
			trace!(target: "webb", "🕸️ outgoing messages, queue len: {}", offline_stage.message_queue().len());

			let enc_messages = offline_stage
				.message_queue()
				.into_iter()
				.map(|m| {
					trace!(target: "webb", "🕸️ MPC protocol message {:?}", *m);
					let m_ser = bincode::serialize(m).unwrap();
					m_ser
				})
				.collect::<Vec<Vec<u8>>>();

			offline_stage.message_queue().clear();
			return Some(enc_messages);
		}
		None
	}

	fn get_outgoing_messages_sign_manual(&mut self) -> Option<Vec<Vec<u8>>> {
		if !self.sign_outgoing_msg_q.is_empty() {
			trace!(target: "webb", "🕸️ outgoing messages, queue len: {}", self.sign_outgoing_msg_q.len());

			let enc_messages = self
				.sign_outgoing_msg_q
				.as_mut_slice()
				.into_iter()
				.map(|m| {
					trace!(target: "webb", "🕸️ MPC protocol message {:?}", &m);
					let m_ser = bincode::serialize(&m).unwrap();
					m_ser
				})
				.collect::<Vec<Vec<u8>>>();

			self.sign_outgoing_msg_q.clear();
			return Some(enc_messages);
		}
		None
	}

	/// Proceed to next step for current Stage

	fn proceed_keygen(&mut self) {
		if self.keygen.wants_to_proceed() {
			info!(target: "webb", "🕸️ Keygen party {} wants to proceed", self.keygen.party_ind());
			trace!(target: "webb", "🕸️ before: {:?}", self.keygen);
			//TODO, handle asynchronously
			match self.keygen.proceed() {
				Ok(_) => {
					trace!(target: "webb", "🕸️ after: {:?}", self.keygen);
				}
				Err(err) => {
					error!(target: "webb", "🕸️ error encountered during proceed: {:?}", err);
				}
			}
		}
	}

	fn proceed_offline_stage(&mut self) {
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
	}

	fn proceed_sign_manual(&mut self) {
		if self.signature.is_none() && self.sign_incoming_msg_q.len() >= self.threshold.into() {
			let sign_manual = std::mem::replace(&mut self.sign_manual, None).unwrap();

			let partial_sigs: Vec<PartialSignature> =
				self.sign_incoming_msg_q.iter().map(|msg| msg.body.clone()).collect();

			match sign_manual.complete(&partial_sigs) {
				Ok(sig) => {
					debug!("Obtained complete signature: {}", &sig.recid);
					self.signature = Some(sig);
				}
				Err(err) => error!("Error signing: {:?}", &err),
			}
		}
	}

	/// Handle incoming messages for current Stage

	fn handle_incoming_keygen(&mut self, data: &[u8]) -> Result<(), MPCError> {
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

		if Some(self.keygen.party_ind()) != msg.receiver
			&& (msg.receiver.is_some() || msg.sender == self.keygen.party_ind())
		{
			warn!(target: "webb", "🕸️ ignore messages sent by self");
			return Ok(());
		}
		trace!(
			target: "webb", "🕸️ party {} got message from={}, broadcast={}: {:?}",
			self.keygen.party_ind(),
			msg.sender,
			msg.receiver.is_none(),
			msg.body,
		);
		debug!(target: "webb", "🕸️ state before incoming message processing: {:?}", self.keygen);
		match self.keygen.handle_incoming(msg.clone()) {
			Ok(()) => (),
			Err(err) if err.is_critical() => {
				error!(target: "webb", "🕸️ Critical error encountered: {:?}", err);
				return Err(MPCError::CryptoOperation(err.to_string()));
			}
			Err(err) => {
				error!(target: "webb", "🕸️ Non-critical error encountered: {:?}", err);
			}
		}
		debug!(target: "webb", "🕸️ state after incoming message processing: {:?}", self.keygen);
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

	fn handle_incoming_sign_manual(&mut self, data: &[u8]) -> Result<(), MPCError> {
		trace!(target: "webb", "🕸️ handle incoming message");
		if data.is_empty() {
			warn!(
				target: "webb", "🕸️ got empty message");
			return Ok(());
		}
		let msg: Msg<PartialSignature> = match bincode::deserialize(&data[..]) {
			Ok(msg) => msg,
			Err(err) => {
				error!(target: "webb", "🕸️ Error deserializing msg: {:?}", err);
				panic!("🕸️ Error deserializing msg: {:?}", err)
			}
		};

		if Some(self.party_index) != msg.receiver && (msg.receiver.is_some() || msg.sender == self.party_index) {
			warn!(target: "webb", "🕸️ ignore messages sent by self");
			return Ok(());
		}
		trace!(
			target: "webb", "🕸️ party {} got message from={}, broadcast={}: {:?}",
			self.party_index,
			msg.sender,
			msg.receiver.is_none(),
			msg.body,
		);

		self.sign_incoming_msg_q.push(msg);

		Ok(())
	}

	/// Try finish current Stage

	fn try_finish_keygen(&mut self) -> bool {
		if self.keygen.is_finished() {
			info!(target: "webb", "🕸️ Keygen is finished, extracting output");
			match self.keygen.pick_output() {
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

	fn try_finish_sign_manual(&mut self) -> bool {
		if let Some(_sig) = &self.signature {
			info!(target: "webb", "🕸️ Manual sign is finished, obtained signature");
			self.sign_incoming_msg_q.clear();
			return true;
		}
		return false;
	}
}

pub struct DKGState {
	pub accepted: bool,
	pub is_epoch_over: bool,
	pub curr_dkg: Option<MultiPartyECDSASettings>,
	pub past_dkg: Option<MultiPartyECDSASettings>,
}

#[cfg(test)]
mod tests {
	use super::{MultiPartyECDSASettings, Stage};

	fn check_all_finished(parties: &mut Vec<MultiPartyECDSASettings>) -> bool {
		for party in &mut parties.into_iter() {
			match party.stage {
				Stage::SignatureReady => {
					if let Some(_sig) = party.signature.clone() {
						continue;
					}
					panic!("No signature for party {}", party.party_index);
				}
				_ => return false,
			}
		}
		true
	}

	fn run_simulation(parties: &mut Vec<MultiPartyECDSASettings>) {
		println!("Simulation starts");

		let mut msgs_pull = vec![];

		for party in &mut parties.into_iter() {
			party.proceed();

			if let Some(mut msgs) = party.get_outgoing_messages() {
				msgs_pull.append(&mut msgs);
			}
		}

		for party in &mut parties.into_iter() {
			party.try_finish();
		}

		for _i in 1..100 {
			let msgs_pull_frozen = msgs_pull.split_off(0);

			for party in &mut parties.into_iter() {
				party.try_finish();
			}

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

			for party in &mut parties.into_iter() {
				println!("Trying sing for party {}, Stage: {:?}", party.party_index, party.stage);
				match party.try_sign(b"Webb") {
					Ok(()) => (),
					Err(_err) => (),
				}
			}

			if check_all_finished(parties) {
				println!("All parties finished");
				return;
			}
		}

		panic!("Test failed")
	}

	fn simulate_multi_party(t: u16, n: u16) {
		let mut parties: Vec<MultiPartyECDSASettings> = vec![];

		for i in 1..=n {
			parties.push(MultiPartyECDSASettings::new(i, t, n).unwrap());
		}

		run_simulation(&mut parties);
	}

	#[test]
	fn simulate_multi_party_t2_n3() {
		simulate_multi_party(2, 3);
	}

	#[test]
	fn simulate_multi_party_t99_n100() {
		simulate_multi_party(2, 3);
	}
}
