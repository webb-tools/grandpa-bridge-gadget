use bincode;
use codec::{Decode, Encode};
use log::{debug, error, info, trace, warn};
use round_based::{IsCritical, Msg, StateMachine};
use sp_keystore::{Error, SyncCryptoStore};
use sp_runtime::traits::{Block, Hash, Header};
use std::sync::Arc;

pub use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::{party_i::*, state_machine::keygen::*, state_machine::sign::*};

use crate::error::MPCError;
use beefy_primitives::crypto::Public;

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

enum Stage {
	Keygen,
	Offline,
	ManualReady,
	ManualProcessing,
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
	pub sing_manual: Option<SignManual>,
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
			sing_manual: None,
		})
	}

	/// Public ///

	pub fn get_outgoing_messages(&mut self, id: &Public) -> Option<Vec<Vec<u8>>> {
		match self.stage {
			Stage::Keygen => self.get_outgoing_messages_keygen(id),
			_ => None
		}
	}

	pub fn proceed(&mut self) {
		match self.stage {
			Stage::Keygen => self.proceed_keygen(),
			_ => return,
		}
	}

	pub fn handle_incoming(&mut self, data: &[u8]) -> Result<(), MPCError> {
		match self.stage {
			Stage::Keygen => self.handle_incoming_keygen(data),
			_ => Ok(()),
		}
	}

	pub fn try_finish(&mut self) {
		match self.stage {
			Stage::Keygen => self.try_finish_keygen(),
			_ => return,
		}
	}

	pub fn is_ready_to_sing(self) -> bool {
		match self.stage {
			Stage::ManualReady => true,
			_ => false,
		}
	}

	/// Internal ///

	/// Get outgoing messages for current Stage

	fn get_outgoing_messages_keygen(&mut self, id: &Public) -> Option<Vec<Vec<u8>>> {
		if !self.keygen.message_queue().is_empty() {
			trace!(target: "webb", "🕸️ outgoing messages, queue len: {}", self.keygen.message_queue().len());

			let enc_messages = self
				.keygen
				.message_queue()
				.into_iter()
				.map(|m| {
					trace!(target: "webb", "🕸️ MPC protocol message {:?}", *m);
					let m_ser = bincode::serialize(m).unwrap();
					let dkg_message = DKGMessage {
						id: id.clone(),
						dkg_type: DKGType::MultiPartyECDSA,
						message: m_ser,
					};
					let encoded_dkg_message = dkg_message.encode();
					debug!(
						target: "webb",
						"🕸️  DKG Message: {:?}, encoded: {:?}",
						dkg_message,
						encoded_dkg_message
					);
					encoded_dkg_message
				})
				.collect::<Vec<Vec<u8>>>();

			self.keygen.message_queue().clear();
			return Some(enc_messages);
		}
		None
	}

	/// Proceed to next step for current Stage

	fn proceed_keygen(&mut self) {
		if self.keygen.wants_to_proceed() {
			info!(target: "webb", "🕸️ Party {} wants to proceed", self.keygen.party_ind());
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
			},
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
	
	/// Try finish current Stage

	fn try_finish_keygen(&mut self) {
		if self.keygen.is_finished() {
			info!(target: "webb", "🕸️ protocol is finished, extracting output");
			match self.keygen.pick_output() {
				Some(Ok(k)) => {
					self.local_key = Some(k);
					info!(target: "webb", "🕸️ local share key is extracted");
				}
				Some(Err(_e)) => panic!("protocol finished with error result"),
				None => panic!("protocol finished with no result"),
			}
		}
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
	use beefy_test::Keyring;
	use log::info;
	use super::{Stage, MultiPartyECDSASettings};

	fn check_all_finished(parties: &mut Vec<MultiPartyECDSASettings>) -> bool {
		for party in &mut parties.into_iter() {
			match party.stage {
				Stage::Offline => continue,
				_ => return false,
			}
		}
		true
	}

	fn run_simulation(parties: &mut Vec<MultiPartyECDSASettings>) {

        info!("Simulation starts");

		let dummy_id = Keyring::Alice.public(); 

        let mut msgs_pull = vec![];

        for party in &mut parties.into_iter() {
			party.proceed();

			if let Some(mut msgs) = party.get_outgoing_messages(&dummy_id.clone()) {
				msgs_pull.append(&mut msgs);
			}
        }

		for party in &mut parties.into_iter() {
			party.try_finish();
        }

        loop {
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

				if let Some(mut msgs) = party.get_outgoing_messages(&dummy_id.clone()) {
					msgs_pull.append(&mut msgs);
				}
            }

            for party in &mut parties.into_iter() {
				party.proceed();

				if let Some(mut msgs) = party.get_outgoing_messages(&dummy_id.clone()) {
					msgs_pull.append(&mut msgs);
				}
            }

            if check_all_finished(parties) {
                return;
            }
        }
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
}
