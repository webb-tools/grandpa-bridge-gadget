use bincode;
use codec::{Decode, Encode};
use log::{debug, error, info, trace, warn};
use round_based::{IsCritical, Msg, StateMachine};
use sp_keystore::{Error, SyncCryptoStore};
use std::sync::Arc;

pub use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::{party_i::*, state_machine::keygen::*};

use crate::error::MPCError;
use beefy_primitives::crypto::Public;

#[derive(Debug, Decode, Encode)]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub enum DKGType {
	MultiPartyECDSA,
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

pub struct MultiPartyECDSASettings {
	pub threshold: usize,
	pub parties: usize,
	pub accepted: bool,
	pub party_index: usize,
	pub keygen: Keygen,
	pub local_key: Option<LocalKey>,
}

impl MultiPartyECDSASettings {
	pub fn new(threshold: usize, parties: usize, party_index: usize) -> Result<Self, MPCError> {
		// TODO u16 limit(=65k) is good enough, change type to u16?
		let keygen = Keygen::new(party_index as u16, threshold as u16, parties as u16)?;
		Ok(Self {
			threshold,
			parties,
			party_index,
			accepted: false,
			keygen,
			local_key: None,
		})
	}

	pub fn get_outgoing_message(&mut self) -> Option<&mut Vec<Msg<ProtocolMessage>>> {
		if !self.keygen.message_queue().is_empty() {
			trace!(target: "beefy", "🕸️ message queue len: {}", self.keygen.message_queue().len());
			return Some(self.keygen.message_queue());
		}
		None
	}

	pub fn proceed(&mut self) {
		if self.keygen.wants_to_proceed() {
			trace!(target: "beefy", "🕸️  proceed");
			self.keygen.proceed();
		}
	}

	pub fn handle_incoming(&mut self, data: &[u8]) -> Result<(), MPCError> {
		if data.is_empty() {
			warn!(
				target: "beefy", "🕸️ got empty message");
			return Ok(());
		}
		let msg: Msg<ProtocolMessage> = bincode::deserialize(&data[..]).unwrap();
		if Some(self.keygen.party_ind()) != msg.receiver
			&& (msg.receiver.is_some() || msg.sender == self.keygen.party_ind())
		{
			return Ok(());
		}
		trace!(
			target: "beefy", "🕸️ party {} got message from={}, broadcast={}: {:?}",
			self.keygen.party_ind(),
			msg.sender,
			msg.receiver.is_none(),
			msg.body,
		);
		debug!(target: "beefy", "🕸️ before: {:?}", self.keygen);
		match self.keygen.handle_incoming(msg.clone()) {
			Ok(()) => (),
			Err(err) if err.is_critical() => return Err(MPCError::CryptoOperation(err.to_string())),
			Err(err) => {
				error!(target: "beefy", "🕸️ Non-critical error encountered: {:?}", err);
			}
		}
		debug!(target: "beefy", "🕸️ after : {:?}", self.keygen);
		Ok(())
	}

	/// If protocol is successfully completed, `self.local_key` will have valid value after this call.
	pub fn try_finish(&mut self) {
		if self.keygen.is_finished() {
			match self.keygen.pick_output() {
				Some(Ok(k)) => self.local_key = Some(k),
				Some(Err(e)) => panic!("protocol finished with error result"),
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
