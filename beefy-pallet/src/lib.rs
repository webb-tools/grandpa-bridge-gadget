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

#![cfg_attr(not(feature = "std"), no_std)]

use codec::Encode;

use frame_support::{traits::OneSessionHandler, Parameter};

use core::convert::TryFrom;
use sp_runtime::{
	generic::DigestItem,
	traits::{IsMember, Member},
	RuntimeAppPublic,
};
use sp_std::prelude::*;

use beefy_primitives::{AuthorityIndex, ConsensusLog, ValidatorSet, BEEFY_ENGINE_ID};

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// Authority identifier type
		type BeefyId: Member + Parameter + RuntimeAppPublic + Default + MaybeSerializeDeserialize;
	}

	#[pallet::pallet]
	pub struct Pallet<T>(PhantomData<T>);

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::weight(0)]
		pub fn set_threshold(origin: OriginFor<T>, new_threshold: u16) -> DispatchResultWithPostInfo {
			ensure_root(origin)?;
			ensure!(
				usize::from(new_threshold) <= Authorities::<T>::get().len(),
				Error::<T>::InvalidThreshold
			);
			// set the new maintainer
			SignatureThreshold::<T>::try_mutate(|threshold| {
				*threshold = new_threshold.clone();
				Ok(().into())
			})
		}
	}

	/// The current signature threshold (i.e. the `t` in t-of-n)
	#[pallet::storage]
	#[pallet::getter(fn signature_threshold)]
	pub(super) type SignatureThreshold<T: Config> = StorageValue<_, u16, ValueQuery>;

	/// The current authorities set
	#[pallet::storage]
	#[pallet::getter(fn authorities)]
	pub(super) type Authorities<T: Config> = StorageValue<_, Vec<T::BeefyId>, ValueQuery>;

	/// The current validator set id
	#[pallet::storage]
	#[pallet::getter(fn validator_set_id)]
	pub(super) type ValidatorSetId<T: Config> = StorageValue<_, beefy_primitives::ValidatorSetId, ValueQuery>;

	/// Authorities set scheduled to be used with the next session
	#[pallet::storage]
	#[pallet::getter(fn next_authorities)]
	pub(super) type NextAuthorities<T: Config> = StorageValue<_, Vec<T::BeefyId>, ValueQuery>;

	#[pallet::genesis_config]
	pub struct GenesisConfig<T: Config> {
		pub authorities: Vec<T::BeefyId>,
		pub threshold: u32,
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Invalid threshold
		InvalidThreshold,
	}

	#[cfg(feature = "std")]
	impl<T: Config> Default for GenesisConfig<T> {
		fn default() -> Self {
			Self {
				authorities: Vec::new(),
				threshold: 0,
			}
		}
	}

	#[pallet::genesis_build]
	impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
		fn build(&self) {
			Pallet::<T>::initialize_authorities(&self.authorities);
			let sig_threshold = u16::try_from(self.authorities.len() / 2).unwrap() + 1;
			SignatureThreshold::<T>::put(sig_threshold);
		}
	}
}

impl<T: Config> Pallet<T> {
	/// Return the current active BEEFY validator set.
	pub fn validator_set() -> ValidatorSet<T::BeefyId> {
		ValidatorSet::<T::BeefyId> {
			validators: Self::authorities(),
			id: Self::validator_set_id(),
		}
	}

	pub fn sig_threshold() -> u16 {
		Self::signature_threshold()
	}

	fn change_authorities(new: Vec<T::BeefyId>, queued: Vec<T::BeefyId>) {
		// As in GRANDPA, we trigger a validator set change only if the the validator
		// set has actually changed.
		if new != Self::authorities() {
			<Authorities<T>>::put(&new);

			let next_id = Self::validator_set_id() + 1u64;
			<ValidatorSetId<T>>::put(next_id);

			let log: DigestItem<T::Hash> = DigestItem::Consensus(
				BEEFY_ENGINE_ID,
				ConsensusLog::AuthoritiesChange(ValidatorSet {
					validators: new,
					id: next_id,
				})
				.encode(),
			);
			<frame_system::Pallet<T>>::deposit_log(log);
		}

		<NextAuthorities<T>>::put(&queued);
	}

	fn initialize_authorities(authorities: &[T::BeefyId]) {
		if authorities.is_empty() {
			return;
		}

		assert!(
			<Authorities<T>>::get().is_empty(),
			"Authorities are already initialized!"
		);

		<Authorities<T>>::put(authorities);
		<ValidatorSetId<T>>::put(0);
		// Like `pallet_session`, initialize the next validator set as well.
		<NextAuthorities<T>>::put(authorities);
	}
}

impl<T: Config> sp_runtime::BoundToRuntimeAppPublic for Pallet<T> {
	type Public = T::BeefyId;
}

impl<T: Config> OneSessionHandler<T::AccountId> for Pallet<T> {
	type Key = T::BeefyId;

	fn on_genesis_session<'a, I: 'a>(validators: I)
	where
		I: Iterator<Item = (&'a T::AccountId, T::BeefyId)>,
	{
		let authorities = validators.map(|(_, k)| k).collect::<Vec<_>>();
		Self::initialize_authorities(&authorities);
	}

	fn on_new_session<'a, I: 'a>(changed: bool, validators: I, queued_validators: I)
	where
		I: Iterator<Item = (&'a T::AccountId, T::BeefyId)>,
	{
		if changed {
			let next_authorities = validators.map(|(_, k)| k).collect::<Vec<_>>();
			let next_queued_authorities = queued_validators.map(|(_, k)| k).collect::<Vec<_>>();

			Self::change_authorities(next_authorities, next_queued_authorities);
		}
	}

	fn on_disabled(i: usize) {
		let log: DigestItem<T::Hash> = DigestItem::Consensus(
			BEEFY_ENGINE_ID,
			ConsensusLog::<T::BeefyId>::OnDisabled(i as AuthorityIndex).encode(),
		);

		<frame_system::Pallet<T>>::deposit_log(log);
	}
}

impl<T: Config> IsMember<T::BeefyId> for Pallet<T> {
	fn is_member(authority_id: &T::BeefyId) -> bool {
		Self::authorities().iter().any(|id| id == authority_id)
	}
}
