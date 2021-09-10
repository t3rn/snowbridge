#![cfg_attr(not(feature = "std"), no_std)]

mod payload;
mod benchmarking;
pub mod weights;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

use frame_system::ensure_signed;
use frame_support::{
	dispatch::{DispatchError, DispatchResult},
	traits::{
		EnsureOrigin,
		tokens::{
			fungible
		}
	},
	transactional,
};
use sp_runtime::traits::StaticLookup;
use sp_std::prelude::*;
use sp_core::{H160, U256};

use codec::{Encode, Decode, EncodeLike, MaxEncodedLen};

use snowbridge_core::{ChannelId, OutboundRouter};

pub use weights::WeightInfo;
use payload::OutboundPayload;

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {

	use super::*;

	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
use sp_runtime::traits::AtLeast32BitUnsigned;

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

		type Balance: AtLeast32BitUnsigned + Encode + Decode + EncodeLike + Copy + Default + Debug + MaxEncodedLen;

		type Asset: fungible::Mutate<Self::AccountId>;

		type OutboundRouter: OutboundRouter<Self::AccountId>;

		type CallOrigin: EnsureOrigin<Self::Origin, Success=H160>;

		type WeightInfo: WeightInfo;
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> { }

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	#[pallet::metadata(T::AccountId = "AccountId")]
	pub enum Event<T: Config> {
		Burned(T::AccountId, H160, U256),
		Minted(H160, T::AccountId, U256),
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The submitted payload could not be decoded.
		InvalidPayload,
	}

	/// Address of the peer application on the Ethereum side.
	#[pallet::storage]
	#[pallet::getter(fn address)]
	pub(super) type Address<T: Config> = StorageValue<_, H160, ValueQuery>;

	#[pallet::genesis_config]
	pub struct GenesisConfig<T> {
		pub address: H160,
		pub phantom: sp_std::marker::PhantomData<T>,
	}

	#[cfg(feature = "std")]
	impl<T: Config> Default for GenesisConfig<T> {
		fn default() -> Self {
			Self {
				address: Default::default(),
				phantom: Default::default(),
			}
		}
	}

	#[pallet::genesis_build]
	impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
		fn build(&self) {
			<Address<T>>::put(self.address);
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {

		#[pallet::weight(T::WeightInfo::burn())]
		#[transactional]
		pub fn burn(
			origin: OriginFor<T>,
			channel_id: ChannelId,
			recipient: H160,
			amount: u128
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			T::Asset::burn_from(&who, amount)?;

			let message = OutboundPayload {
				sender: who.clone(),
				recipient: recipient.clone(),
				amount: amount
			};

			T::OutboundRouter::submit(channel_id, &who, <Address<T>>::get(), &message.encode())?;
			Self::deposit_event(Event::Burned(who.clone(), recipient, amount));

			Ok(())
		}

		#[pallet::weight(T::WeightInfo::mint())]
		#[transactional]
		pub fn mint(
			origin: OriginFor<T>,
			sender: H160,
			recipient: <T::Lookup as StaticLookup>::Source,
			amount: U256
		) -> DispatchResult {
			let who = T::CallOrigin::ensure_origin(origin)?;
			if who != <Address<T>>::get() {
				return Err(DispatchError::BadOrigin.into());
			}

			let recipient = T::Lookup::lookup(recipient)?;
			T::Asset::deposit(&recipient, amount)?;
			Self::deposit_event(Event::Minted(sender, recipient.clone(), amount));

			Ok(())
		}

	}

}
