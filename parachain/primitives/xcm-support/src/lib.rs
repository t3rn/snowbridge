//! # XCMP Support
//!
//! Includes an implementation for the `TransactAsset` trait, thus enabling
//! withdrawals and deposits to assets via XCMP message execution.

#![cfg_attr(not(feature = "std"), no_std)]

use sp_core::{H160, U256};
use sp_std::{result, marker::PhantomData, prelude::*};
use codec::{Encode, Decode};

use xcm::v0::{Error as XcmError, Junction, MultiAsset, MultiLocation, Result as XcmResult};
use xcm_executor::traits::{Convert, TransactAsset};

use snowbridge_core::assets::{AssetId, MultiAsset as SnowbridgeMultiAsset};

// MultiLocation for wrapped ether
fn make_ether_location() -> MultiLocation {
	let asset_id = AssetId::ETH;
	MultiLocation::X3(
		Junction::Parent,
		Junction::Parachain(1000),
		Junction::GeneralKey(asset_id.encode())
	)
}

// MultiLocation for wrapped tokens (ERC20, ERC777, etc)
fn make_erc20_location()-> MultiLocation {
	let token_contract_address = H160::from(hex!["dAC17F958D2ee523a2206206994597C13D831ec7"]);
	let asset_id = AssetId::Token(token_contract_address);
	MultiLocation::X3(
		Junction::Parent,
		Junction::Parachain(1000),
		Junction::GeneralKey(asset_id.encode())
	)
}


pub struct AssetsTransactor<Assets, AccountIdConverter, AccountId>(
	PhantomData<(Assets, AccountIdConverter, AccountId)>,
);

impl<
		Assets: SnowbridgeMultiAsset<AccountId>,
		AccountIdConverter: Convert<MultiLocation, AccountId>,
		AccountId: Clone,
	> AssetsTransactor<Assets, AccountIdConverter, AccountId> {
	fn match_assets(a: &MultiAsset) -> result::Result<(AssetId, U256), XcmError> {
		let (id, amount) = match a {
			MultiAsset::ConcreteFungible { id, amount } => (id, amount),
			_ => return Err(XcmError::AssetNotFound),
		};

		let key = match id.last() {
			Some(Junction::GeneralKey(key)) => key,
			_ => return Err(XcmError::AssetNotFound),
		};

		let asset_id: AssetId = AssetId::decode(&mut key.as_ref())
			.map_err(|_| XcmError::FailedToTransactAsset("AssetIdConversionFailed"))?;

		let value: U256 = (*amount).into();

		Ok((asset_id, value))
	}
}

impl<
		Assets: SnowbridgeMultiAsset<AccountId>,
		AccountIdConverter: Convert<MultiLocation, AccountId>,
		AccountId: Clone,
	> TransactAsset for AssetsTransactor<Assets, AccountIdConverter, AccountId>
{
	fn deposit_asset(asset: &MultiAsset, location: &MultiLocation) -> XcmResult {
		let (asset_id, amount) = Self::match_assets(asset)?;
		let who = AccountIdConverter::convert_ref(location)
			.map_err(|()| XcmError::FailedToTransactAsset("AccountIdConversionFailed"))?;
		Assets::deposit(asset_id, &who, amount)
			.map_err(|e| XcmError::FailedToTransactAsset(e.into()))?;
		return Ok(())
	}

	fn withdraw_asset(
		asset: &MultiAsset,
		location: &MultiLocation,
	) -> Result<xcm_executor::Assets, XcmError> {
		let (asset_id, amount) = Self::match_assets(asset)?;
		let who = AccountIdConverter::convert_ref(location)
			.map_err(|()| XcmError::FailedToTransactAsset("AccountIdConversionFailed"))?;
		Assets::withdraw(asset_id, &who, amount)
			.map_err(|e| XcmError::FailedToTransactAsset(e.into()))?;
		Ok(asset.clone().into())
	}
}
