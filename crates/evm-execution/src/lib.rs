// Copyright 2019-2022 Unique Network (Gibraltar) Ltd.
// This file is part of Unique Network.

// Unique Network is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Unique Network is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Unique Network. If not, see <http://www.gnu.org/licenses/>.

#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::{String, ToString};
use evm_core::{ExitError, ExitFatal};
#[cfg(feature = "std")]
use std::string::{String, ToString};

pub mod abi;

pub type Weight = u64;

/// Solidity type definitions
pub mod types {
	#![allow(non_camel_case_types)]

	#[cfg(not(feature = "std"))]
	use alloc::{vec::Vec};
	use primitive_types::{U256, H160, H256};

	pub type address = H160;

	pub type uint8 = u8;
	pub type uint16 = u16;
	pub type uint32 = u32;
	pub type uint64 = u64;
	pub type uint128 = u128;
	pub type uint256 = U256;

	pub type bytes4 = [u8; 4];

	pub type topic = H256;

	#[cfg(not(feature = "std"))]
	pub type string = ::alloc::string::String;
	#[cfg(feature = "std")]
	pub type string = ::std::string::String;
	pub type bytes = Vec<u8>;

	pub type void = ();

	//#region Special types
	/// Makes function payable
	pub type value = U256;
	/// Makes function caller-sensitive
	pub type caller = address;
	//#endregion

	pub struct Msg<C> {
		pub call: C,
		pub caller: H160,
		pub value: U256,
	}
}

#[derive(Debug, Clone)]
pub enum Error {
	Revert(String),
	Fatal(ExitFatal),
	Error(ExitError),
}

impl<E> From<E> for Error
where
	E: ToString,
{
	fn from(e: E) -> Self {
		Self::Revert(e.to_string())
	}
}

pub type Result<T> = core::result::Result<T, Error>;

pub struct DispatchInfo {
	pub weight: Weight,
}

impl From<Weight> for DispatchInfo {
	fn from(weight: Weight) -> Self {
		Self { weight }
	}
}
impl From<()> for DispatchInfo {
	fn from(_: ()) -> Self {
		Self { weight: 0 }
	}
}

#[derive(Default, Clone)]
pub struct PostDispatchInfo {
	actual_weight: Option<Weight>,
}

impl PostDispatchInfo {
	pub fn calc_unspent(&self, info: &DispatchInfo) -> Weight {
		info.weight - self.calc_actual_weight(info)
	}

	pub fn calc_actual_weight(&self, info: &DispatchInfo) -> Weight {
		if let Some(actual_weight) = self.actual_weight {
			actual_weight.min(info.weight)
		} else {
			info.weight
		}
	}
}

#[derive(Clone)]
pub struct WithPostDispatchInfo<T> {
	pub data: T,
	pub post_info: PostDispatchInfo,
}

impl<T> From<T> for WithPostDispatchInfo<T> {
	fn from(data: T) -> Self {
		Self {
			data,
			post_info: Default::default(),
		}
	}
}

pub type ResultWithPostInfo<T> =
	core::result::Result<WithPostDispatchInfo<T>, WithPostDispatchInfo<Error>>;
