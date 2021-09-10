use frame_support::weights::Weight;

/// Weight functions needed for this pallet.
pub trait WeightInfo {
	fn burn() -> Weight;
	fn mint() -> Weight;
}

impl WeightInfo for () {
	fn burn() -> Weight { 0 }
	fn mint() -> Weight { 0 }
}
