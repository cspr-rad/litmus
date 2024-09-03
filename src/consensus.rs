use alloc::{collections::BTreeMap, vec::Vec};

#[cfg(test)]
use proptest::prelude::*;

use casper_types::{
    bytesrepr::{self, FromBytes, ToBytes},
    PublicKey, U512,
};

#[cfg(test)]
use serde_map_to_array::BTreeMapToArray;
use serde_map_to_array::KeyValueLabels;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
// See https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/node/src/components/consensus/consensus_protocol.rs#L105-L115
pub struct EraReport {
    pub(crate) equivocators: Vec<PublicKey>,
    #[cfg_attr(
        test,
        serde(with = "BTreeMapToArray::<PublicKey, u64, EraRewardsLabels>")
    )]
    pub(crate) rewards: BTreeMap<PublicKey, u64>,
    pub(crate) inactive_validators: Vec<PublicKey>,
}

impl EraReport {
    pub fn new(
        equivocators: Vec<PublicKey>,
        rewards: BTreeMap<PublicKey, u64>,
        inactive_validators: Vec<PublicKey>,
    ) -> Self {
        EraReport {
            equivocators,
            rewards,
            inactive_validators,
        }
    }

    pub fn equivocators(&self) -> &Vec<PublicKey> {
        &self.equivocators
    }

    pub fn rewards(&self) -> &BTreeMap<PublicKey, u64> {
        &self.rewards
    }

    pub fn inactive_validators(&self) -> &Vec<PublicKey> {
        &self.inactive_validators
    }
}

#[cfg(test)]
impl Arbitrary for EraReport {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            proptest::collection::vec(casper_types::crypto::gens::public_key_arb(), 0..5),
            proptest::collection::btree_map(
                casper_types::crypto::gens::public_key_arb(),
                any::<u64>(),
                // Must have at least one reward or deserialization will fail.
                1..5,
            ),
            proptest::collection::vec(casper_types::crypto::gens::public_key_arb(), 0..5),
        )
            .prop_map(|(equivocators, rewards, inactive_validators)| EraReport {
                equivocators,
                rewards,
                inactive_validators,
            })
            .boxed()
    }
}

// See: https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/node/src/types/block.rs#L390-L404
impl ToBytes for EraReport {
    fn to_bytes(&self) -> Result<Vec<u8>, casper_types::bytesrepr::Error> {
        let mut buffer = casper_types::bytesrepr::allocate_buffer(self)?;
        buffer.extend(self.equivocators.to_bytes()?);
        buffer.extend(self.rewards.to_bytes()?);
        buffer.extend(self.inactive_validators.to_bytes()?);
        Ok(buffer)
    }

    fn serialized_length(&self) -> usize {
        self.equivocators.serialized_length()
            + self.rewards.serialized_length()
            + self.inactive_validators.serialized_length()
    }
}

// See: https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/node/src/types/block.rs#L406-L419
impl FromBytes for EraReport {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), casper_types::bytesrepr::Error> {
        let (equivocators, remainder) = Vec::<PublicKey>::from_bytes(bytes)?;
        let (rewards, remainder) = BTreeMap::<PublicKey, u64>::from_bytes(remainder)?;
        let (inactive_validators, remainder) = Vec::<PublicKey>::from_bytes(remainder)?;

        let era_report = EraReport {
            equivocators,
            rewards,
            inactive_validators,
        };
        Ok((era_report, remainder))
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
// See: https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/node/src/types/block.rs#L748-L753
pub struct EraEndV1 {
    pub(crate) era_report: EraReport,
    #[cfg_attr(
        test,
        serde(with = "BTreeMapToArray::<PublicKey, U512, NextEraValidatorLabels>")
    )]
    pub(crate) next_era_validator_weights: BTreeMap<PublicKey, U512>,
}

impl EraEndV1 {
    pub fn new(
        era_report: EraReport,
        next_era_validator_weights: BTreeMap<PublicKey, U512>,
    ) -> Self {
        EraEndV1 {
            era_report,
            next_era_validator_weights,
        }
    }

    pub fn era_report(&self) -> &EraReport {
        &self.era_report
    }

    pub fn next_era_validator_weights(&self) -> &BTreeMap<PublicKey, U512> {
        &self.next_era_validator_weights
    }
}

pub struct NextEraValidatorLabels;

impl KeyValueLabels for NextEraValidatorLabels {
    const KEY: &'static str = "validator";
    const VALUE: &'static str = "weight";
}

#[cfg(test)]
impl Arbitrary for EraEndV1 {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<EraReport>(),
            proptest::collection::btree_map(
                casper_types::crypto::gens::public_key_arb(),
                any::<u128>().prop_map(U512::from),
                // Must have at least one validator or deserialization will fail.
                1..5,
            ),
        )
            .prop_map(|(era_report, next_era_validator_weights)| EraEndV1 {
                era_report,
                next_era_validator_weights,
            })
            .boxed()
    }
}

// See: https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/node/src/types/block.rs#L774-L785
impl ToBytes for EraEndV1 {
    fn to_bytes(&self) -> Result<Vec<u8>, casper_types::bytesrepr::Error> {
        let mut buffer = casper_types::bytesrepr::allocate_buffer(self)?;
        buffer.extend(self.era_report.to_bytes()?);
        buffer.extend(self.next_era_validator_weights.to_bytes()?);
        Ok(buffer)
    }

    fn serialized_length(&self) -> usize {
        self.era_report.serialized_length() + self.next_era_validator_weights.serialized_length()
    }
}

// See: https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/node/src/types/block.rs#L787-L797
impl FromBytes for EraEndV1 {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), casper_types::bytesrepr::Error> {
        let (era_report, bytes) = EraReport::from_bytes(bytes)?;
        let (next_era_validator_weights, bytes) = BTreeMap::<PublicKey, U512>::from_bytes(bytes)?;
        let era_end = EraEndV1 {
            era_report,
            next_era_validator_weights,
        };
        Ok((era_end, bytes))
    }
}

pub struct EraRewardsLabels;

impl KeyValueLabels for EraRewardsLabels {
    const KEY: &'static str = "validator";
    const VALUE: &'static str = "amount";
}

/// Information related to the end of an era, and validator weights for the following era.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct EraEndV2 {
    /// The set of equivocators.
    pub equivocators: Vec<PublicKey>,
    /// Validators that haven't produced any unit during the era.
    pub inactive_validators: Vec<PublicKey>,
    /// The validators for the upcoming era and their respective weights.
    #[cfg_attr(
        test,
        serde(with = "BTreeMapToArray::<PublicKey, U512, NextEraValidatorLabels>")
    )]
    pub next_era_validator_weights: BTreeMap<PublicKey, U512>,
    /// The rewards distributed to the validators.
    pub rewards: BTreeMap<PublicKey, Vec<U512>>,
    pub next_era_gas_price: u8,
}

impl ToBytes for EraEndV2 {
    fn write_bytes(&self, writer: &mut Vec<u8>) -> Result<(), bytesrepr::Error> {
        let EraEndV2 {
            equivocators,
            inactive_validators,
            next_era_validator_weights,
            rewards,
            next_era_gas_price,
        } = self;

        equivocators.write_bytes(writer)?;
        inactive_validators.write_bytes(writer)?;
        next_era_validator_weights.write_bytes(writer)?;
        rewards.write_bytes(writer)?;
        next_era_gas_price.write_bytes(writer)?;

        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut buffer = bytesrepr::allocate_buffer(self)?;
        self.write_bytes(&mut buffer)?;
        Ok(buffer)
    }

    fn serialized_length(&self) -> usize {
        let EraEndV2 {
            equivocators,
            inactive_validators,
            next_era_validator_weights,
            rewards,
            next_era_gas_price,
        } = self;

        equivocators.serialized_length()
            + inactive_validators.serialized_length()
            + next_era_validator_weights.serialized_length()
            + rewards.serialized_length()
            + next_era_gas_price.serialized_length()
    }
}

impl FromBytes for EraEndV2 {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (equivocators, bytes) = Vec::from_bytes(bytes)?;
        let (inactive_validators, bytes) = Vec::from_bytes(bytes)?;
        let (next_era_validator_weights, bytes) = BTreeMap::from_bytes(bytes)?;
        let (rewards, bytes) = BTreeMap::from_bytes(bytes)?;
        let (next_era_gas_price, bytes) = u8::from_bytes(bytes)?;
        let era_end = EraEndV2 {
            equivocators,
            inactive_validators,
            next_era_validator_weights,
            rewards,
            next_era_gas_price,
        };

        Ok((era_end, bytes))
    }
}

#[cfg(test)]
impl Arbitrary for EraEndV2 {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            proptest::collection::vec(casper_types::crypto::gens::public_key_arb(), 0..5),
            proptest::collection::vec(casper_types::crypto::gens::public_key_arb(), 0..5),
            proptest::collection::btree_map(
                casper_types::crypto::gens::public_key_arb(),
                any::<u128>().prop_map(U512::from),
                1..5,
            ),
            proptest::collection::btree_map(
                casper_types::crypto::gens::public_key_arb(),
                proptest::collection::vec(any::<u128>().prop_map(U512::from), 1..5),
                1..5,
            ),
            any::<u8>(),
        )
            .prop_map(
                |(
                    equivocators,
                    inactive_validators,
                    next_era_validator_weights,
                    rewards,
                    next_era_gas_price,
                )| EraEndV2 {
                    equivocators,
                    inactive_validators,
                    next_era_validator_weights,
                    rewards,
                    next_era_gas_price,
                },
            )
            .boxed()
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use casper_types::bytesrepr::{deserialize_from_slice, ToBytes};
    use test_strategy::proptest;

    use super::EraEndV1;

    #[proptest]
    fn bytesrepr_era_end_v1_round_trip(era_end: EraEndV1) {
        let serialized = era_end.to_bytes().unwrap();
        let deserialized: EraEndV1 = deserialize_from_slice(&serialized).unwrap();
        assert_eq!(era_end, deserialized)
    }

    #[proptest]
    fn bytesrepr_era_end_v2_round_trip(era_end: super::EraEndV2) {
        let serialized = era_end.to_bytes().unwrap();
        let deserialized: super::EraEndV2 = deserialize_from_slice(&serialized).unwrap();
        assert_eq!(era_end, deserialized)
    }
}
