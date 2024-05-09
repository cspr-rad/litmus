use alloc::{collections::BTreeMap, vec::Vec};

#[cfg(test)]
use proptest::prelude::*;

use casper_types::{
    bytesrepr::{FromBytes, ToBytes},
    PublicKey, U512,
};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
// See https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/node/src/components/consensus/consensus_protocol.rs#L105-L115
pub struct EraReport {
    pub(crate) equivocators: Vec<PublicKey>,
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
                0..5,
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
pub struct EraEnd {
    pub(crate) era_report: EraReport,
    pub(crate) next_era_validator_weights: BTreeMap<PublicKey, U512>,
}

impl EraEnd {
    pub fn new(
        era_report: EraReport,
        next_era_validator_weights: BTreeMap<PublicKey, U512>,
    ) -> Self {
        EraEnd {
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

#[cfg(test)]
impl Arbitrary for EraEnd {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<EraReport>(),
            proptest::collection::btree_map(
                casper_types::crypto::gens::public_key_arb(),
                any::<u128>().prop_map(U512::from),
                0..5,
            ),
        )
            .prop_map(|(era_report, next_era_validator_weights)| EraEnd {
                era_report,
                next_era_validator_weights,
            })
            .boxed()
    }
}

// See: https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/node/src/types/block.rs#L774-L785
impl ToBytes for EraEnd {
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
impl FromBytes for EraEnd {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), casper_types::bytesrepr::Error> {
        let (era_report, bytes) = EraReport::from_bytes(bytes)?;
        let (next_era_validator_weights, bytes) = BTreeMap::<PublicKey, U512>::from_bytes(bytes)?;
        let era_end = EraEnd {
            era_report,
            next_era_validator_weights,
        };
        Ok((era_end, bytes))
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use casper_types::bytesrepr::{deserialize_from_slice, ToBytes};
    use test_strategy::proptest;

    use super::EraEnd;

    #[proptest]
    fn bytesrepr_era_end_round_trip(era_end: EraEnd) {
        let serialized = era_end.to_bytes().unwrap();
        let deserialized: EraEnd = deserialize_from_slice(&serialized).unwrap();
        assert_eq!(era_end, deserialized)
    }
}
