// See https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/node/src/types/block.rs#L2072

use alloc::vec::Vec;

use casper_types::{EraId, ProtocolVersion, PublicKey, Signature, U512};
use serde::{Deserialize, Serialize};

use crate::{
    block::{
        Block, BlockBody, BlockConstructionError, BlockHeaderWithSignatures,
        BlockHeaderWithSignaturesConstructionError, BlockSignatures,
    },
    block_header::{BlockHash, BlockHeader, Timestamp},
    consensus::{EraEnd, EraReport},
    crypto::SignatureVerificationError,
    hash::Digest,
};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Reward {
    validator: PublicKey,
    amount: u64,
}

impl Reward {
    pub fn validator(&self) -> &PublicKey {
        &self.validator
    }

    pub fn amount(&self) -> u64 {
        self.amount
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ValidatorWeight {
    validator: PublicKey,
    weight: U512,
}

impl ValidatorWeight {
    pub fn validator(&self) -> &PublicKey {
        &self.validator
    }

    pub fn weight(&self) -> U512 {
        self.weight
    }
}

/// Equivocation and reward information to be included in the terminal block.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct JsonEraReport {
    equivocators: Vec<PublicKey>,
    rewards: Vec<Reward>,
    inactive_validators: Vec<PublicKey>,
}

impl JsonEraReport {
    pub fn equivocators(&self) -> &Vec<PublicKey> {
        &self.equivocators
    }

    pub fn rewards(&self) -> &Vec<Reward> {
        &self.rewards
    }

    pub fn inactive_validators(&self) -> &Vec<PublicKey> {
        &self.inactive_validators
    }
}

impl From<EraReport> for JsonEraReport {
    fn from(era_report: EraReport) -> Self {
        let EraReport {
            equivocators,
            rewards,
            inactive_validators,
        } = era_report;
        let rewards = rewards
            .into_iter()
            .map(|(validator, amount)| Reward {
                validator: validator,
                amount: amount,
            })
            .collect();
        JsonEraReport {
            equivocators,
            rewards,
            inactive_validators,
        }
    }
}

impl From<JsonEraReport> for EraReport {
    fn from(era_report: JsonEraReport) -> Self {
        let JsonEraReport {
            equivocators,
            rewards,
            inactive_validators,
        } = era_report;
        let rewards = rewards
            .into_iter()
            .map(|reward| (reward.validator, reward.amount))
            .collect();
        EraReport {
            equivocators,
            rewards,
            inactive_validators,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct JsonEraEnd {
    era_report: JsonEraReport,
    next_era_validator_weights: Vec<ValidatorWeight>,
}

impl JsonEraEnd {
    pub fn era_report(&self) -> &JsonEraReport {
        &self.era_report
    }

    pub fn next_era_validator_weights(&self) -> &Vec<ValidatorWeight> {
        &self.next_era_validator_weights
    }
}

impl From<EraEnd> for JsonEraEnd {
    fn from(era_end: EraEnd) -> Self {
        let era_report = JsonEraReport::from(era_end.era_report);
        let next_era_validator_weights = era_end
            .next_era_validator_weights
            .iter()
            .map(|(validator, weight)| ValidatorWeight {
                validator: validator.clone(),
                weight: *weight,
            })
            .collect();
        JsonEraEnd {
            era_report,
            next_era_validator_weights,
        }
    }
}

impl From<JsonEraEnd> for EraEnd {
    fn from(json_data: JsonEraEnd) -> Self {
        let era_report = EraReport::from(json_data.era_report);
        let next_era_validator_weights = json_data
            .next_era_validator_weights
            .iter()
            .map(|validator_weight| (validator_weight.validator.clone(), validator_weight.weight))
            .collect();
        EraEnd {
            era_report,
            next_era_validator_weights,
        }
    }
}

/// JSON representation of a block header.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct JsonBlockHeader {
    parent_hash: BlockHash,
    state_root_hash: Digest,
    body_hash: Digest,
    random_bit: bool,
    accumulated_seed: Digest,
    era_end: Option<JsonEraEnd>,
    timestamp: Timestamp,
    era_id: EraId,
    height: u64,
    protocol_version: ProtocolVersion,
}

impl JsonBlockHeader {
    pub fn parent_hash(&self) -> &BlockHash {
        &self.parent_hash
    }

    pub fn state_root_hash(&self) -> &Digest {
        &self.state_root_hash
    }

    pub fn body_hash(&self) -> &Digest {
        &self.body_hash
    }

    pub fn random_bit(&self) -> bool {
        self.random_bit
    }

    pub fn accumulated_seed(&self) -> &Digest {
        &self.accumulated_seed
    }

    pub fn era_end(&self) -> Option<&JsonEraEnd> {
        self.era_end.as_ref()
    }

    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    pub fn era_id(&self) -> EraId {
        self.era_id
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    pub fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }
}

impl From<BlockHeader> for JsonBlockHeader {
    fn from(block_header: BlockHeader) -> Self {
        JsonBlockHeader {
            parent_hash: block_header.parent_hash().clone(),
            state_root_hash: block_header.state_root_hash().clone(),
            body_hash: block_header.body_hash().clone(),
            random_bit: block_header.random_bit(),
            accumulated_seed: block_header.accumulated_seed().clone(),
            era_end: block_header.era_end().cloned().map(JsonEraEnd::from),
            timestamp: block_header.timestamp(),
            era_id: block_header.era_id(),
            height: block_header.height(),
            protocol_version: block_header.protocol_version(),
        }
    }
}

impl From<JsonBlockHeader> for BlockHeader {
    fn from(block_header: JsonBlockHeader) -> Self {
        let JsonBlockHeader {
            parent_hash,
            state_root_hash,
            body_hash,
            random_bit,
            accumulated_seed,
            era_end,
            timestamp,
            era_id,
            height,
            protocol_version,
        } = block_header;
        let era_end = era_end.map(EraEnd::from);
        BlockHeader::new(
            parent_hash,
            state_root_hash,
            body_hash,
            random_bit,
            accumulated_seed,
            era_end,
            timestamp,
            era_id,
            height,
            protocol_version,
        )
    }
}

/// A JSON-friendly representation of a proof, i.e. a block's finality signature.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct JsonProof {
    public_key: PublicKey,
    signature: Signature,
}

impl JsonProof {
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}

impl From<(PublicKey, Signature)> for JsonProof {
    fn from((public_key, signature): (PublicKey, Signature)) -> JsonProof {
        JsonProof {
            public_key,
            signature,
        }
    }
}

impl From<JsonProof> for (PublicKey, Signature) {
    fn from(proof: JsonProof) -> (PublicKey, Signature) {
        (proof.public_key, proof.signature)
    }
}

/// A JSON-friendly representation of `Block`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct JsonBlock {
    hash: BlockHash,
    header: JsonBlockHeader,
    body: BlockBody,
    proofs: Vec<JsonProof>,
}

impl JsonBlock {
    pub fn hash(&self) -> &BlockHash {
        &self.hash
    }

    pub fn header(&self) -> &JsonBlockHeader {
        &self.header
    }

    pub fn body(&self) -> &BlockBody {
        &self.body
    }

    pub fn proofs(&self) -> &Vec<JsonProof> {
        &self.proofs
    }
}

impl From<Block> for JsonBlock {
    fn from(block: Block) -> Self {
        let hash = block
            .block_header_with_signatures()
            .block_header()
            .block_hash();
        let header =
            JsonBlockHeader::from(block.block_header_with_signatures().block_header().clone());
        let proofs = block
            .block_header_with_signatures()
            .block_signatures()
            .proofs()
            .into_iter()
            .map(|(pubkey, signature)| JsonProof::from((pubkey.clone(), signature.clone())))
            .collect();
        JsonBlock {
            hash,
            header,
            body: block.body().clone(),
            proofs,
        }
    }
}

#[derive(Debug)]
pub enum JsonBlockConversionError {
    InvalidBlockHash {
        block_hash: BlockHash,
        header_hash: BlockHash,
    },
    SignatureVerificationError(SignatureVerificationError),
    BlockHeaderWithSignaturesConstructionError(BlockHeaderWithSignaturesConstructionError),
    BlockConstructionError(BlockConstructionError),
}

impl TryFrom<JsonBlock> for Block {
    type Error = JsonBlockConversionError;

    fn try_from(json_block: JsonBlock) -> Result<Self, Self::Error> {
        let JsonBlock {
            hash: block_hash,
            header,
            body,
            proofs,
        } = json_block;
        let block_header = BlockHeader::from(header);
        let header_hash = block_header.block_hash();
        if block_hash != header_hash {
            return Err(JsonBlockConversionError::InvalidBlockHash {
                block_hash,
                header_hash,
            });
        }
        let block_signatures = BlockSignatures::new(
            header_hash,
            block_header.era_id(),
            proofs
                .into_iter()
                .map(|proof| (proof.public_key, proof.signature))
                .collect(),
        )
        .map_err(JsonBlockConversionError::SignatureVerificationError)?;
        let header = BlockHeaderWithSignatures::new(block_header, block_signatures)
            .map_err(JsonBlockConversionError::BlockHeaderWithSignaturesConstructionError)?;
        Ok(Block::new(header, body).map_err(JsonBlockConversionError::BlockConstructionError)?)
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use test_strategy::proptest;

    use crate::{
        block_header::BlockHeader,
        consensus::{EraEnd, EraReport},
    };

    use super::{JsonBlockHeader, JsonEraEnd, JsonEraReport};

    #[proptest]
    fn era_report_round_trip(era_report: EraReport) {
        let json_era_report = JsonEraReport::from(era_report.clone());
        let round_trip_era_report = EraReport::from(json_era_report);
        assert_eq!(era_report, round_trip_era_report);
    }

    #[proptest]
    fn era_end_round_trip(era_end: EraEnd) {
        let json_era_end = JsonEraEnd::from(era_end.clone());
        let round_trip_era_end = EraEnd::from(json_era_end);
        assert_eq!(era_end, round_trip_era_end);
    }

    #[proptest]
    fn block_header_round_trip(block_header: BlockHeader) {
        let json_block_header = JsonBlockHeader::from(block_header.clone());
        let round_trip_block_header = BlockHeader::from(json_block_header);
        assert_eq!(block_header, round_trip_block_header);
    }
}
