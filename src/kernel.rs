use alloc::collections::BTreeMap;
use casper_types::{EraId, JsonBlockWithSignatures, PublicKey, U512};

use crate::crypto::{verify, SignatureVerificationError};

use super::block_header::BlockHash;

pub struct EraInfo {
    era_id: EraId,
    validator_weights: BTreeMap<PublicKey, U512>,
    total_weight: U512,
}

#[derive(Debug)]
pub enum BlockSignaturesValidationError {
    WrongEraId {
        trusted_era_id: EraId,
        block_header_era_id: EraId,
    },
    BogusValidator(PublicKey),
    SignatureVerificationError(SignatureVerificationError),
    InsufficientWeight {
        bad_signature_weight: U512,
        total_weight: U512,
    },
}

impl From<SignatureVerificationError> for BlockSignaturesValidationError {
    fn from(signature_verification_error: SignatureVerificationError) -> Self {
        BlockSignaturesValidationError::SignatureVerificationError(signature_verification_error)
    }
}

impl EraInfo {
    pub fn new(era_id: EraId, validator_weights: BTreeMap<PublicKey, U512>) -> Self {
        let total_weight = validator_weights
            .values()
            .fold(U512::from(0), |acc, x| acc + x);
        Self {
            era_id,
            validator_weights,
            total_weight,
        }
    }

    pub fn era_id(&self) -> EraId {
        self.era_id
    }

    #[allow(clippy::result_large_err)]
    pub fn validate(
        &self,
        JsonBlockWithSignatures { block, proofs }: JsonBlockWithSignatures,
    ) -> Result<(), BlockSignaturesValidationError> {
        let mut block_signature_weight = U512::from(0);
        if block.era_id() != self.era_id {
            return Err(BlockSignaturesValidationError::WrongEraId {
                trusted_era_id: self.era_id,
                block_header_era_id: block.era_id(),
            });
        }
        // See: https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/node/src/types/block.rs#L2465-L2474
        let mut signature_data = block.hash().inner().into_vec();
        signature_data.extend_from_slice(&block.era_id().to_le_bytes());
        for (public_key, signature) in proofs.iter() {
            if let Some(validator_weight) = self.validator_weights.get(public_key) {
                block_signature_weight += *validator_weight;
            } else {
                return Err(BlockSignaturesValidationError::BogusValidator(
                    public_key.clone(),
                ));
            }
            verify(public_key, &signature_data, signature)?;

            // If the block has `block_signature_weight >= 1/3 * total_weight`, its okay
            if U512::from(3) * block_signature_weight >= self.total_weight {
                return Ok(());
            }
        }
        Err(BlockSignaturesValidationError::InsufficientWeight {
            bad_signature_weight: block_signature_weight,
            total_weight: self.total_weight,
        })
    }
}

pub struct ParentHashAndCurrentHeight {
    parent_hash: BlockHash,
    current_height: u64,
}

impl ParentHashAndCurrentHeight {
    pub fn parent_hash(&self) -> &BlockHash {
        &self.parent_hash
    }

    pub fn current_height(&self) -> u64 {
        self.current_height
    }
}
