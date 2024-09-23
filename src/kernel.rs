use casper_types::{BlockBody, EraId, JsonBlockWithSignatures, PublicKey, U512};
use std::collections::BTreeMap;

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
    SignatureVerificationError,
    BlockHashMismatch,
    BlockBodyHashMismatch,
    InsufficientWeight {
        bad_signature_weight: U512,
        total_weight: U512,
    },
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

        let block_header = block.clone_header();
        let block_body = block.clone_body();

        // The OnceCell in these will not be initialized prior to calling these hash
        // methods since the `OnceCell` is not serialized upstream.
        let computed_block_hash = block_header.block_hash();
        let computed_block_body_hash = match block_body {
            BlockBody::V1(block_body_v1) => block_body_v1.hash(),
            BlockBody::V2(block_body_v2) => block_body_v2.hash(),
        };

        let claimed_block_hash = block.hash();
        let claimed_block_body_hash = block.body_hash();

        if computed_block_hash != *claimed_block_hash {
            return Err(BlockSignaturesValidationError::BlockHashMismatch);
        }

        if computed_block_body_hash != *claimed_block_body_hash {
            return Err(BlockSignaturesValidationError::BlockBodyHashMismatch);
        }

        // See: https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/node/src/types/block.rs#L2465-L2474
        let mut signature_data = computed_block_hash.inner().into_vec();

        signature_data.extend_from_slice(&block.era_id().to_le_bytes());
        for (public_key, signature) in proofs.iter() {
            if let Some(validator_weight) = self.validator_weights.get(public_key) {
                block_signature_weight += *validator_weight;
            } else {
                return Err(BlockSignaturesValidationError::BogusValidator(
                    public_key.clone(),
                ));
            }
            casper_types::verify(&signature_data, signature, public_key)
                .map_err(|_| BlockSignaturesValidationError::SignatureVerificationError)?;

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
