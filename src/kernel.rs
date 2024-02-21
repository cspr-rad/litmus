use alloc::collections::BTreeMap;
use casper_types::{EraId, PublicKey, Signature, U512};
use core::option::Option;

use crate::{
    block::BlockHeaderWithSignatures,
    crypto::{verify, SignatureVerificationError},
};

use super::block_header::BlockHash;

struct EraInfo {
    era_id: EraId,
    validator_weights: BTreeMap<PublicKey, U512>,
    total_weight: U512,
}

#[derive(Debug)]
pub enum BlockSignaturesValidationError {
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
    fn new(era_id: EraId, validator_weights: BTreeMap<PublicKey, U512>) -> Self {
        let total_weight = validator_weights
            .values()
            .into_iter()
            .fold(U512::from(0), |acc, x| acc + x);
        Self {
            era_id,
            validator_weights,
            total_weight,
        }
    }

    fn era_id(&self) -> &EraId {
        &self.era_id
    }

    fn validate_signatures(
        &self,
        block_hash: &BlockHash,
        block_signatures: &BTreeMap<PublicKey, Signature>,
    ) -> Result<(), BlockSignaturesValidationError> {
        let mut block_signature_weight = U512::from(0);
        for (public_key, signature) in block_signatures.iter() {
            if let Some(validator_weight) = self.validator_weights.get(public_key) {
                block_signature_weight += *validator_weight;
            } else {
                return Err(BlockSignaturesValidationError::BogusValidator(
                    public_key.clone(),
                ));
            }
            verify(public_key, block_hash, signature)?;
        }
        // Check that block_signature_weight >= 2/3 * total_weight
        if U512::from(3) * block_signature_weight < U512::from(2) * self.total_weight {
            return Err(BlockSignaturesValidationError::InsufficientWeight {
                bad_signature_weight: block_signature_weight,
                total_weight: self.total_weight.clone(),
            });
        }
        Ok(())
    }
}

struct ParentHashAndCurrentHeight {
    parent_hash: BlockHash,
    current_height: u64,
}

pub struct LightClientKernel {
    latest_block_hash: BlockHash,
    parent_hash_and_current_height: Option<ParentHashAndCurrentHeight>,
    era_info: Option<EraInfo>,
}

#[derive(Debug)]
pub enum LightClientUpdateError {
    InvalidBlockHashWhenInitializing,
    InvalidBlockHashWhenWalkingBack,
    BlockInPastWhenProgressing {
        bad_block_height: u64,
        current_height: u64,
    },
    WrongEraId {
        bad_era_id: EraId,
        expected_era_id: EraId,
    },
    InvalidSignatures(BlockSignaturesValidationError),
}

impl From<BlockSignaturesValidationError> for LightClientUpdateError {
    fn from(block_signature_validation_error: BlockSignaturesValidationError) -> Self {
        LightClientUpdateError::InvalidSignatures(block_signature_validation_error)
    }
}

impl LightClientKernel {
    pub fn new(latest_block_hash: BlockHash) -> Self {
        LightClientKernel {
            latest_block_hash,
            parent_hash_and_current_height: None,
            era_info: None,
        }
    }

    pub fn update(
        &mut self,
        block_header_with_signatures: &BlockHeaderWithSignatures,
    ) -> Result<(), LightClientUpdateError> {
        let block_header = block_header_with_signatures.block_header();
        match (&self.parent_hash_and_current_height, &self.era_info) {
            // parent_hash_and_current_height are not set, check the latest block has the correct trusted hash and set them
            (None, _) => {
                if self.latest_block_hash == block_header.block_hash() {
                    let parent_hash = block_header.parent_hash().clone();
                    let current_height = block_header.height();
                    self.parent_hash_and_current_height = Some(ParentHashAndCurrentHeight {
                        parent_hash,
                        current_height,
                    });
                    Ok(())
                } else {
                    Err(LightClientUpdateError::InvalidBlockHashWhenInitializing)
                }
            }
            // If the parent_hash_and_current_height are set, but there's no `EraInfo`, then the update effectively walks the light-client back in history by a block.
            // If the block_header_with_metadata has an era_end, use that to set `EraInfo`.
            (
                Some(ParentHashAndCurrentHeight {
                    parent_hash,
                    current_height: _,
                }),
                None,
            ) => {
                if parent_hash == &block_header.block_hash() {
                    self.latest_block_hash = parent_hash.clone();
                    let parent_hash = block_header.parent_hash().clone();
                    let current_height = block_header.height();
                    self.parent_hash_and_current_height = Some(ParentHashAndCurrentHeight {
                        parent_hash,
                        current_height,
                    });
                    if let Some(era_end) = block_header.era_end() {
                        self.era_info = Some(EraInfo::new(
                            block_header.era_id().successor(),
                            era_end.next_era_validator_weights().clone(),
                        ));
                    }
                    Ok(())
                } else {
                    Err(LightClientUpdateError::InvalidBlockHashWhenWalkingBack)
                }
            }
            // If the era_info is set, then the light client progresses by checking if the block is in the current era and has proper finality signatures. If it is and it has a height higher than the kernel, progress the light client.
            (
                Some(ParentHashAndCurrentHeight {
                    parent_hash: _,
                    current_height,
                }),
                Some(era_info),
            ) => {
                if block_header.height() != current_height + 1 {
                    Err(LightClientUpdateError::BlockInPastWhenProgressing {
                        bad_block_height: block_header.height(),
                        current_height: *current_height,
                    })
                } else if block_header.era_id() != era_info.era_id() {
                    Err(LightClientUpdateError::WrongEraId {
                        bad_era_id: block_header.era_id().clone(),
                        expected_era_id: era_info.era_id().clone(),
                    })
                } else {
                    era_info.validate_signatures(
                        &block_header.block_hash(),
                        block_header_with_signatures.block_signatures().proofs(),
                    )?;
                    self.latest_block_hash = block_header.block_hash();
                    self.parent_hash_and_current_height = Some(ParentHashAndCurrentHeight {
                        parent_hash: block_header.parent_hash().clone(),
                        current_height: block_header.height(),
                    });
                    if let Some(era_end) = block_header.era_end() {
                        self.era_info = Some(EraInfo::new(
                            block_header.era_id().successor(),
                            era_end.next_era_validator_weights().clone(),
                        ));
                    }
                    Ok(())
                }
            }
        }
    }
}
