use alloc::collections::BTreeMap;
use casper_types::{EraId, PublicKey, U512};
use core::option::Option;

use crate::{
    block::BlockHeaderWithSignatures,
    crypto::{verify, SignatureVerificationError},
};

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
        block_header_with_signatures: &BlockHeaderWithSignatures,
    ) -> Result<(), BlockSignaturesValidationError> {
        let mut block_signature_weight = U512::from(0);
        let block_header = block_header_with_signatures.block_header();
        if block_header.era_id() != self.era_id {
            return Err(BlockSignaturesValidationError::WrongEraId {
                trusted_era_id: self.era_id,
                block_header_era_id: block_header_with_signatures.block_header().era_id(),
            });
        }
        // See: https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/node/src/types/block.rs#L2465-L2474
        let mut signature_data = block_header.block_hash().as_ref().to_vec();
        signature_data.extend_from_slice(&block_header.era_id().to_le_bytes());
        for (public_key, signature) in block_header_with_signatures
            .block_signatures()
            .proofs()
            .iter()
        {
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

    #[allow(clippy::result_large_err)]
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
                    if let Some(era_end) = block_header.era_end() {
                        self.era_info = Some(EraInfo::new(
                            block_header.era_id().successor(),
                            era_end.next_era_validator_weights().clone(),
                        ));
                    }
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
                if block_header.height() <= *current_height {
                    Err(LightClientUpdateError::BlockInPastWhenProgressing {
                        bad_block_height: block_header.height(),
                        current_height: *current_height,
                    })
                } else {
                    era_info.validate(block_header_with_signatures)?;
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

    pub fn latest_block_hash(&self) -> &BlockHash {
        &self.latest_block_hash
    }

    pub fn parent_hash_and_current_height(&self) -> Option<&ParentHashAndCurrentHeight> {
        self.parent_hash_and_current_height.as_ref()
    }

    pub fn era_info(&self) -> Option<&EraInfo> {
        self.era_info.as_ref()
    }
}
