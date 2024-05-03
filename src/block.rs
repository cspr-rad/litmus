use alloc::{collections::BTreeMap, vec::Vec};

#[cfg(test)]
use casper_types::{crypto::gens::public_key_arb, SecretKey};
#[cfg(test)]
use proptest::prelude::*;

use casper_types::{
    bytesrepr::{FromBytes, ToBytes},
    EraId, PublicKey, Signature,
};

use super::{
    block_header::{BlockHash, BlockHeader},
    crypto::{verify, SignatureVerificationError},
    hash::Digest,
};

#[derive(Clone, Debug, PartialOrd, Ord, Eq, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
// See: https://github.com/casper-network/casper-node/blob/edc4b45ea05526ba6dd7971da09e27754a37a230/node/src/types/block.rs#L1324-L1332
pub struct BlockSignatures {
    block_hash: BlockHash,
    era_id: EraId,
    proofs: BTreeMap<PublicKey, Signature>,
}

impl BlockSignatures {
    pub fn new(
        block_hash: BlockHash,
        era_id: EraId,
        proofs: BTreeMap<PublicKey, Signature>,
    ) -> Result<Self, SignatureVerificationError> {
        let mut signature_data = block_hash.as_ref().to_vec();
        signature_data.extend_from_slice(&era_id.to_le_bytes());
        for (public_key, signature) in &proofs {
            verify(public_key, &signature_data, signature)?;
        }
        Ok(BlockSignatures {
            block_hash,
            era_id,
            proofs,
        })
    }

    pub fn block_hash(&self) -> &BlockHash {
        &self.block_hash
    }

    pub fn era_id(&self) -> EraId {
        self.era_id
    }

    pub fn proofs(&self) -> &BTreeMap<PublicKey, Signature> {
        &self.proofs
    }
}

#[cfg(test)]
impl Arbitrary for BlockSignatures {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<BlockHash>(),
            any::<u64>(), // EraId
            prop::collection::vec(
                prop_oneof![
                    any::<[u8; SecretKey::ED25519_LENGTH]>()
                        .prop_map(|bytes| SecretKey::ed25519_from_bytes(bytes).unwrap()),
                    any::<[u8; SecretKey::SECP256K1_LENGTH]>()
                        .prop_filter("Cannot make a secret key from [0u8; 32]", |bytes| bytes
                            != &[0u8; SecretKey::SECP256K1_LENGTH])
                        .prop_map(|bytes| SecretKey::secp256k1_from_bytes(bytes).unwrap()),
                ],
                0..5,
            ),
        )
            .prop_map(|(block_hash, era_id, proofs)| {
                let era_id = EraId::from(era_id);
                let mut signature_data = block_hash.as_ref().to_vec();
                signature_data.extend_from_slice(&era_id.to_le_bytes());
                let proofs = proofs
                    .into_iter()
                    .map(|secret_key| {
                        let public_key = PublicKey::from(&secret_key);
                        let signature = crate::crypto::sign(&secret_key, &signature_data);
                        (public_key, signature)
                    })
                    .collect();
                BlockSignatures {
                    block_hash,
                    era_id,
                    proofs,
                }
            })
            .boxed()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
// See: https://github.com/casper-network/casper-node/blob/edc4b45ea05526ba6dd7971da09e27754a37a230/node/src/types/block.rs#L1184-L1188
pub struct BlockHeaderWithSignatures {
    block_header: BlockHeader,
    block_signatures: BlockSignatures,
}

#[derive(Debug)]
pub enum BlockHeaderWithSignaturesConstructionError {
    InvalidEraId {
        header_era_id: EraId,
        signatures_era_id: EraId,
    },
    InvalidBlockHash {
        header_block_hash: BlockHash,
        signatures_block_hash: BlockHash,
    },
}

impl BlockHeaderWithSignatures {
    pub fn new(
        block_header: BlockHeader,
        block_signatures: BlockSignatures,
    ) -> Result<Self, BlockHeaderWithSignaturesConstructionError> {
        if block_header.era_id() != block_signatures.era_id() {
            return Err(BlockHeaderWithSignaturesConstructionError::InvalidEraId {
                header_era_id: block_header.era_id().clone(),
                signatures_era_id: block_signatures.era_id(),
            });
        }
        let header_block_hash = block_header.block_hash();
        if block_signatures.block_hash() != &header_block_hash {
            return Err(
                BlockHeaderWithSignaturesConstructionError::InvalidBlockHash {
                    header_block_hash,
                    signatures_block_hash: block_signatures.block_hash().clone(),
                },
            );
        }
        Ok(BlockHeaderWithSignatures {
            block_header,
            block_signatures,
        })
    }

    pub fn block_header(&self) -> &BlockHeader {
        &self.block_header
    }

    pub fn block_signatures(&self) -> &BlockSignatures {
        &self.block_signatures
    }
}

#[cfg(test)]
impl Arbitrary for BlockHeaderWithSignatures {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<BlockHeader>(), any::<BlockSignatures>())
            .prop_map(|(block_header, mut block_signatures)| {
                block_signatures.block_hash = block_header.block_hash();
                block_signatures.era_id = block_header.era_id().clone();
                BlockHeaderWithSignatures {
                    block_header,
                    block_signatures,
                }
            })
            .boxed()
    }
}

#[derive(
    Clone, Default, Ord, PartialOrd, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize,
)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
// See: https://github.com/casper-network/casper-node/blob/edc4b45ea05526ba6dd7971da09e27754a37a230/node/src/types/deploy/deploy_hash.rs#L32
pub struct DeployHash(Digest);

// See: https://github.com/casper-network/casper-node/blob/edc4b45ea05526ba6dd7971da09e27754a37a230/node/src/types/deploy/deploy_hash.rs#L89-L101
impl ToBytes for DeployHash {
    fn write_bytes(&self, writer: &mut Vec<u8>) -> Result<(), casper_types::bytesrepr::Error> {
        self.0.write_bytes(writer)
    }

    fn to_bytes(&self) -> Result<Vec<u8>, casper_types::bytesrepr::Error> {
        self.0.to_bytes()
    }

    fn serialized_length(&self) -> usize {
        self.0.serialized_length()
    }
}

// See: https://github.com/casper-network/casper-node/blob/edc4b45ea05526ba6dd7971da09e27754a37a230/node/src/types/deploy/deploy_hash.rs#L103-L107
impl FromBytes for DeployHash {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), casper_types::bytesrepr::Error> {
        Digest::from_bytes(bytes).map(|(inner, remainder)| (DeployHash(inner), remainder))
    }
}

#[derive(Clone, PartialEq, Eq, Debug, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
// See: https://github.com/casper-network/casper-node/blob/edc4b45ea05526ba6dd7971da09e27754a37a230/node/src/types/block.rs#L1204C14-L1204C15
pub struct BlockBody {
    proposer: PublicKey,
    deploy_hashes: Vec<DeployHash>,
    transfer_hashes: Vec<DeployHash>,
}

impl BlockBody {
    pub fn new(
        proposer: PublicKey,
        deploy_hashes: Vec<DeployHash>,
        transfer_hashes: Vec<DeployHash>,
    ) -> Self {
        BlockBody {
            proposer,
            deploy_hashes,
            transfer_hashes,
        }
    }

    pub fn proposer(&self) -> &PublicKey {
        &self.proposer
    }

    pub fn deploy_hashes(&self) -> &[DeployHash] {
        &self.deploy_hashes
    }

    pub fn transfer_hashes(&self) -> &[DeployHash] {
        &self.transfer_hashes
    }

    pub fn hash(&self) -> Digest {
        Digest::hash(&self.to_bytes().unwrap())
    }
}

#[cfg(test)]
impl Arbitrary for BlockBody {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            public_key_arb(),
            prop::collection::vec(any::<DeployHash>(), 0..5),
            prop::collection::vec(any::<DeployHash>(), 0..5),
        )
            .prop_map(|(proposer, deploy_hashes, transfer_hashes)| BlockBody {
                proposer,
                deploy_hashes,
                transfer_hashes,
            })
            .boxed()
    }
}

// See: https://github.com/casper-network/casper-node/blob/edc4b45ea05526ba6dd7971da09e27754a37a230/node/src/types/block.rs#L1292-L1306
impl ToBytes for BlockBody {
    fn to_bytes(&self) -> Result<Vec<u8>, casper_types::bytesrepr::Error> {
        let mut buffer = casper_types::bytesrepr::allocate_buffer(self)?;
        buffer.extend(self.proposer.to_bytes()?);
        buffer.extend(self.deploy_hashes.to_bytes()?);
        buffer.extend(self.transfer_hashes.to_bytes()?);
        Ok(buffer)
    }

    fn serialized_length(&self) -> usize {
        self.proposer.serialized_length()
            + self.deploy_hashes.serialized_length()
            + self.transfer_hashes.serialized_length()
    }
}

// See: https://github.com/casper-network/casper-node/blob/edc4b45ea05526ba6dd7971da09e27754a37a230/node/src/types/block.rs#L1308-L1321
impl FromBytes for BlockBody {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), casper_types::bytesrepr::Error> {
        let (proposer, bytes) = PublicKey::from_bytes(bytes)?;
        let (deploy_hashes, bytes) = Vec::<DeployHash>::from_bytes(bytes)?;
        let (transfer_hashes, bytes) = Vec::<DeployHash>::from_bytes(bytes)?;
        let body = BlockBody {
            proposer,
            deploy_hashes,
            transfer_hashes,
        };
        Ok((body, bytes))
    }
}

// Data structure reflecting the JSON representation of a block's body.
// See: https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/node/src/types/block.rs#L2268-L2277
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Block {
    block_header_with_signatures: BlockHeaderWithSignatures,
    body: BlockBody,
}

#[derive(Debug)]
pub enum BlockConstructionError {
    InvalidBlockBodyHash {
        header_block_hash: Digest,
        body_hash: Digest,
    },
}

impl Block {
    pub fn new(
        block_header_with_signatures: BlockHeaderWithSignatures,
        body: BlockBody,
    ) -> Result<Self, BlockConstructionError> {
        let header_block_hash = block_header_with_signatures.block_header().body_hash();
        let body_hash = body.hash();
        if header_block_hash != &body_hash {
            return Err(BlockConstructionError::InvalidBlockBodyHash {
                header_block_hash: header_block_hash.clone(),
                body_hash,
            });
        }
        Ok(Block {
            block_header_with_signatures,
            body,
        })
    }

    pub fn block_header_with_signatures(&self) -> &BlockHeaderWithSignatures {
        &self.block_header_with_signatures
    }

    pub fn body(&self) -> &BlockBody {
        &self.body
    }
}

#[cfg(test)]
impl Arbitrary for Block {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<BlockHeaderWithSignatures>(), any::<BlockBody>())
            .prop_map(|(header, body)| Block {
                block_header_with_signatures: header,
                body,
            })
            .boxed()
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use alloc::collections::BTreeMap;

    use casper_types::{bytesrepr::ToBytes, EraId, PublicKey};
    use test_strategy::proptest;

    use crate::{block_header::BlockHash, crypto::sign, hash::DIGEST_LENGTH};

    use super::{BlockBody, BlockSignatures, DeployHash};

    #[proptest]
    fn serde_json_block_signatures_round_trip(block_signatures: BlockSignatures) {
        let serialized_block_signatures = serde_json::to_string(&block_signatures).unwrap();
        let casper_types_block_signatures: casper_node::types::BlockSignatures =
            serde_json::from_str(&serialized_block_signatures).unwrap();
        let serialized_casper_types_block_signatures =
            serde_json::to_string(&casper_types_block_signatures).unwrap();
        assert_eq!(
            serialized_block_signatures,
            serialized_casper_types_block_signatures
        );
        let deserialized_block_signatures: BlockSignatures =
            serde_json::from_str(&serialized_casper_types_block_signatures).unwrap();
        assert_eq!(block_signatures, deserialized_block_signatures);
    }

    #[proptest]
    fn bincode_block_signatures_round_trip(block_signatures: BlockSignatures) {
        let serialized_block_signatures = bincode::serialize(&block_signatures).unwrap();
        let casper_types_block_signatures: casper_node::types::BlockSignatures =
            bincode::deserialize(&serialized_block_signatures).unwrap();
        let serialized_casper_types_block_signatures =
            bincode::serialize(&casper_types_block_signatures).unwrap();
        assert_eq!(
            serialized_block_signatures,
            serialized_casper_types_block_signatures
        );
        let deserialized_block_signatures: BlockSignatures =
            bincode::deserialize(&serialized_casper_types_block_signatures).unwrap();
        assert_eq!(block_signatures, deserialized_block_signatures);
    }

    #[test]
    fn should_verify() {
        let secret_key = casper_types::SecretKey::ed25519_from_bytes([42; 32]).unwrap();
        let block_hash = BlockHash::from([42; DIGEST_LENGTH]);
        let era_id = EraId::from(0);
        let mut signature_data = block_hash.as_ref().to_vec();
        signature_data.extend_from_slice(&era_id.to_le_bytes());
        let signature = sign(&secret_key, signature_data);
        let mut proofs = BTreeMap::new();
        proofs.insert(PublicKey::from(&secret_key), signature);
        let block_signatures = BlockSignatures::new(block_hash, era_id, proofs);
        assert!(block_signatures.is_ok());
    }

    #[test]
    fn should_not_verify() {
        let secret_key0 = casper_types::SecretKey::ed25519_from_bytes([42; 32]).unwrap();
        let secret_key1 = casper_types::SecretKey::ed25519_from_bytes([43; 32]).unwrap();
        let block_hash = BlockHash::from([42; DIGEST_LENGTH]);
        let bogus_signature = sign(&secret_key1, &block_hash);
        let mut proofs = BTreeMap::new();
        proofs.insert(PublicKey::from(&secret_key0), bogus_signature);
        let block_signatures = BlockSignatures::new(block_hash, 0.into(), proofs);
        assert!(block_signatures.is_err());
    }

    #[proptest]
    fn serde_json_deploy_hash_round_trip_casper_types(deploy_hash: DeployHash) {
        let serialized_deploy_hash = serde_json::to_string(&deploy_hash).unwrap();
        let casper_types_deploy_hash: casper_types::DeployHash =
            serde_json::from_str(&serialized_deploy_hash).unwrap();
        let serialized_casper_types_deploy_hash =
            serde_json::to_string(&casper_types_deploy_hash).unwrap();
        assert_eq!(serialized_deploy_hash, serialized_casper_types_deploy_hash);
        let deserialized_deploy_hash: DeployHash =
            serde_json::from_str(&serialized_casper_types_deploy_hash).unwrap();
        assert_eq!(deploy_hash, deserialized_deploy_hash);
    }

    #[proptest]
    fn serde_json_deploy_hash_round_trip_casper_node(deploy_hash: DeployHash) {
        let serialized_deploy_hash = serde_json::to_string(&deploy_hash).unwrap();
        let casper_node_deploy_hash: casper_node::types::DeployHash =
            serde_json::from_str(&serialized_deploy_hash).unwrap();
        let serialized_casper_node_deploy_hash =
            serde_json::to_string(&casper_node_deploy_hash).unwrap();
        assert_eq!(serialized_deploy_hash, serialized_casper_node_deploy_hash);
        let deserialized_deploy_hash: DeployHash =
            serde_json::from_str(&serialized_casper_node_deploy_hash).unwrap();
        assert_eq!(deploy_hash, deserialized_deploy_hash);
    }

    // Note: casper_node and casper_types do not have a consistent bincode serialization, so we chose to follow casper_node's serialization.
    // See https://github.com/casper-network/casper-node/issues/4502

    #[proptest]
    fn bincode_deploy_hash_round_trip_casper_node(deploy_hash: DeployHash) {
        let serialized_deploy_hash = bincode::serialize(&deploy_hash).unwrap();
        let casper_node_deploy_hash: casper_node::types::DeployHash =
            bincode::deserialize(&serialized_deploy_hash).unwrap();
        let serialized_casper_node_deploy_hash =
            bincode::serialize(&casper_node_deploy_hash).unwrap();
        assert_eq!(serialized_deploy_hash, serialized_casper_node_deploy_hash);
        let deserialized_deploy_hash: DeployHash =
            bincode::deserialize(&serialized_casper_node_deploy_hash).unwrap();
        assert_eq!(deploy_hash, deserialized_deploy_hash);
    }

    #[proptest]
    fn bytesrepr_deploy_hash_round_trip_casper_types(deploy_hash: DeployHash) {
        let serialized_deploy_hash = deploy_hash.to_bytes().unwrap();
        let casper_types_deploy_hash: casper_types::DeployHash =
            casper_types::bytesrepr::deserialize(serialized_deploy_hash.clone()).unwrap();
        let serialized_casper_types_deploy_hash =
            casper_types::bytesrepr::serialize(&casper_types_deploy_hash).unwrap();
        assert_eq!(serialized_deploy_hash, serialized_casper_types_deploy_hash);
        let deserialized_deploy_hash: DeployHash =
            casper_types::bytesrepr::deserialize(serialized_casper_types_deploy_hash.clone())
                .unwrap();
        assert_eq!(deploy_hash, deserialized_deploy_hash);
    }

    #[proptest]
    fn bytesrepr_deploy_hash_round_trip_casper_node(deploy_hash: DeployHash) {
        let serialized_deploy_hash = deploy_hash.to_bytes().unwrap();
        let casper_node_deploy_hash: casper_node::types::DeployHash =
            casper_types::bytesrepr::deserialize(serialized_deploy_hash.clone()).unwrap();
        let serialized_casper_node_deploy_hash =
            casper_types::bytesrepr::serialize(&casper_node_deploy_hash).unwrap();
        assert_eq!(serialized_deploy_hash, serialized_casper_node_deploy_hash);
        let deserialized_deploy_hash: DeployHash =
            casper_types::bytesrepr::deserialize(serialized_casper_node_deploy_hash.clone())
                .unwrap();
        assert_eq!(deploy_hash, deserialized_deploy_hash);
    }

    #[proptest]
    fn serde_json_block_body_round_trip(block_body: BlockBody) {
        let serialized_block_body = serde_json::to_string(&block_body).unwrap();
        let casper_node_block_body: casper_node::types::BlockBody =
            serde_json::from_str(&serialized_block_body).unwrap();
        let serialized_node_block_body = serde_json::to_string(&casper_node_block_body).unwrap();
        assert_eq!(serialized_block_body, serialized_node_block_body);
        let deserialized_block_body: BlockBody =
            serde_json::from_str(&serialized_node_block_body).unwrap();
        assert_eq!(block_body, deserialized_block_body);
    }

    #[proptest]
    fn bincode_block_body_round_trip(block_body: BlockBody) {
        let serialized_block_body = bincode::serialize(&block_body).unwrap();
        let casper_node_block_body: casper_node::types::BlockBody =
            bincode::deserialize(&serialized_block_body).unwrap();
        let serialized_casper_node_block_body =
            bincode::serialize(&casper_node_block_body).unwrap();
        assert_eq!(serialized_block_body, serialized_casper_node_block_body);
        let deserialized_block_body: BlockBody =
            bincode::deserialize(&serialized_casper_node_block_body).unwrap();
        assert_eq!(block_body, deserialized_block_body);
    }

    #[proptest]
    fn bytesrepr_block_body_round_trip(block_body: BlockBody) {
        let serialized_block_body = block_body.to_bytes().unwrap();
        let casper_node_block_body: casper_node::types::BlockBody =
            casper_types::bytesrepr::deserialize(serialized_block_body.clone()).unwrap();
        let serialized_casper_node_block_body =
            casper_types::bytesrepr::serialize(&casper_node_block_body).unwrap();
        assert_eq!(serialized_block_body, serialized_casper_node_block_body);
        let deserialized_block_body: BlockBody =
            casper_types::bytesrepr::deserialize(serialized_casper_node_block_body.clone())
                .unwrap();
        assert_eq!(block_body, deserialized_block_body);
    }

    #[proptest]
    fn block_body_hash_agree(block_body: BlockBody) {
        let block_body_hash = block_body.hash();
        let serialized_block_body = block_body.to_bytes().unwrap();
        let casper_node_block_body: casper_node::types::BlockBody =
            casper_types::bytesrepr::deserialize(serialized_block_body).unwrap();
        let casper_node_block_body_hash = casper_node_block_body.hash();
        assert_eq!(
            block_body_hash.as_ref(),
            casper_node_block_body_hash.as_ref()
        );
    }
}
